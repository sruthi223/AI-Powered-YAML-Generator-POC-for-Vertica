package validation

import (
	"context"
	"fmt"
	"strings"

	"vertica-mcp-server/pkg/models"
	"gopkg.in/yaml.v3"
)

// Result holds the validation outcome
type Result struct {
	Valid             bool
	Errors            []string
	Warnings          []string
	Version           string
	MissingFields     []string
	UnsupportedFields []string
}

// Validator validates VerticaDB configurations
type Validator interface {
	ValidateYAML(ctx context.Context, db *models.VerticaDB, version string) (*Result, error)
	ValidateSyntax(ctx context.Context, yamlBytes []byte) error
}

// validator implements the Validator interface
type validator struct {
	registry *SchemaRegistry
}

// NewValidator creates a new validator
func NewValidator(registry *SchemaRegistry) Validator {
	return &validator{
		registry: registry,
	}
}

// ValidateYAML validates a VerticaDB YAML against a specific version's schema
func (v *validator) ValidateYAML(ctx context.Context, db *models.VerticaDB, version string) (*Result, error) {
	result := &Result{
		Valid:             true,
		Version:           version,
		Errors:            []string{},
		Warnings:          []string{},
		MissingFields:     []string{},
		UnsupportedFields: []string{},
	}

	// Normalize version
	normalizedVersion := normalizeVersion(version)
	schema, err := v.registry.GetSchema(normalizedVersion)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}

	// Validate against CRD schema if available
	if schema.CRDSchema != nil {
		crdErrors := validateAgainstCRDSchema(db, schema.CRDSchema)
		if len(crdErrors) > 0 {
			result.Valid = false
			result.Errors = append(result.Errors, crdErrors...)
		}
	} else {
		result.Warnings = append(result.Warnings, "CRD schema not loaded - using basic validation only")
	}

	// Validate required fields
	for fieldName, fieldSpec := range schema.SupportedFields {
		if fieldSpec.Required {
			if !fieldExistsInDB(db, fieldSpec.Path) {
				result.Valid = false
				result.MissingFields = append(result.MissingFields, fieldSpec.Path)
				result.Errors = append(result.Errors, fmt.Sprintf("Required field missing: %s", fieldSpec.Path))
			}
		}

		// Check for deprecated fields
		if fieldSpec.Deprecated && fieldExistsInDB(db, fieldSpec.Path) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Deprecated field used: %s - %s", fieldName, fieldSpec.Description))
		}
	}

	// Version-specific field validation
	v.validateVersionSpecificFields(db, version, result)

	return result, nil
}

// validateVersionSpecificFields validates fields against version requirements
func (v *validator) validateVersionSpecificFields(db *models.VerticaDB, version string, result *Result) {
	versionChecks := []struct {
		fieldName   string
		minVersion  string
		checkFunc   func(*models.VerticaDB) bool
		description string
	}{
		// 25.2+ fields
		{"nmaSecurityContext", "25.2", func(db *models.VerticaDB) bool { return db.Spec.NMASecurityContext != nil }, "NMA Security Context"},
		{"temporarySubclusterRouting", "25.2", func(db *models.VerticaDB) bool { return db.Spec.TemporarySubclusterRouting != nil }, "Temporary Subcluster Routing"},

		// 25.3+ fields
		{"httpsNMATLS", "25.3", func(db *models.VerticaDB) bool { return db.Spec.HTTPSNMATLS != nil }, "HTTPS/NMA TLS Configuration"},
		{"clientServerTLS", "25.3", func(db *models.VerticaDB) bool { return db.Spec.ClientServerTLS != nil }, "Client-Server TLS Configuration"},
		{"serviceClientPort", "25.3", func(db *models.VerticaDB) bool { return db.Spec.ServiceClientPort > 0 }, "Global Service Client Port"},
		{"serviceHTTPSPort", "25.3", func(db *models.VerticaDB) bool { return db.Spec.ServiceHTTPSPort > 0 }, "Global Service HTTPS Port"},
		{"restorePoint.numRestorePoints", "25.3", func(db *models.VerticaDB) bool {
			return db.Spec.RestorePoint != nil && db.Spec.RestorePoint.NumRestorePoints > 0
		}, "Restore Point Limit"},

		// 25.4+ fields
		{"clientServerTLS.autoRotate", "25.4", func(db *models.VerticaDB) bool {
			return db.Spec.ClientServerTLS != nil && db.Spec.ClientServerTLS.AutoRotate != nil
		}, "Client-Server TLS Auto-Rotation"},
		{"httpsNMATLS.autoRotate", "25.4", func(db *models.VerticaDB) bool {
			return db.Spec.HTTPSNMATLS != nil && db.Spec.HTTPSNMATLS.AutoRotate != nil
		}, "HTTPS/NMA TLS Auto-Rotation"},
		{"extraEnv", "25.4", func(db *models.VerticaDB) bool { return len(db.Spec.ExtraEnv) > 0 }, "Custom Environment Variables"},
		{"envFrom", "25.4", func(db *models.VerticaDB) bool { return len(db.Spec.EnvFrom) > 0 }, "Environment Variables from ConfigMap/Secret"},
	}

	for _, check := range versionChecks {
		if check.checkFunc(db) {
			if !isVersionGreaterOrEqual(version, check.minVersion) {
				result.Valid = false
				result.UnsupportedFields = append(result.UnsupportedFields, check.fieldName)
				result.Errors = append(result.Errors,
					fmt.Sprintf("Field '%s' (%s) requires version %s or higher, but target is %s",
						check.fieldName, check.description, check.minVersion, version))
			}
		}
	}
}

// ValidateSyntax performs round-trip validation to ensure YAML is syntactically correct
func (v *validator) ValidateSyntax(ctx context.Context, yamlBytes []byte) error {
	var testDB models.VerticaDB
	if err := yaml.Unmarshal(yamlBytes, &testDB); err != nil {
		return fmt.Errorf("YAML syntax error during unmarshal: %w", err)
	}

	_, err := yaml.Marshal(&testDB)
	if err != nil {
		return fmt.Errorf("YAML syntax error during re-marshal: %w", err)
	}

	return nil
}

// Helper functions

func validateAgainstCRDSchema(db *models.VerticaDB, crdSchema *CRDValidationSchema) []string {
	var errors []string

	if crdSchema == nil || crdSchema.OpenAPIV3Schema == nil {
		return []string{"CRD schema not available"}
	}

	// Convert VerticaDB to a generic map for validation
	dbBytes, err := yaml.Marshal(db)
	if err != nil {
		return []string{fmt.Sprintf("Failed to marshal VerticaDB: %v", err)}
	}

	var dbMap map[string]interface{}
	if err := yaml.Unmarshal(dbBytes, &dbMap); err != nil {
		return []string{fmt.Sprintf("Failed to unmarshal VerticaDB to map: %v", err)}
	}

	// Validate the spec section against the CRD schema
	if spec, ok := dbMap["spec"].(map[string]interface{}); ok {
		specErrors := validateObjectAgainstSchema(spec, crdSchema.OpenAPIV3Schema, "spec")
		errors = append(errors, specErrors...)
	}

	return errors
}

func validateObjectAgainstSchema(obj map[string]interface{}, schema *OpenAPIV3Schema, path string) []string {
	var errors []string

	if schema == nil {
		return errors
	}

	// Check required fields
	for _, reqField := range schema.Required {
		if _, exists := obj[reqField]; !exists {
			errors = append(errors, fmt.Sprintf("Required field missing: %s.%s", path, reqField))
		}
	}

	// Validate each property
	for key, value := range obj {
		propPath := fmt.Sprintf("%s.%s", path, key)
		propSchema, exists := schema.Properties[key]
		if !exists {
			continue
		}

		if err := validatePropertyValue(value, propSchema, propPath); err != "" {
			errors = append(errors, err)
		}
	}

	return errors
}

func validatePropertyValue(value interface{}, propSchema *OpenAPIV3Property, path string) string {
	if propSchema == nil {
		return ""
	}

	// Type validation
	switch propSchema.Type {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Sprintf("Type mismatch at %s: expected string, got %T", path, value)
		}
	case "integer":
		switch value.(type) {
		case int, int32, int64, float64:
			// Valid
		default:
			return fmt.Sprintf("Type mismatch at %s: expected integer, got %T", path, value)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Sprintf("Type mismatch at %s: expected boolean, got %T", path, value)
		}
	case "array":
		if _, ok := value.([]interface{}); !ok {
			return fmt.Sprintf("Type mismatch at %s: expected array, got %T", path, value)
		}
	case "object":
		if objMap, ok := value.(map[string]interface{}); ok {
			if propSchema.Properties != nil {
				nestedSchema := &OpenAPIV3Schema{
					Properties: propSchema.Properties,
					Required:   propSchema.Required,
				}
				errors := validateObjectAgainstSchema(objMap, nestedSchema, path)
				if len(errors) > 0 {
					return strings.Join(errors, "; ")
				}
			}
		} else {
			return fmt.Sprintf("Type mismatch at %s: expected object, got %T", path, value)
		}
	}

	// Enum validation
	if len(propSchema.Enum) > 0 {
		valid := false
		for _, enumVal := range propSchema.Enum {
			if value == enumVal {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Sprintf("Invalid enum value at %s: got %v, allowed values: %v", path, value, propSchema.Enum)
		}
	}

	return ""
}

func isVersionGreaterOrEqual(current, required string) bool {
	return current >= required
}

func fieldExistsInDB(db *models.VerticaDB, path string) bool {
	parts := strings.Split(path, ".")

	if len(parts) == 0 {
		return false
	}

	if parts[0] == "spec" && len(parts) > 1 {
		switch parts[1] {
		case "image":
			return db.Spec.Image != ""
		case "communal":
			return db.Spec.Communal != nil
		case "local":
			return db.Spec.Local != nil
		case "subclusters":
			return len(db.Spec.Subclusters) > 0
		case "shardCount":
			return db.Spec.ShardCount > 0
		case "restorePoint":
			return db.Spec.RestorePoint != nil
		case "sidecars":
			return len(db.Spec.Sidecars) > 0
		}
	}

	return false
}

func normalizeVersion(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return version
}

// FormatResult formats the validation result into a readable string
func FormatResult(result *Result) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n=== Validation Result for Version %s ===\n", result.Version))

	if result.Valid {
		sb.WriteString("✓ YAML is VALID\n")
	} else {
		sb.WriteString("✗ YAML validation FAILED\n")
	}

	if len(result.Errors) > 0 {
		sb.WriteString("\n❌ Errors:\n")
		for _, err := range result.Errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", err))
		}
	}

	if len(result.Warnings) > 0 {
		sb.WriteString("\n⚠️  Warnings:\n")
		for _, warn := range result.Warnings {
			sb.WriteString(fmt.Sprintf("  - %s\n", warn))
		}
	}

	if len(result.MissingFields) > 0 {
		sb.WriteString("\n📋 Missing Required Fields:\n")
		for _, field := range result.MissingFields {
			sb.WriteString(fmt.Sprintf("  - %s\n", field))
		}
	}

	sb.WriteString("=====================================\n")
	return sb.String()
}
