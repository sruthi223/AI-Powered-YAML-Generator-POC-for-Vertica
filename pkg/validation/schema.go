package validation

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"vertica-mcp-server/pkg/config"
	"vertica-mcp-server/schemas"
	"gopkg.in/yaml.v3"
)

// SchemaRegistry manages version schemas
type SchemaRegistry struct {
	Versions map[string]*VersionSchema
	Current  string
	mu       sync.RWMutex
	client   *http.Client
}

// VersionSchema represents a version-specific schema
type VersionSchema struct {
	Version         string
	SupportedFields map[string]FieldSpec
	Defaults        map[string]interface{}
	CRDSchema       *CRDValidationSchema
}

// FieldSpec defines a field specification
type FieldSpec struct {
	Path        string
	Type        string
	Description string
	Required    bool
	Default     interface{}
	Deprecated  bool
	MinVersion  string
}

// CRDValidationSchema represents the OpenAPI v3 schema from CRD
type CRDValidationSchema struct {
	OpenAPIV3Schema *OpenAPIV3Schema `json:"openAPIV3Schema" yaml:"openAPIV3Schema"`
}

// OpenAPIV3Schema represents an OpenAPI v3 schema
type OpenAPIV3Schema struct {
	Type       string                        `json:"type" yaml:"type"`
	Properties map[string]*OpenAPIV3Property `json:"properties" yaml:"properties"`
	Required   []string                      `json:"required" yaml:"required"`
}

// OpenAPIV3Property represents a property in OpenAPI v3 schema
type OpenAPIV3Property struct {
	Type        string                        `json:"type" yaml:"type"`
	Description string                        `json:"description" yaml:"description"`
	Properties  map[string]*OpenAPIV3Property `json:"properties" yaml:"properties"`
	Items       *OpenAPIV3Property            `json:"items" yaml:"items"`
	Required    []string                      `json:"required" yaml:"required"`
	Enum        []interface{}                 `json:"enum" yaml:"enum"`
	Format      string                        `json:"format" yaml:"format"`
	Pattern     string                        `json:"pattern" yaml:"pattern"`
	Minimum     *float64                      `json:"minimum" yaml:"minimum"`
	Maximum     *float64                      `json:"maximum" yaml:"maximum"`
}

// CustomResourceDefinition represents a Kubernetes CRD
type CustomResourceDefinition struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Versions []struct {
			Name   string `yaml:"name"`
			Schema struct {
				OpenAPIV3Schema OpenAPIV3Schema `yaml:"openAPIV3Schema"`
			} `yaml:"schema"`
		} `yaml:"versions"`
	} `yaml:"spec"`
}

// NewSchemaRegistry creates a new schema registry
func NewSchemaRegistry(client *http.Client) *SchemaRegistry {
	registry := &SchemaRegistry{
		Versions: make(map[string]*VersionSchema),
		Current:  config.DefaultVersion,
		client:   client,
	}
	registry.initializeSchemas()
	return registry
}

// GetSchema retrieves a schema for a version (thread-safe)
func (r *SchemaRegistry) GetSchema(version string) (*VersionSchema, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	schema, exists := r.Versions[version]
	if !exists {
		return nil, fmt.Errorf("version %s not found in registry", version)
	}
	return schema, nil
}

// LoadCRDSchema loads the CRD schema for a specific version
func (r *SchemaRegistry) LoadCRDSchema(ctx context.Context, version string) error {
	normalizedVersion := normalizeVersion(version)

	r.mu.RLock()
	schema, exists := r.Versions[normalizedVersion]
	r.mu.RUnlock()

	if !exists {
		return fmt.Errorf("version %s not found in registry", version)
	}

	// Check if already loaded
	if schema.CRDSchema != nil {
		log.Printf("CRD schema already loaded for version %s", version)
		return nil
	}

	// Download and parse CRD
	crdSchema, err := r.downloadCRDSchema(ctx, version)
	if err != nil {
		log.Printf("Warning: Failed to load CRD schema for version %s: %v", version, err)
		return err
	}

	r.mu.Lock()
	schema.CRDSchema = crdSchema
	r.mu.Unlock()

	log.Printf("✓ CRD schema loaded and cached for version %s", version)
	return nil
}

// downloadCRDSchema downloads and parses the CRD schema from GitHub or local file
func (r *SchemaRegistry) downloadCRDSchema(ctx context.Context, version string) (*CRDValidationSchema, error) {
	// Check if we should use local files
	cfg := config.Load()
	if cfg.CRDBaseURL == "local" || cfg.CRDBaseURL == "" {
		return r.loadLocalCRDSchema(version, cfg.CRDLocalPath)
	}

	// Download from GitHub (or custom URL)
	url := getCRDURL(version)
	log.Printf("Downloading CRD schema from: %s", url)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		// Fallback to local if download fails
		log.Printf("⚠️  Failed to create download request: %v, trying local fallback", err)
		return r.loadLocalCRDSchema(version, cfg.CRDLocalPath)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		// Fallback to local if download fails
		log.Printf("⚠️  Failed to download CRD: %v, trying local fallback", err)
		return r.loadLocalCRDSchema(version, cfg.CRDLocalPath)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Fallback to local if download fails
		log.Printf("⚠️  Failed to download CRD: HTTP %d, trying local fallback", resp.StatusCode)
		return r.loadLocalCRDSchema(version, cfg.CRDLocalPath)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRD response: %w", err)
	}

	// Parse and return CRD
	return r.parseCRDYAML(body)
}

// loadLocalCRDSchema loads CRD schema from embedded files or fallback to filesystem
func (r *SchemaRegistry) loadLocalCRDSchema(version, localPath string) (*CRDValidationSchema, error) {
	// Construct filename: verticadbs.vertica.com-crd-v{version}.yaml
	filename := fmt.Sprintf("verticadbs.vertica.com-crd-v%s.yaml", version)

	// First, try to load from embedded files
	data, err := schemas.Schemas.ReadFile(filename)
	if err == nil {
		log.Printf("✓ Loaded CRD schema from embedded files")
		return r.parseCRDYAML(data)
	}

	// Fallback to filesystem if embedded files not available (for development)
	log.Printf("Embedded schema not found, trying filesystem: %s", localPath)
	filePath := localPath + "/" + filename
	data, err = os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRD schema %s (embedded or local): %w (hint: ensure schemas/*.yaml are present)", filename, err)
	}

	log.Printf("✓ Loaded CRD schema from local file")
	return r.parseCRDYAML(data)
}

// parseCRDYAML parses CRD YAML data and extracts the validation schema
func (r *SchemaRegistry) parseCRDYAML(data []byte) (*CRDValidationSchema, error) {
	// Parse CRD YAML
	var crd CustomResourceDefinition
	if err := yaml.Unmarshal(data, &crd); err != nil {
		return nil, fmt.Errorf("failed to parse CRD YAML: %w", err)
	}

	// Extract the schema from the first version
	if len(crd.Spec.Versions) == 0 {
		return nil, fmt.Errorf("no versions found in CRD")
	}

	schema := &CRDValidationSchema{
		OpenAPIV3Schema: &crd.Spec.Versions[0].Schema.OpenAPIV3Schema,
	}

	log.Printf("✓ Successfully parsed CRD schema")
	return schema, nil
}

// getCRDURL returns the CRD download URL for a specific version
func getCRDURL(version string) string {
	versionMap := map[string]string{
		"25.1": "v25.1.0-0/verticadbs.vertica.com-crd.yaml",
		"25.2": "v25.2.0-0/verticadbs.vertica.com-crd.yaml",
		"25.3": "v25.3.0-0/verticadbs.vertica.com-crd.yaml",
		"25.4": "v25.4.0-0/verticadbs.vertica.com-crd.yaml",
	}

	if releasePath, ok := versionMap[version]; ok {
		return fmt.Sprintf("%s/%s", config.CRDBaseURL, releasePath)
	}

	// Default to latest
	return fmt.Sprintf("%s/v25.4.0-0/verticadbs.vertica.com-crd.yaml", config.CRDBaseURL)
}

// initializeSchemas initializes version-specific schemas
func (r *SchemaRegistry) initializeSchemas() {
	baseFields := r.getBaseFields()

	// Initialize 25.1 schema
	r.Versions["25.1"] = &VersionSchema{
		Version:         "25.1.x",
		SupportedFields: copyFieldSpec(baseFields),
		Defaults: map[string]interface{}{
			"image":              "opentext/vertica-k8s:25.1.0",
			"dbName":             "vertdb",
			"autoRestartVertica": true,
			"upgradePolicy":      "Auto",
			"initPolicy":         "Create",
		},
	}

	// Initialize 25.2 schema
	r.Versions["25.2"] = &VersionSchema{
		Version:         "25.2.x",
		SupportedFields: copyFieldSpec(baseFields),
		Defaults: map[string]interface{}{
			"image":              "opentext/vertica-k8s:25.2.0",
			"dbName":             "vertdb",
			"autoRestartVertica": true,
			"upgradePolicy":      "Auto",
			"initPolicy":         "Create",
		},
	}
	r.Versions["25.2"].SupportedFields["nmaSecurityContext"] = FieldSpec{Type: "object", MinVersion: "25.2"}
	r.Versions["25.2"].SupportedFields["temporarySubclusterRouting"] = FieldSpec{Type: "object", MinVersion: "25.2"}

	// Initialize 25.3 schema
	r.Versions["25.3"] = &VersionSchema{
		Version:         "25.3.x",
		SupportedFields: copyFieldSpec(baseFields),
		Defaults: map[string]interface{}{
			"image":              "opentext/vertica-k8s:25.3.0",
			"dbName":             "vertdb",
			"autoRestartVertica": true,
			"upgradePolicy":      "Auto",
			"initPolicy":         "Create",
		},
	}
	r.Versions["25.3"].SupportedFields["nmaSecurityContext"] = FieldSpec{Type: "object", MinVersion: "25.2"}
	r.Versions["25.3"].SupportedFields["temporarySubclusterRouting"] = FieldSpec{Type: "object", MinVersion: "25.2"}
	r.Versions["25.3"].SupportedFields["httpsNMATLS"] = FieldSpec{Type: "object", MinVersion: "25.3"}
	r.Versions["25.3"].SupportedFields["clientServerTLS"] = FieldSpec{Type: "object", MinVersion: "25.3"}
	r.Versions["25.3"].SupportedFields["serviceClientPort"] = FieldSpec{Type: "int", MinVersion: "25.3"}
	r.Versions["25.3"].SupportedFields["serviceHTTPSPort"] = FieldSpec{Type: "int", MinVersion: "25.3"}
	r.Versions["25.3"].SupportedFields["restorePoint.numRestorePoints"] = FieldSpec{Type: "int", MinVersion: "25.3"}

	// Initialize 25.4 schema
	r.Versions["25.4"] = &VersionSchema{
		Version:         "25.4.x",
		SupportedFields: copyFieldSpec(baseFields),
		Defaults: map[string]interface{}{
			"image":              "opentext/vertica-k8s:25.4.0",
			"dbName":             "vertdb",
			"autoRestartVertica": true,
			"upgradePolicy":      "Auto",
			"initPolicy":         "Create",
		},
	}
	r.Versions["25.4"].SupportedFields["nmaSecurityContext"] = FieldSpec{Type: "object", MinVersion: "25.2"}
	r.Versions["25.4"].SupportedFields["temporarySubclusterRouting"] = FieldSpec{Type: "object", MinVersion: "25.2"}
	r.Versions["25.4"].SupportedFields["httpsNMATLS"] = FieldSpec{Type: "object", MinVersion: "25.3"}
	r.Versions["25.4"].SupportedFields["clientServerTLS"] = FieldSpec{Type: "object", MinVersion: "25.3"}
	r.Versions["25.4"].SupportedFields["serviceClientPort"] = FieldSpec{Type: "int", MinVersion: "25.3"}
	r.Versions["25.4"].SupportedFields["serviceHTTPSPort"] = FieldSpec{Type: "int", MinVersion: "25.3"}
	r.Versions["25.4"].SupportedFields["restorePoint.numRestorePoints"] = FieldSpec{Type: "int", MinVersion: "25.3"}
	r.Versions["25.4"].SupportedFields["clientServerTLS.autoRotate"] = FieldSpec{Type: "object", MinVersion: "25.4"}
	r.Versions["25.4"].SupportedFields["httpsNMATLS.autoRotate"] = FieldSpec{Type: "object", MinVersion: "25.4"}
	r.Versions["25.4"].SupportedFields["extraEnv"] = FieldSpec{Type: "array", MinVersion: "25.4"}
	r.Versions["25.4"].SupportedFields["envFrom"] = FieldSpec{Type: "array", MinVersion: "25.4"}

	log.Printf("Initialized schema registry with version-specific fields:")
	log.Printf("  25.1: %d base fields", len(r.Versions["25.1"].SupportedFields))
	log.Printf("  25.2: %d fields (+nmaSecurityContext, +temporarySubclusterRouting)", len(r.Versions["25.2"].SupportedFields))
	log.Printf("  25.3: %d fields (+httpsNMATLS, +clientServerTLS, +service ports, +numRestorePoints)", len(r.Versions["25.3"].SupportedFields))
	log.Printf("  25.4: %d fields (+TLS autoRotate, +extraEnv, +envFrom)", len(r.Versions["25.4"].SupportedFields))
}

// getBaseFields returns the base field specifications
func (r *SchemaRegistry) getBaseFields() map[string]FieldSpec {
	return map[string]FieldSpec{
		"image":                   {Type: "string"},
		"dbName":                  {Type: "string"},
		"initPolicy":              {Type: "string"},
		"upgradePolicy":           {Type: "string"},
		"encryptSpreadComm":       {Type: "string"},
		"autoRestartVertica":      {Type: "bool"},
		"imagePullPolicy":         {Type: "string"},
		"serviceType":             {Type: "string"},
		"shardCount":              {Type: "int"},
		"kSafety":                 {Type: "int"},
		"communal":                {Type: "object"},
		"local":                   {Type: "object"},
		"subclusters":             {Type: "array"},
		"sandboxes":               {Type: "array"},
		"volumes":                 {Type: "array"},
		"volumeMounts":            {Type: "array"},
		"livenessProbeOverride":   {Type: "object"},
		"readinessProbeOverride":  {Type: "object"},
		"startupProbeOverride":    {Type: "object"},
		"sidecars":                {Type: "array"},
		"passwordSecret":          {Type: "string"},
		"superuserPasswordSecret": {Type: "string"},
		"licenseSecret":           {Type: "string"},
		"kerberosSecret":          {Type: "string"},
		"hadoopConfig":            {Type: "string"},
		"nmaTLSSecret":            {Type: "string"},
		"certSecrets":             {Type: "array"},
		"podSecurityContext":      {Type: "object"},
		"securityContext":         {Type: "object"},
		"serviceAccountName":      {Type: "string"},
		"imagePullSecrets":        {Type: "array"},
		"labels":                  {Type: "map"},
		"annotations":             {Type: "map"},
		"proxy":                   {Type: "object"},
		"restorePoint":            {Type: "object"},
		"reviveOrder":             {Type: "array"},
	}
}

// copyFieldSpec creates a deep copy of a FieldSpec map
func copyFieldSpec(source map[string]FieldSpec) map[string]FieldSpec {
	dest := make(map[string]FieldSpec)
	for k, v := range source {
		dest[k] = v
	}
	return dest
}
