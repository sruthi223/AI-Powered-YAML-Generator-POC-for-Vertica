package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// buildParsePrompt creates the prompt for parsing instructions
func buildParsePrompt(instruction, version string) string {
	// Ultra-minimal directive prompt for fastest inference
	return fmt.Sprintf(`Extract fields. Output JSON only. No explanation.

Instruction: %s

JSON schema:
{"dbName":"str","nodeCount":num,"storageType":"s3|gcs|azure","communalPath":"uri","credentialSecret":"str","region":"str","subclusters":[{"name":"str","type":"primary|secondary","size":num}]}

JSON:`, instruction)
}

// buildSummaryPrompt creates the prompt for database summary
func buildSummaryPrompt(dbInfo map[string]interface{}) string {
	infoJSON, _ := json.MarshalIndent(dbInfo, "", "  ")
	return fmt.Sprintf(`Provide a brief, professional summary of this Vertica database configuration:

%s

Format as 2-3 short paragraphs covering:
1. Database overview (name, version, mode, shards)
2. Cluster architecture (subclusters, nodes, storage)
3. Key configuration details

Be concise and technical.`, string(infoJSON))
}

// buildValidationPrompt creates the prompt for validation error explanation
func buildValidationPrompt(yamlContent string, errors []string, version string) string {
	errorsText := strings.Join(errors, "\n- ")
	return fmt.Sprintf(`Explain these Vertica YAML validation errors in simple terms:

YAML VERSION: %s

ERRORS:
- %s

YAML:
%s

Provide:
1. What each error means
2. How to fix it
3. Example of correct configuration

Be concise and actionable.`, version, errorsText, yamlContent)
}

// parseConfigResponse parses the LLM response into ParsedConfig
func parseConfigResponse(response string) (*ParsedConfig, error) {
	// Clean response - extract JSON from code blocks if present
	response = strings.TrimSpace(response)
	
	// Remove markdown code blocks
	if strings.HasPrefix(response, "```json") {
		response = strings.TrimPrefix(response, "```json")
	}
	if strings.HasPrefix(response, "```") {
		response = strings.TrimPrefix(response, "```")
	}
	if strings.HasSuffix(response, "```") {
		response = strings.TrimSuffix(response, "```")
	}
	response = strings.TrimSpace(response)

	// Extract JSON object
	if idx := strings.Index(response, "{"); idx != -1 {
		response = response[idx:]
	}
	if idx := strings.LastIndex(response, "}"); idx != -1 {
		response = response[:idx+1]
	}

	var config ParsedConfig
	if err := json.Unmarshal([]byte(response), &config); err != nil {
		return nil, fmt.Errorf("failed to parse response as JSON: %w (response: %s)", err, response[:min(len(response), 200)])
	}

	// Apply defaults
	applyConfigDefaults(&config)
	
	return &config, nil
}

// applyConfigDefaults sets default values for unspecified fields
func applyConfigDefaults(config *ParsedConfig) {
	if config.DBName == "" {
		config.DBName = "vertdb"
	}
	if config.NodeCount == 0 && len(config.Subclusters) == 0 {
		config.NodeCount = 3
	}
	if config.StorageType == "" {
		config.StorageType = "s3"
	}
	if config.InitPolicy == "" {
		config.InitPolicy = "Create"
	}
	if config.UpgradePolicy == "" {
		config.UpgradePolicy = "Auto"
	}
	if config.KSafety == 0 {
		config.KSafety = 1
	}
	if config.Namespace == "" {
		config.Namespace = "default"
	}
	if config.ImagePullPolicy == "" {
		config.ImagePullPolicy = "IfNotPresent"
	}
	if config.ServiceType == "" {
		config.ServiceType = "ClusterIP"
	}
	if config.SubclusterName == "" {
		config.SubclusterName = "main"
	}
	if config.SubclusterType == "" {
		config.SubclusterType = "primary"
	}
	if config.Region == "" && config.StorageType == "s3" {
		config.Region = "us-east-1"
	}
	if config.DataPath == "" {
		config.DataPath = "/data"
	}
	if config.DepotPath == "" {
		config.DepotPath = "/depot"
	}
	if config.CatalogPath == "" {
		config.CatalogPath = "/catalog"
	}
	if config.RequestSize == "" {
		config.RequestSize = "500Gi"
	}
	if config.StorageClass == "" {
		config.StorageClass = "standard"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
