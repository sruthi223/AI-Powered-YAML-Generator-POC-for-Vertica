package llm

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ollama/ollama/api"
)

// Simple in-memory cache for LLM results
var (
	resultCache   = make(map[string]string)
	cacheMutex    sync.RWMutex
	cacheHits     int
	cacheMisses   int
)

// OllamaClient handles communication with Ollama API using official SDK
type OllamaClient struct {
	client *api.Client
	model  string
}

// NewOllamaClient creates a new Ollama API client using official SDK
func NewOllamaClient(baseURL, model string, httpClient *http.Client) *OllamaClient {
	// Parse base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		// Fallback to default localhost if parsing fails
		parsedURL, _ = url.Parse("http://localhost:11434")
	}

	// Create official Ollama client
	client := api.NewClient(parsedURL, httpClient)

	return &OllamaClient{
		client: client,
		model:  model,
	}
}

// Warmup preloads the model into memory to eliminate cold start delay
func (c *OllamaClient) Warmup() {
	log.Printf("🔥 Warming up model: %s", c.model)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Simple prompt to load model into memory
	_, err := c.generateWithContext(ctx, "Hi", 128)
	if err != nil {
		log.Printf("⚠️ Warmup failed (non-critical): %v", err)
	} else {
		log.Printf("✅ Model warmed up and ready!")
	}
}

// Generate sends a prompt to Ollama and returns the response using official SDK
func (c *OllamaClient) Generate(ctx context.Context, prompt string) (string, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%x", md5.Sum([]byte(c.model+prompt)))
	
	cacheMutex.RLock()
	if cached, exists := resultCache[cacheKey]; exists {
		cacheHits++
		cacheMutex.RUnlock()
		log.Printf("💾 Cache hit! (hits: %d, misses: %d, ratio: %.1f%%)", 
			cacheHits, cacheMisses, float64(cacheHits)/float64(cacheHits+cacheMisses)*100)
		return cached, nil
	}
	cacheMisses++
	cacheMutex.RUnlock()
	
	start := time.Now()
	
	// Create keep-alive duration (-1 means forever in Ollama's API)
	// The Go API expects an api.Duration wrapping a time.Duration
	// Ollama interprets negative durations as "keep forever"
	keepAlive := api.Duration{Duration: -1}
	
	log.Printf("🔧 Request config: model=%s, keep_alive=%v, num_ctx=4096", c.model, keepAlive.Duration)
	
	req := &api.GenerateRequest{
		Model:     c.model,
		Prompt:    prompt,
		Stream:    ptrBool(true), // CRITICAL: Enable streaming to keep MCP alive
		KeepAlive: &keepAlive,    // CRITICAL: Keep model in memory indefinitely
		Options: map[string]interface{}{
			"temperature":     0.0,   // Zero for fastest decoding
			"top_p":           0.9,   // Standard sampling
			"repeat_penalty":  1.0,   // No penalty = faster
			"num_ctx":         4096,  // Increased from 2048 - prompt was being truncated at 2144 tokens
			"num_predict":     512,   // Sufficient for JSON
			"num_thread":      16,    // Pin to 16 threads
		},
	}

	var fullResponse strings.Builder
	tokenCount := 0
	lastLog := time.Now()
	firstToken := time.Time{}

	// Generate response using official SDK with streaming
	err := c.client.Generate(ctx, req, func(resp api.GenerateResponse) error {
		if firstToken.IsZero() {
			firstToken = time.Now()
			log.Printf("⚡ First token in %v", firstToken.Sub(start))
		}
		
		fullResponse.WriteString(resp.Response)
		tokenCount++
		
		// Log progress every 5 seconds to show activity (keeps connection alive)
		if time.Since(lastLog) > 5*time.Second {
			log.Printf("🔄 LLM generating... (%d tokens, %.1fs elapsed)", tokenCount, time.Since(start).Seconds())
			lastLog = time.Now()
		}
		
		return nil
	})

	if err != nil {
		return "", fmt.Errorf("ollama generation failed: %w", err)
	}

	elapsed := time.Since(start)
	tps := float64(tokenCount) / elapsed.Seconds()
	log.Printf("✓ LLM complete: %d tokens in %v (%.1f tok/s)", tokenCount, elapsed, tps)
	
	// Cache the result
	result := fullResponse.String()
	cacheMutex.Lock()
	resultCache[cacheKey] = result
	// Limit cache size to prevent memory bloat
	if len(resultCache) > 100 {
		// Simple eviction: clear half the cache
		for k := range resultCache {
			delete(resultCache, k)
			if len(resultCache) <= 50 {
				break
			}
		}
		log.Printf("🧹 Cache evicted (now: %d entries)", len(resultCache))
	}
	cacheMutex.Unlock()
	
	return result, nil
}

// generateWithContext is like Generate but with custom num_ctx for optimization
func (c *OllamaClient) generateWithContext(ctx context.Context, prompt string, numCtx int) (string, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%x", md5.Sum([]byte(c.model+prompt)))
	
	cacheMutex.RLock()
	if cached, exists := resultCache[cacheKey]; exists {
		cacheHits++
		cacheMutex.RUnlock()
		log.Printf("💾 Cache hit!")
		return cached, nil
	}
	cacheMisses++
	cacheMutex.RUnlock()
	
	start := time.Now()
	keepAlive := api.Duration{Duration: -1}
	
	req := &api.GenerateRequest{
		Model:     c.model,
		Prompt:    prompt,
		Stream:    ptrBool(false), // No streaming for micro-prompts
		KeepAlive: &keepAlive,
		Options: map[string]interface{}{
			"temperature":     0.0,
			"num_ctx":         numCtx, // Custom context size
			"num_predict":     256,    // Small output
			"num_thread":      16,
		},
	}

	var result string
	err := c.client.Generate(ctx, req, func(resp api.GenerateResponse) error {
		result += resp.Response
		return nil
	})

	if err != nil {
		return "", fmt.Errorf("ollama generation failed: %w", err)
	}

	log.Printf("✓ LLM complete in %v (ctx=%d)", time.Since(start), numCtx)
	
	// Cache the result
	cacheMutex.Lock()
	resultCache[cacheKey] = result
	if len(resultCache) > 100 {
		for k := range resultCache {
			delete(resultCache, k)
			if len(resultCache) <= 50 {
				break
			}
		}
	}
	cacheMutex.Unlock()
	
	return result, nil
}

// ptrBool returns a pointer to a bool value
func ptrBool(b bool) *bool {
	return &b
}

// SubclusterConfig represents a single subcluster configuration
type SubclusterConfig struct {
	Name              string            `json:"name"`              // Subcluster name
	Type              string            `json:"type"`              // primary, secondary
	Size              int               `json:"size"`              // Number of nodes
	ServiceType       string            `json:"serviceType"`       // ClusterIP, NodePort, LoadBalancer
	ServiceName       string            `json:"serviceName"`       // Custom service name
	CPURequest        string            `json:"cpuRequest"`        // e.g., "2", "2000m"
	MemoryRequest     string            `json:"memoryRequest"`     // e.g., "8Gi"
	CPULimit          string            `json:"cpuLimit"`          // e.g., "4"
	MemoryLimit       string            `json:"memoryLimit"`       // e.g., "16Gi"
	PriorityClassName string            `json:"priorityClassName"` // Pod priority class
	NodeSelector      map[string]string `json:"nodeSelector"`      // Node selector labels
	ImageOverride     string            `json:"imageOverride"`     // Custom image for this subcluster
	Shutdown          bool              `json:"shutdown"`          // Shutdown this subcluster
	ServiceClientPort int               `json:"serviceClientPort"` // Default: 5433 (25.3+)
	ServiceHTTPSPort  int               `json:"serviceHTTPSPort"`  // Default: 8443 (25.3+)
	ExternalIPs       []string          `json:"externalIPs"`       // External IPs for LoadBalancer service
	Affinity          string            `json:"affinity"`          // Affinity rules (simplified as string for LLM)
	Tolerations       []string          `json:"tolerations"`       // Tolerations (simplified as string array)
}

// Canonical defaults for VerticaDB (Phase 2 truth source)
var DefaultVerticaSpec = ParsedConfig{
	InitPolicy:        "Create",
	UpgradePolicy:     "Auto",
	ImagePullPolicy:   "IfNotPresent",
	KSafety:           1,
	ShardCount:        0, // auto-calculate
	ServiceClientPort: 5433,
	ServiceHTTPSPort:  8443,
	Region:            "us-east-1",
	Endpoint:          "https://s3.amazonaws.com",
}

// Default subcluster resource settings
var DefaultSubclusterResources = SubclusterConfig{
	ServiceType:   "ClusterIP",
	CPURequest:    "2",
	MemoryRequest: "8Gi",
	CPULimit:      "4",
	MemoryLimit:   "16Gi",
}

// ParsedConfig represents the parsed configuration from natural language
type ParsedConfig struct {
	// Basic database settings
	DBName           string `json:"dbName"`
	NodeCount        int    `json:"nodeCount"`           // Total nodes (used when subclusters not specified)
	InitPolicy       string `json:"initPolicy"`          // Create, Revive, ScheduleOnly
	UpgradePolicy    string `json:"upgradePolicy"`       // Auto, Offline, Online
	KSafety          int    `json:"kSafety"`             // 0, 1, or 2
	ShardCount       int    `json:"shardCount"`          // Override default calculation
	AutoRestart      *bool  `json:"autoRestart"`         // Auto-restart Vertica on failure
	Namespace        string `json:"namespace"`           // Kubernetes namespace
	ImageOverride    string `json:"imageOverride"`       // Custom Vertica image
	ImagePullPolicy  string `json:"imagePullPolicy"`     // Always, IfNotPresent, Never

	// Communal storage (EON mode)
	StorageType            string `json:"storageType"`            // s3, gcs, azure, hdfs, minio
	CommunalPath           string `json:"communalPath"`           // Full path to communal storage
	CredentialSecret       string `json:"credentialSecret"`       // K8s secret for storage credentials
	Region                 string `json:"region"`                 // Cloud region
	Endpoint               string `json:"endpoint"`               // Storage endpoint URL
	IncludeUIDInPath       *bool  `json:"includeUIDInPath"`       // Add UID to communal path
	S3ServerSideEncryption string `json:"s3ServerSideEncryption"` // AES256, aws:kms
	CaFile                 string `json:"caFile"`                 // CA file for communal storage

	// Local storage
	DataPath     string `json:"dataPath"`     // Local data path
	DepotPath    string `json:"depotPath"`    // Depot cache path
	CatalogPath  string `json:"catalogPath"`  // Catalog path
	RequestSize  string `json:"requestSize"`  // PV size request
	StorageClass string `json:"storageClass"` // K8s storage class
	DepotVolume  string `json:"depotVolume"`  // Depot volume type

	// Secrets
	LicenseSecret           string `json:"licenseSecret"`
	SuperuserPasswordSecret string `json:"superuserPasswordSecret"`
	PasswordSecret          string `json:"passwordSecret"`
	KerberosSecret          string `json:"kerberosSecret"`

	// TLS/Security
	EncryptSpreadComm     string `json:"encryptSpreadComm"`     // vertica, disabled
	NMATLSSecret          string `json:"nmaTLSSecret"`          // Simple TLS approach
	HTTPSNMATLSMode       string `json:"httpsNMATLSMode"`       // disable, enable, try_verify, verify_ca, verify_full (25.3+)
	HTTPSNMATLSSecret     string `json:"httpsNMATLSSecret"`     // TLS secret for NMA (25.3+)
	ClientServerTLSMode   string `json:"clientServerTLSMode"`   // disable, enable, try_verify, verify_ca, verify_full (25.3+)
	ClientServerTLSSecret string `json:"clientServerTLSSecret"` // TLS secret for client-server (25.3+)

	// Service configuration
	ServiceType       string `json:"serviceType"`       // ClusterIP, NodePort, LoadBalancer
	ServiceClientPort int    `json:"serviceClientPort"` // Default: 5433 (25.3+)
	ServiceHTTPSPort  int    `json:"serviceHTTPSPort"`  // Default: 8443 (25.3+)

	// Multi-subcluster configuration (NEW)
	Subclusters []SubclusterConfig `json:"subclusters"` // Multiple subclusters

	// Single subcluster configuration (backward compatibility)
	SubclusterName string `json:"subclusterName"` // Name for primary subcluster
	SubclusterType string `json:"subclusterType"` // primary, secondary

	// Resource limits (per pod - used when subclusters not specified)
	CPURequest    string `json:"cpuRequest"`    // e.g., "2", "2000m"
	MemoryRequest string `json:"memoryRequest"` // e.g., "8Gi"
	CPULimit      string `json:"cpuLimit"`      // e.g., "4"
	MemoryLimit   string `json:"memoryLimit"`   // e.g., "16Gi"

	// Advanced features
	HadoopConfig          string            `json:"hadoopConfig"`          // ConfigMap for Hadoop config
	ServiceAccountName    string            `json:"serviceAccountName"`    // K8s service account
	PriorityClassName     string            `json:"priorityClassName"`     // Pod priority class (global, can be overridden per subcluster)
	NodeSelector          map[string]string `json:"nodeSelector"`          // Node selector labels (global, can be overridden per subcluster)
	Labels                map[string]string `json:"labels"`                // Custom labels
	Annotations           map[string]string `json:"annotations"`           // Custom annotations
	ServiceAnnotations    map[string]string `json:"serviceAnnotations"`    // Service-specific annotations

	// Sandboxes (25.3+)
	SandboxNames []string `json:"sandboxNames"` // List of sandbox names to create

	// Proxy configuration
	ProxyEnabled  bool `json:"proxyEnabled"`  // Enable client proxy
	ProxyReplicas int  `json:"proxyReplicas"` // Number of proxy replicas

	// Restore configuration
	RestoreArchive string `json:"restoreArchive"` // Archive name for restore
	RestoreID      string `json:"restoreID"`      // Restore point ID

	// Temporary subcluster routing (25.2+)
	TemporarySubclusterNames []string `json:"temporarySubclusterNames"` // Names of temporary subclusters for routing

	// Update mode (for handling updates vs creates)
	IsUpdate     bool     `json:"isUpdate"`     // True if updating existing config
	UpdateFields []string `json:"updateFields"` // List of fields to update
}

// ApplyDefaults fills all missing fields with canonical defaults (Phase 2)
// This ALWAYS runs after intent detection, whether from regex or LLM
func ApplyDefaults(cfg *ParsedConfig) {
	// Helper for bool pointers
	ptr := func(b bool) *bool { return &b }
	
	// Basic settings
	if cfg.DBName == "" {
		cfg.DBName = "verticadb"
	}
	if cfg.InitPolicy == "" {
		cfg.InitPolicy = DefaultVerticaSpec.InitPolicy
	}
	if cfg.UpgradePolicy == "" {
		cfg.UpgradePolicy = DefaultVerticaSpec.UpgradePolicy
	}
	if cfg.ImagePullPolicy == "" {
		cfg.ImagePullPolicy = DefaultVerticaSpec.ImagePullPolicy
	}
	if cfg.KSafety == 0 {
		cfg.KSafety = DefaultVerticaSpec.KSafety
	}
	if cfg.AutoRestart == nil {
		cfg.AutoRestart = ptr(true)
	}
	if cfg.IncludeUIDInPath == nil {
		cfg.IncludeUIDInPath = ptr(true)
	}
	
	// Service ports
	if cfg.ServiceClientPort == 0 {
		cfg.ServiceClientPort = DefaultVerticaSpec.ServiceClientPort
	}
	if cfg.ServiceHTTPSPort == 0 {
		cfg.ServiceHTTPSPort = DefaultVerticaSpec.ServiceHTTPSPort
	}
	
	// Communal storage defaults
	if cfg.StorageType == "s3" {
		if cfg.Region == "" {
			cfg.Region = DefaultVerticaSpec.Region
		}
		if cfg.Endpoint == "" {
			cfg.Endpoint = DefaultVerticaSpec.Endpoint
		}
	}
	
	// Subcluster defaults
	if cfg.SubclusterName == "" && len(cfg.Subclusters) == 0 {
		cfg.SubclusterName = "defaultsubcluster"
		cfg.SubclusterType = "primary"
	}
	
	// Apply resource defaults to all subclusters
	for i := range cfg.Subclusters {
		ApplySubclusterDefaults(&cfg.Subclusters[i], i)
	}
}

// ApplySubclusterDefaults fills missing subcluster fields with defaults
func ApplySubclusterDefaults(sc *SubclusterConfig, index int) {
	if sc.ServiceType == "" {
		sc.ServiceType = DefaultSubclusterResources.ServiceType
	}
	if sc.CPURequest == "" {
		sc.CPURequest = DefaultSubclusterResources.CPURequest
	}
	if sc.MemoryRequest == "" {
		sc.MemoryRequest = DefaultSubclusterResources.MemoryRequest
	}
	if sc.CPULimit == "" {
		sc.CPULimit = DefaultSubclusterResources.CPULimit
	}
	if sc.MemoryLimit == "" {
		sc.MemoryLimit = DefaultSubclusterResources.MemoryLimit
	}
	
	// Validate and correct type (ONLY "primary" or "secondary" allowed)
	if sc.Type != "primary" && sc.Type != "secondary" {
		if index == 0 {
			sc.Type = "primary" // First subcluster is always primary
		} else {
			sc.Type = "secondary" // All others are secondary
		}
	}
}

// UpdateIntent represents what the user wants to change (minimal, no full YAML)
type UpdateIntent struct {
	Operation      string                 `json:"operation"` // add_subcluster, remove_subcluster, scale_subcluster, update_field, etc.
	SubclusterName string                 `json:"subclusterName,omitempty"`
	Subcluster     *SubclusterConfig      `json:"subcluster,omitempty"`
	Size           int                    `json:"size,omitempty"`
	Resources      map[string]string      `json:"resources,omitempty"`
	FieldPath      string                 `json:"fieldPath,omitempty"`      // Dot-notation path: spec.image, spec.communal.path, spec.initPolicy
	FieldValue     interface{}            `json:"fieldValue,omitempty"`     // New value for the field
	Fields         map[string]interface{} `json:"fields,omitempty"`         // Multiple field updates (deprecated, use update_field)
}

// ParseUpdateIntent extracts ONLY the change intent (fast, minimal prompt)
func (c *OllamaClient) ParseUpdateIntent(ctx context.Context, instruction, version string) (*UpdateIntent, error) {
	// Comprehensive prompt covering all CRD fields
	prompt := fmt.Sprintf(`Extract update intent. Return JSON only.

Instruction: %s
CRD Version: %s

Operations:
- add_subcluster: Add new subcluster (type="secondary")
- remove_subcluster: Remove subcluster by name
- scale_subcluster: Change node count (needs subclusterName + size)
- update_resources: Change CPU/memory for subcluster(s)
- update_field: Change any spec field (use fieldPath + fieldValue)

Common fieldPath examples:
- spec.image (string)
- spec.dbName (string)
- spec.initPolicy (string: Create|Revive|ScheduleOnly)
- spec.upgradePolicy (string: Auto|Manual|Offline)
- spec.autoRestartVertica (bool)
- spec.kSafety (int: 0|1)
- spec.communal.path (string: s3://...)
- spec.communal.endpoint (string)
- spec.communal.credentialSecret (string)
- spec.communal.region (string)
- spec.local.requestSize (string: 500Gi)
- spec.imagePullPolicy (string: Always|IfNotPresent|Never)
- spec.encryptSpreadComm (string: vertica|disabled)

Size extraction:
- "6 nodes" → size: 6
- "scale to 5" → size: 5

Examples:
{"operation": "add_subcluster", "subcluster": {"name": "analytics", "type": "secondary", "size": 6}}
{"operation": "remove_subcluster", "subclusterName": "subcluster3"}
{"operation": "scale_subcluster", "subclusterName": "primary", "size": 5}
{"operation": "update_field", "fieldPath": "spec.image", "fieldValue": "opentext/vertica-k8s:25.4.0"}
{"operation": "update_field", "fieldPath": "spec.initPolicy", "fieldValue": "Revive"}
{"operation": "update_field", "fieldPath": "spec.communal.path", "fieldValue": "s3://new-bucket/path"}

JSON:`, instruction, version)

	response, err := c.generateWithContext(ctx, prompt, 1024) // Increased from 512 for better accuracy
	if err != nil {
		return nil, fmt.Errorf("intent extraction failed: %w", err)
	}

	// Clean response
	response = strings.TrimSpace(response)
	if strings.HasPrefix(response, "```json") {
		response = strings.TrimPrefix(response, "```json")
		response = strings.TrimPrefix(response, "```")
	}
	if strings.HasSuffix(response, "```") {
		response = strings.TrimSuffix(response, "```")
	}
	response = strings.TrimSpace(response)

	// Extract JSON
	if idx := strings.Index(response, "{"); idx != -1 {
		response = response[idx:]
	}
	if idx := strings.LastIndex(response, "}"); idx != -1 {
		response = response[:idx+1]
	}

	var intent UpdateIntent
	if err := json.Unmarshal([]byte(response), &intent); err != nil {
		return nil, fmt.Errorf("failed to parse intent: %w (response: %s)", err, response)
	}

	// FORCE secondary type for add_subcluster (override whatever LLM said)
	if intent.Operation == "add_subcluster" && intent.Subcluster != nil {
		intent.Subcluster.Type = "secondary" // ALWAYS secondary for new subclusters
		
		// Default name if not specified
		if intent.Subcluster.Name == "" {
			intent.Subcluster.Name = "secondary"
		}
		
		// Default size if not specified
		if intent.Subcluster.Size == 0 {
			intent.Subcluster.Size = 3
		}
	}

	return &intent, nil
}

// parseSimpleCREATE attempts deterministic parsing for simple CREATE requests (bypasses LLM)
// Returns nil if request is too complex and needs LLM
func parseSimpleCREATE(instruction string) *ParsedConfig {
	lower := strings.ToLower(instruction)
	
	// Extract node count (3 is default)
	nodeCount := 3
	for _, word := range strings.Fields(instruction) {
		if num := strings.TrimSuffix(strings.TrimSuffix(word, "-node"), "-nodes"); num != word {
			var n int
			if _, err := fmt.Sscanf(num, "%d", &n); err == nil && n > 0 {
				nodeCount = n
				break
			}
		}
	}
	
	// Detect storage type (default s3)
	storageType := "s3"
	communalPath := "s3://vertica-data/db"
	credentialSecret := "aws-credentials"
	
	if strings.Contains(lower, "gcs") || strings.Contains(lower, "google") {
		storageType = "gcs"
		communalPath = "gs://vertica-data/db"
		credentialSecret = "gcs-credentials"
	} else if strings.Contains(lower, "azure") {
		storageType = "azure"
		communalPath = "azb://vertica-data/db"
		credentialSecret = "azure-credentials"
	} else if strings.Contains(lower, "local") || strings.Contains(lower, "persistent") {
		storageType = "persistent"
		communalPath = ""
		credentialSecret = ""
	}
	
	// Only handle simple cases (no subclusters, tls, resources, etc.)
	if strings.Contains(lower, "subcluster") || 
	   strings.Contains(lower, "tls") ||
	   strings.Contains(lower, "security") ||
	   strings.Contains(lower, "sandbox") ||
	   strings.Contains(lower, "proxy") ||
	   strings.Contains(lower, "restore") ||
	   strings.Contains(lower, "cpu") ||
	   strings.Contains(lower, "memory") ||
	   strings.Contains(lower, "resource") {
		return nil // Too complex, needs LLM
	}
	
	log.Printf("✅ Simple CREATE detected - bypassing LLM (deterministic parsing)")
	
	// Phase 1: Return minimal intent (Phase 2 will fill defaults)
	return &ParsedConfig{
		NodeCount:        nodeCount,
		StorageType:      storageType,
		CommunalPath:     communalPath,
		CredentialSecret: credentialSecret,
	}
}

// ParseInstruction uses LLM to parse natural language instruction into structured config
func (c *OllamaClient) ParseInstruction(ctx context.Context, instruction, version string) (*ParsedConfig, error) {
	// Phase 1: Intent detection (try deterministic first, fall back to LLM)
	var parsedConfig *ParsedConfig
	var err error
	
	if simpleConfig := parseSimpleCREATE(instruction); simpleConfig != nil {
		parsedConfig = simpleConfig
	} else {
		log.Printf("🤖 Complex request detected - using LLM for parsing")
		parsedConfig, err = c.parseWithLLM(ctx, instruction, version)
		if err != nil {
			return nil, err
		}
	}
	
	// Phase 2: Apply comprehensive defaults (ALWAYS runs)
	ApplyDefaults(parsedConfig)
	
	return parsedConfig, nil
}

// parseWithLLM handles LLM-based parsing for complex requests
func (c *OllamaClient) parseWithLLM(ctx context.Context, instruction, version string) (*ParsedConfig, error) {
	// Single-phase: Precise prompt with all CRD-valid values
	prompt := fmt.Sprintf(`Parse Vertica cluster config. Return valid JSON only.

Instruction: %s

CRITICAL RULES:
1. Subcluster "type" MUST be: "primary" or "secondary" (case-sensitive)
2. Size extraction: "6 nodes" → size:6, "3-node" → size:3
3. Storage types: "s3", "gcs", "azure", "persistent"
4. First subcluster is ALWAYS type="primary"
5. Additional subclusters are type="secondary"

Required fields:
{
  "dbName": "verticadb",
  "storageType": "s3|gcs|azure|persistent",
  "communalPath": "s3://bucket/path",
  "credentialSecret": "secret-name",
  "subclusters": [
    {"name": "primary", "type": "primary", "size": 3},
    {"name": "secondary", "type": "secondary", "size": 3}
  ]
}

JSON:`, instruction)

	response, err := c.Generate(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("LLM generation failed: %w", err)
	}

	// Clean response - extract JSON from code blocks if present
	response = strings.TrimSpace(response)
	// Remove markdown code blocks if present
	if strings.HasPrefix(response, "```json") {
		response = strings.TrimPrefix(response, "```json")
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
		return nil, fmt.Errorf("failed to parse LLM response as JSON: %w (response: %s)", err, response)
	}

	// Note: ApplyDefaults() in ParseInstruction() will fill ALL missing fields
	// No need to duplicate default logic here
	return &config, nil
}

// ExplainValidationErrors uses LLM to explain validation errors in plain language
func (c *OllamaClient) ExplainValidationErrors(ctx context.Context, yamlContent string, errors []string, version string) (string, error) {
	if len(errors) == 0 {
		return "✓ No validation errors found. The YAML is valid!", nil
	}

	errorsText := strings.Join(errors, "\n")

	prompt := fmt.Sprintf(`You are a Vertica database expert. A user has YAML configuration errors that need to be explained in simple, actionable language.

YAML Version: %s
Validation Errors:
%s

YAML Content:
%s

Please provide:
1. A brief summary of what's wrong
2. For each error, explain it in plain language and suggest how to fix it
3. Provide corrected YAML snippets where applicable

Keep explanations concise and actionable. Focus on helping the user understand and fix the issues.

Response:`, version, errorsText, yamlContent)

	response, err := c.Generate(ctx, prompt)
	if err != nil {
		return "", fmt.Errorf("failed to generate explanation: %w", err)
	}

	return strings.TrimSpace(response), nil
}

// SummarizeDatabase uses LLM to generate a human-readable summary of database configuration
func (c *OllamaClient) SummarizeDatabase(ctx context.Context, dbInfo map[string]interface{}) (string, error) {
	// Convert dbInfo to JSON for the LLM
	jsonBytes, err := json.Marshal(dbInfo)
	if err != nil {
		return "", fmt.Errorf("failed to marshal database info: %w", err)
	}

	prompt := fmt.Sprintf(`You are a Vertica database expert. Analyze this database configuration and provide a clear, concise summary for a database administrator.

Database Configuration (JSON):
%s

Please provide:
1. Overview (database name, version, mode, node count)
2. Storage configuration (type, paths, capacity)
3. Resource allocation (CPU, memory per node)
4. High availability setup (K-safety, subclusters)
5. Notable features or configurations
6. Any recommendations or warnings

Keep the summary concise and focused on the most important details.

Summary:`, string(jsonBytes))

	response, err := c.Generate(ctx, prompt)
	if err != nil {
		return "", fmt.Errorf("failed to generate summary: %w", err)
	}

	return strings.TrimSpace(response), nil
}
