/*
Vertica MCP Server - Production Main Entry Point
Author: Sruthi Anumula
Enhanced: Refactored architecture with security hardening
Version: 6.2.0

This is the new main entry point that uses the refactored modular architecture.
It replaces mainv6_1.go with improved security and clean code organization.
*/
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"vertica-mcp-server/internal/state"
	"vertica-mcp-server/pkg/config"
	"vertica-mcp-server/pkg/database"
	"vertica-mcp-server/pkg/llm"
	"vertica-mcp-server/pkg/models"
	"vertica-mcp-server/pkg/security"
	"vertica-mcp-server/pkg/validation"
	_ "github.com/vertica/vertica-sql-go"
	"gopkg.in/yaml.v3"
)

// Global instances (initialized once)
var (
	cfg          *config.Config
	httpClient   *http.Client
	stateManager *state.Manager
	validator    validation.Validator
	registry     *validation.SchemaRegistry
	llmClient    llm.LLMClient // Unified LLM interface
	// jobManager removed - async pattern unused by Claude Desktop
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	log.Println("🚀 Vertica MCP Server v7.0.0 - Simplified Architecture")
	log.Println("========================================================")

	// Initialize configuration
	cfg = config.Load()
	log.Printf("✓ Configuration loaded (Ollama: %s, Model: %s)", cfg.OllamaURL, cfg.OllamaModel)

	// Initialize secure HTTP client
	httpClient = security.SecureHTTPClient()
	log.Println("✓ Secure HTTP client initialized (TLS 1.2+, timeouts enabled)")

	// Initialize thread-safe state manager
	stateManager = state.NewManager()
	log.Println("✓ Thread-safe state manager initialized")

	// Background job manager removed - Claude Desktop doesn't use async pattern

	// Initialize validation registry
	registry = validation.NewSchemaRegistry(httpClient)
	validator = validation.NewValidator(registry)
	log.Println("✓ Validation engine initialized")

	// Initialize LLM client based on provider
	if cfg.LLMProvider == "gemini" && cfg.GeminiAPIKey != "" {
		llmClient = llm.NewGeminiClient(cfg.GeminiAPIKey, cfg.GeminiModel, httpClient)
		log.Printf("✓ Google Gemini LLM client initialized (%s) - Fast cloud inference", cfg.GeminiModel)
	} else {
		// Use Ollama with long-running HTTP client
		ollamaHTTPClient := security.LongRunningHTTPClient(cfg.HTTPTimeout)
		llmClient = llm.NewOllamaClient(cfg.OllamaURL, cfg.OllamaModel, ollamaHTTPClient)
		log.Printf("✓ Ollama LLM client initialized (%s, timeout: %v)", cfg.OllamaModel, cfg.HTTPTimeout)
		
		// Warmup model (eliminates 3-minute cold start)
		if ollamaClient, ok := llmClient.(*llm.OllamaClient); ok {
			go ollamaClient.Warmup() // Non-blocking warmup
		}
	}

	// Pre-load CRD schema (non-blocking)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		log.Printf("Attempting to pre-load CRD schema for version %s...", cfg.DefaultVersion)
		if err := registry.LoadCRDSchema(ctx, cfg.DefaultVersion); err != nil {
			log.Printf("⚠️  Could not pre-load CRD schema: %v (will use basic validation)", err)
		} else {
			log.Println("✓ CRD schema loaded successfully")
		}
	}()

	// Create MCP server
	s := server.NewMCPServer("Vertica YAML Generator", "7.0.0")

	// Register 4 core tools (removed unused Get_Result and Load_CRD)
	s.AddTool(createGeneratorTool(), handleYAMLGeneration)
	s.AddTool(createUpdateYAMLTool(), handleUpdateYAML)
	s.AddTool(createValidationTool(), handleValidation)
	s.AddTool(createInspectorTool(), handleDBInspection)

	log.Println("✓ All 4 core tools registered successfully")

	// Determine mode (stdio or HTTP)
	useHTTP := false
	for _, arg := range os.Args {
		if arg == "--http" {
			useHTTP = true
			break
		}
	}
	if os.Getenv("HTTP_MODE") == "true" {
		useHTTP = true
	}

	if useHTTP {
		// HTTP mode - Streamable HTTP server for MCP protocol
		port := cfg.HTTPPort
		if port == "" {
			port = "9090" // Avoid conflict with Vertica ports
		}

		log.Printf("🌐 Starting server in HTTP mode (Streamable HTTP) on port %s", port)
		log.Println("MCP Streamable HTTP transport enabled")
		log.Printf("📡 Endpoint: http://localhost:%s/mcp", port)
		log.Println("✅ 4 core MCP tools available: Generate_YAML, Update_YAML, Validate_YAML, Inspect_DB")

		// Create Streamable HTTP server
		httpServer := server.NewStreamableHTTPServer(s)

		// Graceful shutdown handler
		go func() {
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
			<-sigChan

			log.Println("\n🛑 Shutting down gracefully...")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := httpServer.Shutdown(ctx); err != nil {
				log.Printf("❌ Server shutdown error: %v", err)
			}
			log.Println("✓ Server stopped")
			os.Exit(0)
		}()

		// Start HTTP server
		// Bind to all interfaces (0.0.0.0) for remote access
		addr := "0.0.0.0:" + port
		log.Printf("✓ Streamable HTTP server listening on %s", addr)
		log.Printf("⚠️  Server bound to all interfaces - ensure firewall is configured")

		if err := httpServer.Start(addr); err != nil {
			log.Fatalf("❌ HTTP server error: %v\n", err)
		}
	} else {
		// Stdio mode - standard MCP protocol
		log.Println("🔌 Starting server in stdio mode (MCP protocol)")
		if err := server.ServeStdio(s); err != nil {
			log.Fatalf("❌ Server error: %v\n", err)
		}
	}
}

// ============================================================================
// TOOL DEFINITIONS
// ============================================================================

func createGeneratorTool() mcp.Tool {
	return mcp.NewTool("Vertica_Dynamic_YAML_Generator",
		mcp.WithDescription("Create a NEW VerticaDB cluster from scratch. Use ONLY for: 'Create cluster', 'Deploy new database', 'Initialize Vertica', 'Set up new cluster'. Do NOT use this for modifying existing clusters - use Update_YAML instead."),
		mcp.WithString("instruction", mcp.Required(), mcp.Description("Natural language instruction describing the NEW cluster (e.g., 'Create 3-node cluster with S3 storage', 'Deploy cluster with 2 subclusters')")),
		mcp.WithString("version", mcp.Description("Target version: 25.1, 25.2, 25.3, or 25.4 (default: 25.4)")),
	)
}

func createInspectorTool() mcp.Tool {
	return mcp.NewTool("Vertica_DB_Inspect_Generate",
		mcp.WithDescription("Inspect existing Vertica database and generate YAML from its configuration. Includes AI-powered configuration summary."),
		mcp.WithString("host", mcp.Required(), mcp.Description("Database host")),
		mcp.WithString("port", mcp.Description("Database port (default: 5433)")),
		mcp.WithString("database", mcp.Required(), mcp.Description("Database name")),
		mcp.WithString("username", mcp.Required(), mcp.Description("Database username")),
		mcp.WithString("password", mcp.Required(), mcp.Description("Database password")),
		mcp.WithString("version", mcp.Description("Target YAML version (default: 25.4)")),
	)
}

func createValidationTool() mcp.Tool {
	return mcp.NewTool("Vertica_Validate_YAML",
		mcp.WithDescription("Validate VerticaDB YAML against version-specific schema and CRD. Provides AI-powered error explanations when validation fails."),
		mcp.WithString("yaml", mcp.Required(), mcp.Description("YAML content to validate")),
		mcp.WithString("version", mcp.Required(), mcp.Description("Target version: 25.1, 25.2, 25.3, or 25.4")),
	)
}

// REMOVED: Load_CRD_Schema tool (internal operation, not user-facing)
// REMOVED: Get_Result tool (async pattern unused by Claude Desktop)

func createUpdateYAMLTool() mcp.Tool {
	return mcp.NewTool("Vertica_Update_YAML",
		mcp.WithDescription("MODIFY an EXISTING VerticaDB cluster. Use this for: 'Add subcluster', 'Remove subcluster', 'Scale nodes', 'Change resources', 'Update configuration', 'Add third subcluster'. This is 10x faster than recreating. Requires existing YAML as input."),
		mcp.WithString("yaml", mcp.Required(), mcp.Description("Existing VerticaDB YAML to modify")),
		mcp.WithString("instruction", mcp.Required(), mcp.Description("What to change (e.g., 'add subcluster3 with 6 nodes', 'remove subcluster2', 'scale primary to 5 nodes')")),
		mcp.WithString("version", mcp.Description("Target version (default: extracted from YAML or 25.4)")),
	)
}

// ============================================================================
// TOOL HANDLERS
// ============================================================================

func handleYAMLGeneration(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	log.Println("📝 Handling YAML generation request...")

	// Extract parameters
	instruction := getStringParam(req, "instruction")
	version := getStringParam(req, "version")
	asyncMode := getStringParam(req, "async") == "true" // Check if async requested
	
	if version == "" {
		version = cfg.DefaultVersion
	}

	if instruction == "" {
		return mcp.NewToolResultError("instruction parameter is required"), nil
	}

	log.Printf("📋 Request: instruction='%s', version=%s, async=%v", instruction, version, asyncMode)

	// Async mode removed - all requests processed synchronously
	return processYAMLGenerationSync(ctx, instruction, version)
}

// processYAMLGenerationSync handles synchronous YAML generation (original logic)
func processYAMLGenerationSync(ctx context.Context, instruction, version string) (*mcp.CallToolResult, error) {

	// Parse instruction using LLM with timeout handling
	log.Printf("🤖 Parsing instruction with LLM (version: %s): %s", version, instruction)
	
	// Use longer timeout for large models (70B) on CPU
	llmTimeout := 10 * time.Minute
	if cfg.HTTPTimeout < llmTimeout {
		llmTimeout = cfg.HTTPTimeout
	}
	
	log.Printf("⏱️  Using %v timeout for LLM parsing", llmTimeout)
	
	parseCtx, parseCancel := context.WithTimeout(context.Background(), llmTimeout)
	defer parseCancel()

	parsedConfig, err := llmClient.ParseInstruction(parseCtx, instruction, version)
	if err != nil {
		log.Printf("⚠️  LLM parsing failed after %v: %v (falling back to simple parsing)", llmTimeout, err)
		// Fallback to simple parsing
		instructionLower := strings.ToLower(instruction)
		parsedConfig = &llm.ParsedConfig{
			DBName:      "vertdb",
			NodeCount:   parseNodeCount(instructionLower),
			StorageType: parseStorageType(instructionLower),
			Region:      "us-east-1",
		}
	} else {
		if parsedConfig.IsUpdate {
			log.Printf("✓ LLM detected UPDATE operation for fields: %v", parsedConfig.UpdateFields)
		}
		if len(parsedConfig.Subclusters) > 0 {
			log.Printf("✓ LLM parsed config: dbName=%s, subclusters=%d, storage=%s, path=%s",
				parsedConfig.DBName, len(parsedConfig.Subclusters), parsedConfig.StorageType,
				parsedConfig.CommunalPath)
		} else {
			log.Printf("✓ LLM parsed config: dbName=%s, nodes=%d, storage=%s, path=%s, secret=%s",
				parsedConfig.DBName, parsedConfig.NodeCount, parsedConfig.StorageType,
				parsedConfig.CommunalPath, parsedConfig.CredentialSecret)
		}
	}

	// Extract values from parsed config
	storageType := parsedConfig.StorageType

	// Calculate total node count and PRIMARY node count
	nodeCount := parsedConfig.NodeCount
	primaryNodeCount := parsedConfig.NodeCount // For shardCount calculation
	
	if len(parsedConfig.Subclusters) > 0 {
		nodeCount = 0
		primaryNodeCount = 0
		for _, sc := range parsedConfig.Subclusters {
			nodeCount += sc.Size
			// Only count primary subclusters for shardCount
			if sc.Type == "primary" || sc.Type == "" {
				primaryNodeCount += sc.Size
			}
		}
	}

	// Get state for sample context
	st := stateManager.GetOrCreate(state.SampleContext)

	// Calculate shard count based on PRIMARY node count ONLY
	// Secondary subclusters don't participate in sharding
	shardCount := parsedConfig.ShardCount
	if shardCount == 0 {
		shardCount = primaryNodeCount * 3
		if shardCount < 6 {
			shardCount = 6
		}
	}

	// Set autoRestartVertica
	autoRestart := true
	if parsedConfig.AutoRestart != nil {
		autoRestart = *parsedConfig.AutoRestart
	}

	// Determine version-specific features
	// 25.2+: nmaSecurityContext, temporarySubclusterRouting
	// 25.3+: httpsNMATLS, clientServerTLS, serviceClientPort, serviceHTTPSPort
	// 25.4+: extraEnv, envFrom, TLS autoRotate
	isVersion253OrLater := version == "25.3" || version == "25.4"
	isVersion254 := version == "25.4"

	// Initialize with production-ready defaults based on official Vertica CRD documentation
	st.UpdateYamlState(func(db *models.VerticaDB) {
		db.APIVersion = "vertica.com/v1"
		db.Kind = "VerticaDB"
		db.Metadata = models.Metadata{
			Name:        parsedConfig.DBName,
			Namespace:   parsedConfig.Namespace,
			Labels:      parsedConfig.Labels,
			Annotations: parsedConfig.Annotations,
		}

		// Determine image
		image := fmt.Sprintf("opentext/vertica-k8s:%s.0", version)
		if parsedConfig.ImageOverride != "" {
			image = parsedConfig.ImageOverride
		}

		db.Spec = models.Spec{
			// Container image
			Image:           image,
			ImagePullPolicy: parsedConfig.ImagePullPolicy,

			// Database settings
			DBName:             parsedConfig.DBName,
			ShardCount:         shardCount,
			InitPolicy:         parsedConfig.InitPolicy,
			UpgradePolicy:      parsedConfig.UpgradePolicy,
			KSafety:            parsedConfig.KSafety,
			AutoRestartVertica: &autoRestart,

			// Credentials and secrets
			LicenseSecret:           parsedConfig.LicenseSecret,
			SuperuserPasswordSecret: parsedConfig.SuperuserPasswordSecret,
			PasswordSecret:          parsedConfig.PasswordSecret,
			KerberosSecret:          parsedConfig.KerberosSecret,

			// Security
			EncryptSpreadComm: parsedConfig.EncryptSpreadComm,
			NMATLSSecret:      parsedConfig.NMATLSSecret,

			// Advanced configuration
			HadoopConfig:       parsedConfig.HadoopConfig,
			ServiceAccountName: parsedConfig.ServiceAccountName,
			Labels:             parsedConfig.Labels,
			Annotations:        parsedConfig.Annotations,
		}

		// Build subclusters array
		if len(parsedConfig.Subclusters) > 0 {
			// Use LLM-parsed subclusters array (multi-subcluster mode)
			db.Spec.Subclusters = make([]models.Subcluster, 0, len(parsedConfig.Subclusters))
			for _, sc := range parsedConfig.Subclusters {
				subcluster := models.Subcluster{
					Name:        sc.Name,
					Size:        sc.Size,
					Type:        sc.Type,
					ServiceType: sc.ServiceType,
				}

				// Optional fields
				if sc.ServiceName != "" {
					subcluster.ServiceName = sc.ServiceName
				}
				if sc.ImageOverride != "" {
					subcluster.ImageOverride = sc.ImageOverride
				}
				if sc.PriorityClassName != "" {
					subcluster.PriorityClassName = sc.PriorityClassName
				} else if parsedConfig.PriorityClassName != "" {
					subcluster.PriorityClassName = parsedConfig.PriorityClassName // Use global
				}
				if len(sc.NodeSelector) > 0 {
					subcluster.NodeSelector = sc.NodeSelector
				} else if len(parsedConfig.NodeSelector) > 0 {
					subcluster.NodeSelector = parsedConfig.NodeSelector // Use global
				}
				if subcluster.ServiceType == "" {
					subcluster.ServiceType = parsedConfig.ServiceType // Use global default
				}
				if subcluster.Type == "" {
					subcluster.Type = "primary" // Default to primary
				}

				// Resources
				if sc.CPURequest != "" || sc.MemoryRequest != "" || sc.CPULimit != "" || sc.MemoryLimit != "" {
					subcluster.Resources = &models.Resources{
						Requests: &models.ResourceList{
							CPU:    sc.CPURequest,
							Memory: sc.MemoryRequest,
						},
						Limits: &models.ResourceList{
							CPU:    sc.CPULimit,
							Memory: sc.MemoryLimit,
						},
					}
				} else {
					// Use global defaults
					subcluster.Resources = &models.Resources{
						Requests: &models.ResourceList{
							CPU:    parsedConfig.CPURequest,
							Memory: parsedConfig.MemoryRequest,
						},
						Limits: &models.ResourceList{
							CPU:    parsedConfig.CPULimit,
							Memory: parsedConfig.MemoryLimit,
						},
					}
				}

				// Version 25.3+ service ports
				if isVersion253OrLater {
					if sc.ServiceClientPort > 0 {
						subcluster.ServiceClientPort = sc.ServiceClientPort
					}
					if sc.ServiceHTTPSPort > 0 {
						subcluster.ServiceHTTPSPort = sc.ServiceHTTPSPort
					}
				}

				// External IPs
				if len(sc.ExternalIPs) > 0 {
					subcluster.ExternalIPs = sc.ExternalIPs
				}

				// Shutdown
				subcluster.Shutdown = sc.Shutdown

				db.Spec.Subclusters = append(db.Spec.Subclusters, subcluster)
			}
			log.Printf("📊 Created %d subclusters from LLM-parsed configuration", len(db.Spec.Subclusters))
		} else {
			// Backward compatibility: single subcluster mode
			db.Spec.Subclusters = []models.Subcluster{
				{
					Name:              parsedConfig.SubclusterName,
					Size:              nodeCount,
					Type:              parsedConfig.SubclusterType,
					ServiceType:       parsedConfig.ServiceType,
					PriorityClassName: parsedConfig.PriorityClassName,
					NodeSelector:      parsedConfig.NodeSelector,
					Resources: &models.Resources{
						Requests: &models.ResourceList{
							CPU:    parsedConfig.CPURequest,
							Memory: parsedConfig.MemoryRequest,
						},
						Limits: &models.ResourceList{
							CPU:    parsedConfig.CPULimit,
							Memory: parsedConfig.MemoryLimit,
						},
					},
				},
			}
		}

		// Add proxy configuration if enabled
		if parsedConfig.ProxyEnabled {
			db.Spec.Proxy = &models.Proxy{
				Image: "opentext/client-proxy:latest",
			}
			db.Spec.Subclusters[0].Proxy = &models.SubclusterProxy{
				Replicas: parsedConfig.ProxyReplicas,
			}
			if db.Spec.Subclusters[0].Proxy.Replicas == 0 {
				db.Spec.Subclusters[0].Proxy.Replicas = 1
			}
		}

		// Version 25.3+ specific fields
		if isVersion253OrLater {
			// Service ports
			if parsedConfig.ServiceClientPort > 0 {
				db.Spec.ServiceClientPort = parsedConfig.ServiceClientPort
				db.Spec.Subclusters[0].ServiceClientPort = parsedConfig.ServiceClientPort
			} else {
				db.Spec.ServiceClientPort = 5433
			}

			if parsedConfig.ServiceHTTPSPort > 0 {
				db.Spec.ServiceHTTPSPort = parsedConfig.ServiceHTTPSPort
				db.Spec.Subclusters[0].ServiceHTTPSPort = parsedConfig.ServiceHTTPSPort
			} else {
				db.Spec.ServiceHTTPSPort = 8443
			}

			// Advanced TLS configuration (25.3+)
			if parsedConfig.HTTPSNMATLSSecret != "" || parsedConfig.HTTPSNMATLSMode != "" {
				db.Spec.HTTPSNMATLS = &models.TLSConfig{
					Mode:   parsedConfig.HTTPSNMATLSMode,
					Secret: parsedConfig.HTTPSNMATLSSecret,
				}
			}

			if parsedConfig.ClientServerTLSSecret != "" || parsedConfig.ClientServerTLSMode != "" {
				db.Spec.ClientServerTLS = &models.TLSConfig{
					Mode:   parsedConfig.ClientServerTLSMode,
					Secret: parsedConfig.ClientServerTLSSecret,
				}
			}
		}

		// Version 25.4 specific features
		_ = isVersion254 // Reserved for future use

		// Add communal storage configuration (required for EON mode)
		// This tool only generates EON-mode configurations
		db.Spec.Communal = buildCommunalConfig(parsedConfig)

		// Local storage for depot and data caching (required for EON mode)
		db.Spec.Local = &models.Local{
			DataPath:     parsedConfig.DataPath,
			DepotPath:    parsedConfig.DepotPath,
			CatalogPath:  parsedConfig.CatalogPath,
			RequestSize:  parsedConfig.RequestSize,
			StorageClass: parsedConfig.StorageClass,
			DepotVolume:  parsedConfig.DepotVolume,
		}

		// Sandboxes (25.3+)
		if len(parsedConfig.SandboxNames) > 0 {
			db.Spec.Sandboxes = make([]models.Sandbox, 0, len(parsedConfig.SandboxNames))
			for _, name := range parsedConfig.SandboxNames {
				db.Spec.Sandboxes = append(db.Spec.Sandboxes, models.Sandbox{
					Name: name,
				})
			}
		}

		// Restore point configuration
		if parsedConfig.RestoreArchive != "" || parsedConfig.RestoreID != "" {
			db.Spec.RestorePoint = &models.RestorePoint{
				Archive: parsedConfig.RestoreArchive,
				ID:      parsedConfig.RestoreID,
			}
		}

		// Temporary subcluster routing (25.2+)
		if len(parsedConfig.TemporarySubclusterNames) > 0 {
			db.Spec.TemporarySubclusterRouting = &models.TemporarySubclusterRouting{
				Names: parsedConfig.TemporarySubclusterNames,
			}
		}

		// Service annotations
		if len(parsedConfig.ServiceAnnotations) > 0 && len(db.Spec.Subclusters) > 0 {
			for i := range db.Spec.Subclusters {
				db.Spec.Subclusters[i].ServiceAnnotations = parsedConfig.ServiceAnnotations
			}
		}
	})

	log.Printf("📄 Generated YAML (version: %s, nodes: %d, EON: true, storage: %s)", version, nodeCount, storageType)

	// Get current state
	yamlState := st.GetYamlState()

	// Validate
	validationCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := validator.ValidateYAML(validationCtx, &yamlState, version)
	if err != nil {
		log.Printf("⚠️  Validation error: %v", err)
	}

	// Generate YAML
	yamlBytes, err := yaml.Marshal(&yamlState)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal YAML: %v", err)), nil
	}

	// Format response
	response := fmt.Sprintf("Generated VerticaDB YAML (version %s):\n\n%s\n\n%s",
		version, string(yamlBytes), validation.FormatResult(result))

	return mcp.NewToolResultText(response), nil
}

// handleUpdateYAML modifies existing YAML based on instruction (FAST - no full YAML to LLM)
func handleUpdateYAML(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	log.Println("📝 Handling YAML update request...")

	// Extract parameters
	existingYAML := getStringParam(req, "yaml")
	instruction := getStringParam(req, "instruction")
	version := getStringParam(req, "version")

	if existingYAML == "" {
		return mcp.NewToolResultError("yaml parameter is required"), nil
	}
	if instruction == "" {
		return mcp.NewToolResultError("instruction parameter is required"), nil
	}

	// Parse existing YAML to get current configuration
	log.Println("📄 Parsing existing YAML...")
	var existingDB models.VerticaDB
	if err := yaml.Unmarshal([]byte(existingYAML), &existingDB); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to parse existing YAML: %v", err)), nil
	}

	// Extract version from YAML if not provided
	if version == "" {
		if existingDB.Spec.Image != "" {
			// Try to extract version from image tag (e.g., "vertica-k8s:25.4.0")
			if strings.Contains(existingDB.Spec.Image, ":25.") {
				parts := strings.Split(existingDB.Spec.Image, ":25.")
				if len(parts) > 1 {
					version = "25." + strings.Split(parts[1], ".")[0]
				}
			}
		}
		if version == "" {
			version = cfg.DefaultVersion
		}
	}

	log.Printf("📋 Update request: instruction='%s', version=%s", instruction, version)

	// CRITICAL: Extract ONLY the intent (fast, minimal prompt, NO YAML sent to LLM)
	log.Printf("🔍 Extracting update intent (minimal LLM call)...")
	intentCtx, intentCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer intentCancel()

	intent, err := llmClient.ParseUpdateIntent(intentCtx, instruction, version)
	if err != nil {
		log.Printf("⚠️  Intent extraction failed: %v (applying fallback)", err)
		// Fallback to simple parsing
		intent = parseSimpleIntent(instruction)
	}

	log.Printf("✓ Intent extracted: operation=%s", intent.Operation)

	// Apply modifications deterministically in Go (instant, no hallucination)
	updated, err := applyIntentToYAML(&existingDB, intent, version)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to apply update: %v", err)), nil
	}

	// Generate updated YAML
	yamlBytes, err := yaml.Marshal(updated)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("YAML generation error: %v", err)), nil
	}

	yamlStr := string(yamlBytes)
	log.Printf("✓ Updated YAML generated (version: %s)", version)

	// Validate the updated YAML
	validationCtx, validationCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer validationCancel()

	var validationDB models.VerticaDB
	if err := yaml.Unmarshal(yamlBytes, &validationDB); err == nil {
		result, err := validator.ValidateYAML(validationCtx, &validationDB, version)
		if err == nil && len(result.Errors) > 0 {
			return mcp.NewToolResultText(fmt.Sprintf("⚠️  YAML updated but has validation issues:\n\n%s\n\n%s",
				strings.Join(result.Errors, "\n"), yamlStr)), nil
		}
	}

	return mcp.NewToolResultText(fmt.Sprintf("✓ YAML successfully updated\n\n%s", yamlStr)), nil
}

// applyIntentToYAML applies update intent deterministically (Go code, instant)
func applyIntentToYAML(existing *models.VerticaDB, intent *llm.UpdateIntent, version string) (*models.VerticaDB, error) {
	switch intent.Operation {
	case "add_subcluster":
		if intent.Subcluster == nil {
			return nil, fmt.Errorf("subcluster details required for add_subcluster")
		}
		
		// Validate: prevent multiple primary subclusters
		if intent.Subcluster.Type == "primary" {
			for _, sc := range existing.Spec.Subclusters {
				if sc.Type == "primary" {
					return nil, fmt.Errorf("cannot add primary subcluster: cluster already has primary '%s'. Use type=secondary", sc.Name)
				}
			}
		}
		
		// Auto-generate sequential name if LLM didn't provide a specific one
		// or provided a generic name like "new_subcluster"
		if intent.Subcluster.Name == "" || intent.Subcluster.Name == "new_subcluster" {
			intent.Subcluster.Name = fmt.Sprintf("subcluster%d", len(existing.Spec.Subclusters)+1)
		}
		
		// Validate: prevent duplicate names
		for _, sc := range existing.Spec.Subclusters {
			if sc.Name == intent.Subcluster.Name {
				return nil, fmt.Errorf("subcluster '%s' already exists. Use a different name or remove it first", sc.Name)
			}
		}
		
		log.Printf("➕ Adding subcluster: %s (type=%s, size=%d)", 
			intent.Subcluster.Name, intent.Subcluster.Type, intent.Subcluster.Size)
		
		subcluster := models.Subcluster{
			Name: intent.Subcluster.Name,
			Size: intent.Subcluster.Size,
			Type: intent.Subcluster.Type,
		}
		
		// Copy resources if specified in intent
		if intent.Subcluster.CPURequest != "" || intent.Subcluster.MemoryRequest != "" {
			subcluster.Resources = &models.Resources{
				Requests: &models.ResourceList{
					CPU:    intent.Subcluster.CPURequest,
					Memory: intent.Subcluster.MemoryRequest,
				},
			}
			if intent.Subcluster.CPULimit != "" || intent.Subcluster.MemoryLimit != "" {
				subcluster.Resources.Limits = &models.ResourceList{
					CPU:    intent.Subcluster.CPULimit,
					Memory: intent.Subcluster.MemoryLimit,
				}
			}
		}
		
		// Apply defaults to ensure all fields are populated (especially resources)
		if subcluster.ServiceType == "" {
			subcluster.ServiceType = "ClusterIP"
		}
		if subcluster.Resources == nil {
			subcluster.Resources = &models.Resources{
				Requests: &models.ResourceList{
					CPU:    "2",
					Memory: "8Gi",
				},
				Limits: &models.ResourceList{
					CPU:    "4",
					Memory: "16Gi",
				},
			}
		}
		
		existing.Spec.Subclusters = append(existing.Spec.Subclusters, subcluster)
		
	case "remove_subcluster":
		if intent.SubclusterName == "" {
			return nil, fmt.Errorf("subclusterName required for remove_subcluster")
		}
		log.Printf("➖ Removing subcluster: %s", intent.SubclusterName)
		filtered := []models.Subcluster{}
		found := false
		for _, sc := range existing.Spec.Subclusters {
			if sc.Name != intent.SubclusterName {
				filtered = append(filtered, sc)
			} else {
				found = true
				// Prevent removing the only/primary subcluster
				if sc.Type == "primary" && len(existing.Spec.Subclusters) == 1 {
					return nil, fmt.Errorf("cannot remove primary subcluster '%s': it's the only subcluster", sc.Name)
				}
			}
		}
		if !found {
			return nil, fmt.Errorf("subcluster '%s' not found", intent.SubclusterName)
		}
		existing.Spec.Subclusters = filtered
		
	case "scale_subcluster":
		if intent.SubclusterName == "" {
			return nil, fmt.Errorf("subclusterName required for scale_subcluster")
		}
		if intent.Size <= 0 {
			return nil, fmt.Errorf("size must be positive")
		}
		log.Printf("📏 Scaling subcluster %s to %d nodes", intent.SubclusterName, intent.Size)
		found := false
		for i := range existing.Spec.Subclusters {
			if existing.Spec.Subclusters[i].Name == intent.SubclusterName {
				existing.Spec.Subclusters[i].Size = intent.Size
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("subcluster '%s' not found", intent.SubclusterName)
		}
		
	case "update_resources":
		log.Printf("⚙️  Updating resources: %+v", intent.Resources)
		targetName := intent.SubclusterName // empty = all subclusters
		updated := false
		for i := range existing.Spec.Subclusters {
			if targetName == "" || existing.Spec.Subclusters[i].Name == targetName {
				if existing.Spec.Subclusters[i].Resources == nil {
					existing.Spec.Subclusters[i].Resources = &models.Resources{}
				}
				if existing.Spec.Subclusters[i].Resources.Requests == nil {
					existing.Spec.Subclusters[i].Resources.Requests = &models.ResourceList{}
				}
				if cpu, ok := intent.Resources["cpu"]; ok {
					existing.Spec.Subclusters[i].Resources.Requests.CPU = cpu
				}
				if memory, ok := intent.Resources["memory"]; ok {
					existing.Spec.Subclusters[i].Resources.Requests.Memory = memory
				}
				updated = true
			}
		}
		if !updated && targetName != "" {
			return nil, fmt.Errorf("subcluster '%s' not found", targetName)
		}
		
	case "change_image":
		if image, ok := intent.Fields["image"].(string); ok {
			log.Printf("🖼️  Updating image: %s", image)
			existing.Spec.Image = image
		} else {
			return nil, fmt.Errorf("image field required for change_image")
		}
		
	case "change_storage":
		log.Printf("💾 Updating storage configuration")
		if path, ok := intent.Fields["communalPath"].(string); ok {
			if existing.Spec.Communal == nil {
				existing.Spec.Communal = &models.Communal{}
			}
			existing.Spec.Communal.Path = path
		}
		if size, ok := intent.Fields["requestSize"].(string); ok {
			if existing.Spec.Local == nil {
				existing.Spec.Local = &models.Local{}
			}
			existing.Spec.Local.RequestSize = size
		}
		if secret, ok := intent.Fields["credentialSecret"].(string); ok {
			if existing.Spec.Communal == nil {
				existing.Spec.Communal = &models.Communal{}
			}
			existing.Spec.Communal.CredentialSecret = secret
		}
		
	case "update_ksafety":
		if ksafety, ok := intent.Fields["kSafety"].(float64); ok {
			log.Printf("🛡️  Updating K-Safety: %d", int(ksafety))
			existing.Spec.KSafety = int(ksafety)
		} else {
			return nil, fmt.Errorf("kSafety field required")
		}
	
	case "update_field":
		// Generic field updater using dot-notation path
		if intent.FieldPath == "" {
			return nil, fmt.Errorf("fieldPath required for update_field operation")
		}
		log.Printf("🔧 Updating field: %s = %v", intent.FieldPath, intent.FieldValue)
		
		if err := updateFieldByPath(existing, intent.FieldPath, intent.FieldValue); err != nil {
			return nil, fmt.Errorf("failed to update field %s: %w", intent.FieldPath, err)
		}
		
	default:
		return nil, fmt.Errorf("unsupported operation: %s", intent.Operation)
	}
	
	return existing, nil
}

// updateFieldByPath updates a field in the VerticaDB spec using dot-notation path
func updateFieldByPath(vdb *models.VerticaDB, path string, value interface{}) error {
	// Remove "spec." prefix if present
	path = strings.TrimPrefix(path, "spec.")
	
	parts := strings.Split(path, ".")
	
	// Top-level spec fields
	switch parts[0] {
	case "image":
		if v, ok := value.(string); ok {
			vdb.Spec.Image = v
		} else {
			return fmt.Errorf("image must be string")
		}
	case "dbName":
		if v, ok := value.(string); ok {
			vdb.Spec.DBName = v
		} else {
			return fmt.Errorf("dbName must be string")
		}
	case "initPolicy":
		if v, ok := value.(string); ok {
			vdb.Spec.InitPolicy = v
		} else {
			return fmt.Errorf("initPolicy must be string")
		}
	case "upgradePolicy":
		if v, ok := value.(string); ok {
			vdb.Spec.UpgradePolicy = v
		} else {
			return fmt.Errorf("upgradePolicy must be string")
		}
	case "imagePullPolicy":
		if v, ok := value.(string); ok {
			vdb.Spec.ImagePullPolicy = v
		} else {
			return fmt.Errorf("imagePullPolicy must be string")
		}
	case "autoRestartVertica":
		if v, ok := value.(bool); ok {
			vdb.Spec.AutoRestartVertica = &v
		} else {
			return fmt.Errorf("autoRestartVertica must be bool")
		}
	case "kSafety":
		// Handle both float64 (from JSON) and int
		switch v := value.(type) {
		case float64:
			vdb.Spec.KSafety = int(v)
		case int:
			vdb.Spec.KSafety = v
		default:
			return fmt.Errorf("kSafety must be int")
		}
	case "shardCount":
		switch v := value.(type) {
		case float64:
			vdb.Spec.ShardCount = int(v)
		case int:
			vdb.Spec.ShardCount = v
		default:
			return fmt.Errorf("shardCount must be int")
		}
	case "encryptSpreadComm":
		if v, ok := value.(string); ok {
			vdb.Spec.EncryptSpreadComm = v
		} else {
			return fmt.Errorf("encryptSpreadComm must be string")
		}
	
	// Nested communal fields
	case "communal":
		if len(parts) < 2 {
			return fmt.Errorf("communal path must specify subfield (e.g., communal.path)")
		}
		if vdb.Spec.Communal == nil {
			vdb.Spec.Communal = &models.Communal{}
		}
		switch parts[1] {
		case "path":
			if v, ok := value.(string); ok {
				vdb.Spec.Communal.Path = v
			} else {
				return fmt.Errorf("communal.path must be string")
			}
		case "endpoint":
			if v, ok := value.(string); ok {
				vdb.Spec.Communal.Endpoint = v
			} else {
				return fmt.Errorf("communal.endpoint must be string")
			}
		case "credentialSecret":
			if v, ok := value.(string); ok {
				vdb.Spec.Communal.CredentialSecret = v
			} else {
				return fmt.Errorf("communal.credentialSecret must be string")
			}
		case "region":
			if v, ok := value.(string); ok {
				vdb.Spec.Communal.Region = v
			} else {
				return fmt.Errorf("communal.region must be string")
			}
		case "includeUIDInPath":
			if v, ok := value.(bool); ok {
				vdb.Spec.Communal.IncludeUIDInPath = v
			} else {
				return fmt.Errorf("communal.includeUIDInPath must be bool")
			}
		default:
			return fmt.Errorf("unsupported communal field: %s", parts[1])
		}
	
	// Nested local fields
	case "local":
		if len(parts) < 2 {
			return fmt.Errorf("local path must specify subfield (e.g., local.requestSize)")
		}
		if vdb.Spec.Local == nil {
			vdb.Spec.Local = &models.Local{}
		}
		switch parts[1] {
		case "requestSize":
			if v, ok := value.(string); ok {
				vdb.Spec.Local.RequestSize = v
			} else {
				return fmt.Errorf("local.requestSize must be string")
			}
		case "storageClass":
			if v, ok := value.(string); ok {
				vdb.Spec.Local.StorageClass = v
			} else {
				return fmt.Errorf("local.storageClass must be string")
			}
		default:
			return fmt.Errorf("unsupported local field: %s", parts[1])
		}
	
	default:
		return fmt.Errorf("unsupported field path: %s", path)
	}
	
	return nil
}

// parseSimpleIntent provides fallback intent parsing (no LLM)
func parseSimpleIntent(instruction string) *llm.UpdateIntent {
	lower := strings.ToLower(instruction)
	intent := &llm.UpdateIntent{}
	
	if strings.Contains(lower, "add") && strings.Contains(lower, "subcluster") {
		intent.Operation = "add_subcluster"
		intent.Subcluster = &llm.SubclusterConfig{
			Name: "secondary",
			Type: "secondary",
			Size: 3,
		}
		// Try to extract size
		for _, word := range strings.Fields(lower) {
			if num, err := fmt.Sscanf(word, "%d", &intent.Subcluster.Size); err == nil && num == 1 {
				break
			}
		}
	} else if strings.Contains(lower, "scale") || strings.Contains(lower, "resize") {
		intent.Operation = "scale_subcluster"
		intent.Size = 3 // default
		for _, word := range strings.Fields(lower) {
			if num, err := fmt.Sscanf(word, "%d", &intent.Size); err == nil && num == 1 {
				break
			}
		}
	} else if strings.Contains(lower, "remove") || strings.Contains(lower, "delete") {
		intent.Operation = "remove_subcluster"
		intent.SubclusterName = "secondary"
	}
	
	return intent
}

// parseSimpleModification provides fallback parsing when LLM fails (DEPRECATED - use parseSimpleIntent)
func parseSimpleModification(instruction string) *llm.ParsedConfig {
	lower := strings.ToLower(instruction)
	config := &llm.ParsedConfig{}

	// Detect subcluster additions
	if strings.Contains(lower, "subcluster") || strings.Contains(lower, "add") {
		// Extract subcluster name
		if strings.Contains(lower, "named") {
			parts := strings.Split(lower, "named")
			if len(parts) > 1 {
				name := strings.TrimSpace(strings.Fields(parts[1])[0])
				size := parseNodeCount(lower)
				if size == 0 {
					size = 3 // Default
				}
				config.Subclusters = []llm.SubclusterConfig{{
					Name: name,
					Type: "secondary",
					Size: size,
				}}
			}
		}
	}

	// Detect resource changes
	if strings.Contains(lower, "memory") {
		// Extract memory value
		if strings.Contains(lower, "gi") {
			for _, word := range strings.Fields(lower) {
				if strings.HasSuffix(word, "gi") {
					config.MemoryRequest = strings.ToUpper(word)
					break
				}
			}
		}
	}

	if strings.Contains(lower, "cpu") {
		for _, word := range strings.Fields(lower) {
			if strings.HasSuffix(word, "m") || (len(word) <= 2 && word[0] >= '0' && word[0] <= '9') {
				config.CPURequest = word
				break
			}
		}
	}

	return config
}

// applyModifications applies parsed changes to existing VerticaDB
func applyModifications(existing *models.VerticaDB, changes *llm.ParsedConfig, version string) *models.VerticaDB {
	// Add new subclusters
	if len(changes.Subclusters) > 0 {
		log.Printf("Adding %d new subcluster(s)", len(changes.Subclusters))
		for _, newSC := range changes.Subclusters {
			subcluster := models.Subcluster{
				Name: newSC.Name,
				Size: newSC.Size,
				Type: newSC.Type,
			}
			if subcluster.Type == "" {
				subcluster.Type = "secondary" // Default for added subclusters
			}
			existing.Spec.Subclusters = append(existing.Spec.Subclusters, subcluster)
		}
	}

	// Update resources if specified
	if changes.MemoryRequest != "" || changes.CPURequest != "" {
		log.Printf("Updating resource requests: CPU=%s, Memory=%s", changes.CPURequest, changes.MemoryRequest)
		// Apply to all subclusters
		for i := range existing.Spec.Subclusters {
			if existing.Spec.Subclusters[i].Resources == nil {
				existing.Spec.Subclusters[i].Resources = &models.Resources{}
			}
			if existing.Spec.Subclusters[i].Resources.Requests == nil {
				existing.Spec.Subclusters[i].Resources.Requests = &models.ResourceList{}
			}
			if changes.CPURequest != "" {
				existing.Spec.Subclusters[i].Resources.Requests.CPU = changes.CPURequest
			}
			if changes.MemoryRequest != "" {
				existing.Spec.Subclusters[i].Resources.Requests.Memory = changes.MemoryRequest
			}
		}
	}

	// Update storage size if specified
	if changes.RequestSize != "" && existing.Spec.Local != nil {
		log.Printf("Updating storage size: %s", changes.RequestSize)
		existing.Spec.Local.RequestSize = changes.RequestSize
	}

	return existing
}

func handleDBInspection(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	log.Println("🔍 Handling database inspection request...")

	// Extract parameters
	host := getStringParam(req, "host")
	port := getStringParam(req, "port")
	dbName := getStringParam(req, "database")
	username := getStringParam(req, "username")
	password := getStringParam(req, "password")
	version := getStringParam(req, "version")

	if host == "" || dbName == "" || username == "" || password == "" {
		return mcp.NewToolResultError("host, database, username, and password are required"), nil
	}

	if port == "" {
		port = "5433"
	}
	if version == "" {
		version = cfg.DefaultVersion
	}

	// Build connection string
	connStr := fmt.Sprintf("vertica://%s:%s@%s:%s/%s", username, password, host, port, dbName)

	// Connect to database
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	db, err := sql.Open("vertica", connStr)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Connection failed: %v", err)), nil
	}
	defer db.Close()

	// Test connection
	if err := db.PingContext(ctx); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Ping failed: %v", err)), nil
	}

	log.Println("✓ Connected to database successfully")

	// Create repository
	repo := database.NewRepository(db)
	defer repo.Close()

	// Inspect database
	dbInfo, err := repo.InspectDatabase(ctx)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Inspection failed: %v", err)), nil
	}

	// Inspect subclusters
	subclusters, err := repo.InspectSubclusters(ctx)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Subcluster inspection failed: %v", err)), nil
	}

	log.Printf("✓ Inspected database: %s (version: %s, %d subclusters)",
		dbInfo.DatabaseName, dbInfo.Version, len(subclusters))

	// Build VerticaDB from inspection
	st := stateManager.GetOrCreate(state.InspectContext)

	st.UpdateYamlState(func(vdb *models.VerticaDB) {
		vdb.APIVersion = "vertica.com/v1"
		vdb.Kind = "VerticaDB"
		vdb.Metadata = models.Metadata{
			Name: strings.ToLower(dbInfo.DatabaseName),
		}
		vdb.Spec = models.Spec{
			Image:      fmt.Sprintf("opentext/vertica-k8s:%s.0", version),
			DBName:     dbInfo.DatabaseName,
			ShardCount: dbInfo.ShardCount,
			InitPolicy: "Revive",
		}

		// Add subclusters
		for _, sc := range subclusters {
			subcluster := models.Subcluster{
				Name: sc.Name,
				Size: sc.NodeCount,
			}
			if sc.IsPrimary {
				subcluster.Type = "primary"
			} else {
				subcluster.Type = "secondary"
			}
			vdb.Spec.Subclusters = append(vdb.Spec.Subclusters, subcluster)
		}

		// Add communal storage if Eon mode
		if dbInfo.IsEon && dbInfo.CommunalPath != "" {
			communal, _ := repo.GetCommunalConfig(ctx, dbInfo.CommunalPath, dbInfo.DatabaseName)
			vdb.Spec.Communal = communal
		}

		// Add local storage with actual sizes from database (matches vdbgen implementation)
		requestSize := "500Gi" // default
		if dbInfo.RequestSizeMB > 0 {
			// Convert MB to appropriate unit (Mi for Kubernetes)
			requestSize = fmt.Sprintf("%.0fMi", dbInfo.RequestSizeMB)
			log.Printf("✓ Using actual storage size from database: %s (Depot: %.0fMi + Catalog: %.0fMi)",
				requestSize, dbInfo.DepotSizeMB, dbInfo.CatalogSizeMB)
		}

		vdb.Spec.Local = &models.Local{
			DataPath:     dbInfo.DataPath,
			DepotPath:    dbInfo.DepotPath,
			CatalogPath:  dbInfo.CatalogPath,
			RequestSize:  requestSize,
			StorageClass: "standard",
		}
	})

	// Get generated YAML
	yamlState := st.GetYamlState()
	yamlBytes, err := yaml.Marshal(&yamlState)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal YAML: %v", err)), nil
	}

	response := fmt.Sprintf("Inspected Database: %s\n\nGenerated YAML:\n\n%s",
		dbInfo.DatabaseName, string(yamlBytes))

	// Generate credential secret if S3 credentials are available (matches vdbgen implementation)
	if dbInfo.IsEon {
		accessKey, secretKey, err := repo.GetS3Credentials(ctx)
		if err != nil {
			log.Printf("⚠️  Could not retrieve S3 credentials: %v", err)
		} else if accessKey != "" && secretKey != "" {
			// Create credential secret (matches vdbgen format)
			credSecret := models.Secret{
				APIVersion: "v1",
				Kind:       "Secret",
				Metadata: models.Metadata{
					Name: fmt.Sprintf("%s-s3-creds", strings.ToLower(dbInfo.DatabaseName)),
				},
				Data: map[string]string{
					"accesskey": accessKey,
					"secretkey": secretKey,
				},
			}
			credSecretBytes, err := yaml.Marshal(&credSecret)
			if err != nil {
				log.Printf("⚠️  Could not marshal credential secret: %v", err)
			} else {
				response += fmt.Sprintf("\n\n---\n%s", string(credSecretBytes))
				log.Printf("✓ Generated S3 credential secret: %s", credSecret.Metadata.Name)
			}
		}
	}

	// Use LLM to generate a human-readable summary
	log.Println("🤖 Generating AI-powered database summary...")
	// Increased timeout to 3 minutes for large models like llama3:70b
	summaryCtx, summaryCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer summaryCancel()

	// Build database info map for LLM
	dbInfoMap := map[string]interface{}{
		"databaseName":  dbInfo.DatabaseName,
		"version":       dbInfo.Version,
		"isEon":         dbInfo.IsEon,
		"shardCount":    dbInfo.ShardCount,
		"subclusters":   subclusters,
		"communalPath":  dbInfo.CommunalPath,
		"dataPath":      dbInfo.DataPath,
		"depotPath":     dbInfo.DepotPath,
		"catalogPath":   dbInfo.CatalogPath,
		"depotSizeMB":   dbInfo.DepotSizeMB,
		"catalogSizeMB": dbInfo.CatalogSizeMB,
		"requestSizeMB": dbInfo.RequestSizeMB,
	}

	summary, err := llmClient.SummarizeDatabase(summaryCtx, dbInfoMap)
	if err != nil {
		log.Printf("⚠️  LLM summary generation failed: %v", err)
		// Continue without summary
	} else {
		response += "\n\n=== AI-Powered Database Summary ===\n" + summary
	}

	return mcp.NewToolResultText(response), nil
}

func handleValidation(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	log.Println("✅ Handling validation request...")

	yamlContent := getStringParam(req, "yaml")
	version := getStringParam(req, "version")

	if yamlContent == "" || version == "" {
		return mcp.NewToolResultError("yaml and version parameters are required"), nil
	}

	// Parse YAML
	var vdb models.VerticaDB
	if err := yaml.Unmarshal([]byte(yamlContent), &vdb); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid YAML: %v", err)), nil
	}

	// Validate
	validateCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := validator.ValidateYAML(validateCtx, &vdb, version)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Validation error: %v", err)), nil
	}

	response := validation.FormatResult(result)

	// If there are validation errors, use LLM to explain them
	if !result.Valid && len(result.Errors) > 0 {
		log.Println("🤖 Using LLM to explain validation errors...")
		// Increased timeout to 3 minutes for large models like llama3:70b
		llmCtx, llmCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer llmCancel()

		explanation, err := llmClient.ExplainValidationErrors(llmCtx, yamlContent, result.Errors, version)
		if err != nil {
			log.Printf("⚠️  LLM explanation failed: %v", err)
			// Continue without LLM explanation
		} else {
			response += "\n\n=== AI-Powered Error Explanation ===\n" + explanation
		}
	}

	return mcp.NewToolResultText(response), nil
}

// REMOVED: handleLoadCRD - Internal operation, not user-facing
// REMOVED: handleGetResult - Async pattern unused by Claude Desktop  
// REMOVED: processYAMLGenerationAsync - All processing is synchronous

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func getStringParam(req mcp.CallToolRequest, key string) string {
	if req.Params.Arguments == nil {
		return ""
	}
	// Handle Arguments as interface{} (can be map[string]interface{} or map[string]any)
	if argsMap, ok := req.Params.Arguments.(map[string]interface{}); ok {
		if val, exists := argsMap[key]; exists {
			if strVal, ok := val.(string); ok {
				return strVal
			}
		}
	}
	return ""
}

// parseNodeCount extracts node count from instruction (default: 3)
func parseNodeCount(instruction string) int {
	// Look for patterns like "3-node", "3 node", "5 nodes"
	patterns := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "12", "16", "24", "32"}
	for _, p := range patterns {
		if strings.Contains(instruction, p+"-node") ||
			strings.Contains(instruction, p+" node") ||
			strings.Contains(instruction, p+" nodes") {
			switch p {
			case "1":
				return 1
			case "2":
				return 2
			case "3":
				return 3
			case "4":
				return 4
			case "5":
				return 5
			case "6":
				return 6
			case "7":
				return 7
			case "8":
				return 8
			case "9":
				return 9
			case "10":
				return 10
			case "12":
				return 12
			case "16":
				return 16
			case "24":
				return 24
			case "32":
				return 32
			}
		}
	}
	return 3 // default
}

// parseStorageType determines storage type from instruction
func parseStorageType(instruction string) string {
	if strings.Contains(instruction, "s3") || strings.Contains(instruction, "aws") {
		return "s3"
	}
	if strings.Contains(instruction, "gcs") || strings.Contains(instruction, "google") {
		return "gcs"
	}
	if strings.Contains(instruction, "azure") || strings.Contains(instruction, "blob") {
		return "azure"
	}
	if strings.Contains(instruction, "hdfs") || strings.Contains(instruction, "hadoop") {
		return "hdfs"
	}
	if strings.Contains(instruction, "minio") {
		return "minio"
	}
	return "s3" // default for EON mode
}

// buildCommunalConfig creates communal storage config based on parsed configuration
// Based on official Vertica CRD documentation
func buildCommunalConfig(config *llm.ParsedConfig) *models.Communal {
	communal := &models.Communal{
		IncludeUIDInPath: true, // Recommended: adds UID to path for uniqueness
		CaFile:           config.CaFile,
	}

	// S3 Server Side Encryption
	if config.S3ServerSideEncryption != "" {
		communal.S3ServerSideEncryption = config.S3ServerSideEncryption
	}

	// Use LLM-parsed values or defaults
	switch config.StorageType {
	case "s3":
		communal.Path = config.CommunalPath
		if communal.Path == "" {
			communal.Path = "s3://YOUR_BUCKET/YOUR_DATABASE_PATH"
		}
		communal.Endpoint = config.Endpoint
		if communal.Endpoint == "" {
			communal.Endpoint = "https://s3.amazonaws.com"
		}
		communal.CredentialSecret = config.CredentialSecret
		if communal.CredentialSecret == "" {
			communal.CredentialSecret = "s3-credentials"
		}
		communal.Region = config.Region
		if communal.Region == "" {
			communal.Region = "us-east-1"
		}

	case "gcs":
		communal.Path = config.CommunalPath
		if communal.Path == "" {
			communal.Path = "gs://YOUR_BUCKET/YOUR_DATABASE_PATH"
		}
		communal.Endpoint = config.Endpoint
		if communal.Endpoint == "" {
			communal.Endpoint = "https://storage.googleapis.com"
		}
		communal.CredentialSecret = config.CredentialSecret
		if communal.CredentialSecret == "" {
			communal.CredentialSecret = "gcs-credentials"
		}

	case "azure":
		communal.Path = config.CommunalPath
		if communal.Path == "" {
			communal.Path = "azb://YOUR_CONTAINER/YOUR_DATABASE_PATH"
		}
		communal.Endpoint = config.Endpoint
		if communal.Endpoint == "" {
			communal.Endpoint = "https://YOUR_ACCOUNT.blob.core.windows.net"
		}
		communal.CredentialSecret = config.CredentialSecret
		if communal.CredentialSecret == "" {
			communal.CredentialSecret = "azure-credentials"
		}

	case "hdfs":
		communal.Path = config.CommunalPath
		if communal.Path == "" {
			communal.Path = "webhdfs://YOUR_NAMENODE:9870/YOUR_DATABASE_PATH"
		}
		communal.Endpoint = config.Endpoint

	case "minio":
		communal.Path = config.CommunalPath
		if communal.Path == "" {
			communal.Path = "s3://YOUR_BUCKET/YOUR_DATABASE_PATH"
		}
		communal.Endpoint = config.Endpoint
		if communal.Endpoint == "" {
			communal.Endpoint = "http://minio.minio.svc.cluster.local:9000"
		}
		communal.CredentialSecret = config.CredentialSecret
		if communal.CredentialSecret == "" {
			communal.CredentialSecret = "minio-credentials"
		}
		communal.Region = config.Region
		if communal.Region == "" {
			communal.Region = "us-east-1"
		}

	default:
		// Default to S3
		communal.Path = config.CommunalPath
		if communal.Path == "" {
			communal.Path = "s3://YOUR_BUCKET/YOUR_DATABASE_PATH"
		}
		communal.Endpoint = config.Endpoint
		if communal.Endpoint == "" {
			communal.Endpoint = "https://s3.amazonaws.com"
		}
		communal.CredentialSecret = config.CredentialSecret
		if communal.CredentialSecret == "" {
			communal.CredentialSecret = "s3-credentials"
		}
		communal.Region = config.Region
		if communal.Region == "" {
			communal.Region = "us-east-1"
		}
	}

	return communal
}
