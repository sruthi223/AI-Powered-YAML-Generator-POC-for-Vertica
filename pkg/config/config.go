package config

import (
	"os"
	"time"
)

const (
	// DefaultVersion is the default Vertica version
	DefaultVersion = "25.4"

	// CRDBaseURL is the base URL for Vertica CRD downloads
	// Default is "local" since CRDs are bundled in the schemas/ directory
	// Set to GitHub URL if you want to fetch latest versions online
	CRDBaseURL = "local"

	// LocalCRDPath is the local directory path for offline CRD schemas
	LocalCRDPath = "./schemas"

	// DefaultHTTPTimeout is the default timeout for HTTP requests to Ollama
	// Set to 30 minutes to accommodate large models like llama3:70b with model loading time
	// Adjust with OLLAMA_TIMEOUT env var if needed (e.g., OLLAMA_TIMEOUT=45m for very large models)
	DefaultHTTPTimeout = 30 * time.Minute

	// DefaultDBTimeout is the default timeout for database operations
	DefaultDBTimeout = 60 * time.Second

	// DefaultHTTPPort is the default HTTP server port
	// Using 9090 to avoid conflict with Vertica ports (5433, 5434, 5444, 8443)
	DefaultHTTPPort = "9090"
)

// Config holds application configuration
type Config struct {
	OllamaURL      string
	OllamaModel    string
	GeminiAPIKey   string // Google Gemini API key
	GeminiModel    string // Gemini model name
	LLMProvider    string // "ollama" or "gemini"
	DefaultVersion string
	HTTPTimeout    time.Duration
	DBTimeout      time.Duration
	HTTPPort       string
	CRDBaseURL     string // CRD download URL or "local" for offline mode
	CRDLocalPath   string // Local path for CRD schemas when in offline mode
}

// Load loads configuration from environment variables with defaults
func Load() *Config {
	// Parse Ollama timeout with default of 30 minutes (600s)
	ollamaTimeout := DefaultHTTPTimeout
	if timeoutStr := os.Getenv("OLLAMA_TIMEOUT"); timeoutStr != "" {
		if duration, err := time.ParseDuration(timeoutStr); err == nil {
			ollamaTimeout = duration
		}
	}

	// Determine LLM provider
	llmProvider := getEnv("LLM_PROVIDER", "ollama") // Default to ollama
	geminiKey := os.Getenv("GEMINI_API_KEY")
	if geminiKey != "" && llmProvider == "ollama" {
		llmProvider = "gemini" // Auto-switch to Gemini if API key provided
	}

	return &Config{
		OllamaURL:      getEnv("OLLAMA_URL", "http://localhost:11434"),
		OllamaModel:    getEnv("OLLAMA_MODEL", "llama3:70b"),
		GeminiAPIKey:   geminiKey,
		GeminiModel:    getEnv("GEMINI_MODEL", "gemini-2.0-flash-exp"),
		LLMProvider:    llmProvider,
		DefaultVersion: getEnv("DEFAULT_VERSION", DefaultVersion),
		HTTPTimeout:    ollamaTimeout,
		DBTimeout:      DefaultDBTimeout,
		HTTPPort:       getEnv("HTTP_PORT", DefaultHTTPPort),
		CRDBaseURL:     getEnv("CRD_BASE_URL", CRDBaseURL),
		CRDLocalPath:   getEnv("CRD_LOCAL_PATH", LocalCRDPath),
	}
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
