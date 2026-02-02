package llm

import (
	"context"
)

// LLMClient is the unified interface for all LLM providers
type LLMClient interface {
	Generate(ctx context.Context, prompt string) (string, error)
	ParseInstruction(ctx context.Context, instruction, version string) (*ParsedConfig, error)
	ParseUpdateIntent(ctx context.Context, instruction, version string) (*UpdateIntent, error)
	SummarizeDatabase(ctx context.Context, dbInfo map[string]interface{}) (string, error)
	ExplainValidationErrors(ctx context.Context, yamlContent string, errors []string, version string) (string, error)
}

// Ensure both clients implement the interface
var _ LLMClient = (*OllamaClient)(nil)
var _ LLMClient = (*GeminiClient)(nil)
