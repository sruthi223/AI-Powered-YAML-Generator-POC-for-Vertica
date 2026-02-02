package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GeminiClient handles communication with Google Gemini API
type GeminiClient struct {
	apiKey     string
	model      string
	httpClient *http.Client
	baseURL    string
}

// NewGeminiClient creates a new Gemini API client
func NewGeminiClient(apiKey, model string, httpClient *http.Client) *GeminiClient {
	if model == "" {
		model = "gemini-2.0-flash-exp" // Fast, free tier, great for JSON
	}
	return &GeminiClient{
		apiKey:     apiKey,
		model:      model,
		httpClient: httpClient,
		baseURL:    "https://generativelanguage.googleapis.com/v1beta/models",
	}
}

// Generate sends a prompt to Gemini and returns the response
func (c *GeminiClient) Generate(ctx context.Context, prompt string) (string, error) {
	url := fmt.Sprintf("%s/%s:generateContent?key=%s", c.baseURL, c.model, c.apiKey)

	requestBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
		"generationConfig": map[string]interface{}{
			"temperature":     0.1, // Low temperature for consistent JSON
			"topK":            1,
			"topP":            1,
			"maxOutputTokens": 8192,
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("gemini API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("gemini API error %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var response struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(response.Candidates) == 0 || len(response.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("no response from Gemini")
	}

	return response.Candidates[0].Content.Parts[0].Text, nil
}

// ParseInstruction uses Gemini to parse natural language instruction
func (c *GeminiClient) ParseInstruction(ctx context.Context, instruction, version string) (*ParsedConfig, error) {
	prompt := buildParsePrompt(instruction, version)
	response, err := c.Generate(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("Gemini generation failed: %w", err)
	}

	return parseConfigResponse(response)
}

// ParseUpdateIntent extracts update intent using Gemini
func (c *GeminiClient) ParseUpdateIntent(ctx context.Context, instruction, version string) (*UpdateIntent, error) {
	// Reuse Ollama's implementation logic
	prompt := fmt.Sprintf(`Extract update intent. JSON only.

Instruction: %s

Operations:
- add_subcluster: Add SECONDARY subcluster (type MUST be "secondary")
- remove_subcluster: Remove subcluster by name
- scale_subcluster: Change size
- update_resources: Change CPU/memory

CRITICAL: New subclusters are ALWAYS "secondary" type. Never "primary".

JSON:`, instruction)

	response, err := c.Generate(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("intent extraction failed: %w", err)
	}

	// Parse JSON response (similar to Ollama)
	response = strings.TrimSpace(response)
	if strings.HasPrefix(response, "```json") {
		response = strings.TrimPrefix(response, "```json")
		response = strings.TrimPrefix(response, "```")
	}
	if strings.HasSuffix(response, "```") {
		response = strings.TrimSuffix(response, "```")
	}
	response = strings.TrimSpace(response)

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

	// FORCE secondary type
	if intent.Operation == "add_subcluster" && intent.Subcluster != nil {
		intent.Subcluster.Type = "secondary"
		if intent.Subcluster.Name == "" {
			intent.Subcluster.Name = "secondary"
		}
		if intent.Subcluster.Size == 0 {
			intent.Subcluster.Size = 3
		}
	}

	return &intent, nil
}

// SummarizeDatabase uses Gemini to generate database summary
func (c *GeminiClient) SummarizeDatabase(ctx context.Context, dbInfo map[string]interface{}) (string, error) {
	prompt := buildSummaryPrompt(dbInfo)
	return c.Generate(ctx, prompt)
}

// ExplainValidationErrors uses Gemini to explain validation errors
func (c *GeminiClient) ExplainValidationErrors(ctx context.Context, yamlContent string, errors []string, version string) (string, error) {
	prompt := buildValidationPrompt(yamlContent, errors, version)
	return c.Generate(ctx, prompt)
}
