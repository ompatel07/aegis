// Package ai is the opt-in AI layer. It is deliberately isolated: a single
// provider switch (disabled|mock|claude|openai) selects the backend, and the
// "openai" adapter covers OpenAI, Azure OpenAI, AWS Bedrock-compatible, and any
// self-hosted OpenAI-compatible endpoint via a base URL. Nothing else in the
// platform depends on which backend is chosen.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config selects and configures the backend.
type Config struct {
	Provider string // disabled | mock | claude | openai
	Model    string
	APIKey   string
	BaseURL  string // for openai-compatible / self-hosted
}

// Backend is a minimal chat-completion interface. Implementations send only the
// prompt they are given (the caller guarantees it is snippet-only).
type Backend interface {
	Provider() string
	Model() string
	Complete(ctx context.Context, system, user string) (string, error)
}

// New returns the configured backend, or nil when AI is disabled.
func New(cfg Config) Backend {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "mock":
		return &mockBackend{model: orDefault(cfg.Model, "aegis-mock-1")}
	case "claude", "anthropic":
		return &claudeBackend{apiKey: cfg.APIKey, model: orDefault(cfg.Model, "claude-sonnet-5")}
	case "openai", "azure", "self-hosted", "custom":
		base := orDefault(cfg.BaseURL, "https://api.openai.com/v1")
		return &openAIBackend{apiKey: cfg.APIKey, model: orDefault(cfg.Model, "gpt-4o-mini"), baseURL: strings.TrimRight(base, "/")}
	default:
		return nil
	}
}

var httpClient = &http.Client{Timeout: 60 * time.Second}

// ── Mock (no network, deterministic — the default for tests/dev) ───────────────
type mockBackend struct{ model string }

func (m *mockBackend) Provider() string { return "mock" }
func (m *mockBackend) Model() string    { return m.model }
func (m *mockBackend) Complete(_ context.Context, _, user string) (string, error) {
	return "```\n// Suggested fix (mock backend — no live model configured)\n" +
		"// Apply parameterization / validation / encoding appropriate to the finding.\n```\n\n" +
		"Explanation: This is a deterministic placeholder produced by the mock backend. " +
		"Configure AI_PROVIDER=claude|openai with a key to get real suggestions. " +
		"The prompt was snippet-only.", nil
}

// ── Anthropic Claude ─────────────────────────────────────────────────────────
type claudeBackend struct {
	apiKey, model string
}

func (c *claudeBackend) Provider() string { return "claude" }
func (c *claudeBackend) Model() string    { return c.model }
func (c *claudeBackend) Complete(ctx context.Context, system, user string) (string, error) {
	if c.apiKey == "" {
		return "", fmt.Errorf("claude backend: AI_API_KEY not set")
	}
	body, _ := json.Marshal(map[string]any{
		"model":      c.model,
		"max_tokens": 1024,
		"system":     system,
		"messages":   []map[string]string{{"role": "user", "content": user}},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	raw, err := doJSON(req)
	if err != nil {
		return "", err
	}
	var out struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if len(out.Content) == 0 {
		return "", fmt.Errorf("claude: empty response")
	}
	return out.Content[0].Text, nil
}

// ── OpenAI-compatible (OpenAI / Azure / self-hosted) ──────────────────────────
type openAIBackend struct {
	apiKey, model, baseURL string
}

func (o *openAIBackend) Provider() string { return "openai" }
func (o *openAIBackend) Model() string    { return o.model }
func (o *openAIBackend) Complete(ctx context.Context, system, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model": o.model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"max_tokens": 1024,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.apiKey)
	}
	raw, err := doJSON(req)
	if err != nil {
		return "", err
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("openai: empty response")
	}
	return out.Choices[0].Message.Content, nil
}

func doJSON(req *http.Request) ([]byte, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s returned %d: %s", req.URL.Host, resp.StatusCode, truncate(string(raw), 300))
	}
	return raw, nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
