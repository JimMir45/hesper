// Package client implements the model-agnostic planner client (design
// §4.5/§5.6): OpenAI-compatible and Anthropic endpoints, API keys by
// environment-variable NAME only (a key value in a file is a contract
// violation — config validation already refuses it), model fallback chain.
// No agent framework, no streaming: one request, one completion.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/JimMir45/hesper/internal/config"
)

const defaultAnthropicEndpoint = "https://api.anthropic.com"

// Client calls one configured model (plus its fallback chain).
type Client struct {
	m           config.Model
	temperature float64
	maxTokens   int
	hc          *http.Client
}

// New builds a client. temperature/maxTokens are planner settings, not
// model identity — they come from run.config.planner.
func New(m config.Model, temperature float64, maxTokens int) *Client {
	if maxTokens <= 0 {
		maxTokens = 4096
	}
	return &Client{
		m:           m,
		temperature: temperature,
		maxTokens:   maxTokens,
		hc:          &http.Client{Timeout: 120 * time.Second},
	}
}

// Complete sends the system+user pair and returns the model's text.
// The primary model is tried first, then every fallback, same provider.
func (c *Client) Complete(ctx context.Context, system, user string) (string, error) {
	key := os.Getenv(c.m.APIKeyEnv)
	if key == "" {
		return "", fmt.Errorf("planner: api key environment variable %s is not set (keys never live in files)", c.m.APIKeyEnv)
	}
	models := append([]string{c.m.Model}, c.m.Fallback...)
	var lastErr error
	for _, mdl := range models {
		if mdl == "" {
			continue
		}
		out, err := c.callOnce(ctx, mdl, key, system, user)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("planner: no model configured")
	}
	return "", fmt.Errorf("planner: all models failed: %w", lastErr)
}

func (c *Client) callOnce(ctx context.Context, model, key, system, user string) (string, error) {
	switch c.m.Provider {
	case "openai_compatible":
		return c.callOpenAI(ctx, model, key, system, user)
	case "anthropic":
		return c.callAnthropic(ctx, model, key, system, user)
	default:
		return "", fmt.Errorf("planner: unknown provider %q", c.m.Provider)
	}
}

func (c *Client) callOpenAI(ctx context.Context, model, key, system, user string) (string, error) {
	url := strings.TrimRight(c.m.Endpoint, "/") + "/chat/completions"
	body := map[string]any{
		"model":       model,
		"temperature": c.temperature,
		"max_tokens":  c.maxTokens,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := c.post(ctx, url, key, body, &out, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+key)
	}); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("planner: openai response has no choices (model %s)", model)
	}
	return out.Choices[0].Message.Content, nil
}

func (c *Client) callAnthropic(ctx context.Context, model, key, system, user string) (string, error) {
	endpoint := c.m.Endpoint
	if endpoint == "" {
		endpoint = defaultAnthropicEndpoint
	}
	url := strings.TrimRight(endpoint, "/") + "/v1/messages"
	body := map[string]any{
		"model":      model,
		"max_tokens": c.maxTokens,
		"system":     system,
		"messages": []map[string]string{
			{"role": "user", "content": user},
		},
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := c.post(ctx, url, key, body, &out, func(r *http.Request) {
		r.Header.Set("x-api-key", key)
		r.Header.Set("anthropic-version", "2023-06-01")
	}); err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, p := range out.Content {
		if p.Type == "text" {
			sb.WriteString(p.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("planner: anthropic response has no text (model %s)", model)
	}
	return sb.String(), nil
}

func (c *Client) post(ctx context.Context, url, key string, body any, out any, decorate func(*http.Request)) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("planner: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("planner: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if decorate != nil {
		decorate(req)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("planner: call %s: %w", url, err)
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("planner: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("planner: %s: HTTP %d: %.200s", url, resp.StatusCode, string(rb))
	}
	if err := json.Unmarshal(rb, out); err != nil {
		return fmt.Errorf("planner: decode response: %w", err)
	}
	return nil
}
