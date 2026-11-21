package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/JimMir45/hesper/internal/config"
)

// No test in this file uses a real key: the key travels via an environment
// variable NAME (HESPER_TEST_KEY) whose value is a dummy.

func testModel(provider, endpoint string, fallback ...string) config.Model {
	return config.Model{
		Provider:  provider,
		Endpoint:  endpoint,
		Model:     "m1",
		APIKeyEnv: "HESPER_TEST_KEY",
		Fallback:  fallback,
	}
}

func TestOpenAICompatibleShapeAndParse(t *testing.T) {
	t.Setenv("HESPER_TEST_KEY", "test-key-123")
	var gotPath, gotAuth string
	var gotBody struct {
		Model       string  `json:"model"`
		Temperature float64 `json:"temperature"`
		Messages    []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"[{\"card_id\":\"x\"}]"}}]}`))
	}))
	defer srv.Close()

	c := New(testModel("openai_compatible", srv.URL+"/v1"), 0, 1024)
	out, err := c.Complete(context.Background(), "sys", "usr")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out != `[{"card_id":"x"}]` {
		t.Fatalf("content = %q", out)
	}
	if gotPath != "/v1/chat/completions" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer test-key-123" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotBody.Model != "m1" || gotBody.Temperature != 0 {
		t.Fatalf("body = %+v", gotBody)
	}
	if len(gotBody.Messages) != 2 || gotBody.Messages[0].Role != "system" || gotBody.Messages[1].Content != "usr" {
		t.Fatalf("messages = %+v", gotBody.Messages)
	}
}

func TestFallbackChain(t *testing.T) {
	t.Setenv("HESPER_TEST_KEY", "k")
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		var b struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.Model == "m1" {
			http.Error(w, "upstream exploded", http.StatusBadGateway)
			return
		}
		fmt.Fprintf(w, `{"choices":[{"message":{"content":"ok-from-%s-call-%d"}}]}`, b.Model, n)
	}))
	defer srv.Close()

	c := New(testModel("openai_compatible", srv.URL+"/v1", "m2"), 0, 64)
	out, err := c.Complete(context.Background(), "sys", "usr")
	if err != nil {
		t.Fatalf("Complete with fallback: %v", err)
	}
	if out != "ok-from-m2-call-2" {
		t.Fatalf("out = %q", out)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestAllModelsFail(t *testing.T) {
	t.Setenv("HESPER_TEST_KEY", "k")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New(testModel("openai_compatible", srv.URL+"/v1", "m2", "m3"), 0, 64)
	if _, err := c.Complete(context.Background(), "sys", "usr"); err == nil {
		t.Fatal("expected error when every model fails")
	}
}

func TestAnthropicShapeAndParse(t *testing.T) {
	t.Setenv("HESPER_TEST_KEY", "anth-key")
	var gotPath, gotKey, gotVersion string
	var gotBody struct {
		Model    string `json:"model"`
		System   string `json:"system"`
		Messages []struct{ Role, Content string } `json:"messages"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"part1"},{"type":"text","text":"part2"}]}`))
	}))
	defer srv.Close()

	c := New(testModel("anthropic", srv.URL), 0, 64)
	out, err := c.Complete(context.Background(), "sys", "usr")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out != "part1part2" {
		t.Fatalf("content = %q", out)
	}
	if gotPath != "/v1/messages" || gotKey != "anth-key" || gotVersion != "2023-06-01" {
		t.Fatalf("path=%q key=%q version=%q", gotPath, gotKey, gotVersion)
	}
	if gotBody.System != "sys" || len(gotBody.Messages) != 1 || gotBody.Messages[0].Role != "user" {
		t.Fatalf("body = %+v", gotBody)
	}
}

func TestKeyEnvMissingFailsClosedWithoutHTTP(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	// HESPER_TEST_KEY deliberately NOT set in this test.
	c := New(testModel("openai_compatible", srv.URL+"/v1"), 0, 64)
	if _, err := c.Complete(context.Background(), "sys", "usr"); err == nil {
		t.Fatal("missing key env must fail")
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("no HTTP call may happen without a key, got %d hits", hits)
	}
}
