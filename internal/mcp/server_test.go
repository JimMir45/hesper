package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func echoTool() Tool {
	return Tool{
		Name:        "echo",
		Description: "echo the text argument",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"text": map[string]any{"type": "string"},
			},
			"required": []string{"text"},
		},
		Fn: func(_ context.Context, args json.RawMessage) (string, error) {
			var a struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(args, &a)
			return "echo: " + a.Text, nil
		},
	}
}

func failingTool() Tool {
	return Tool{
		Name:        "boom",
		Description: "always fails",
		Fn: func(_ context.Context, _ json.RawMessage) (string, error) {
			return "", &rpcErr{-32000, "deliberate failure"}
		},
	}
}

// roundTrip drives the server over an in-memory pipe — the same
// line-delimited JSON-RPC an MCP client would send over stdio.
func roundTrip(t *testing.T, lines []string) []string {
	t.Helper()
	srv := NewServer("hesper-test", "0.0.0", []Tool{echoTool(), failingTool()})
	var in bytes.Buffer
	for _, l := range lines {
		in.WriteString(l + "\n")
	}
	var out bytes.Buffer
	if err := srv.Serve(context.Background(), &in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []string
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l != "" {
			resps = append(resps, l)
		}
	}
	return resps
}

func TestInitializeHandshake(t *testing.T) {
	resps := roundTrip(t, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
	})
	if len(resps) != 1 {
		t.Fatalf("responses=%d", len(resps))
	}
	var r struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(resps[0]), &r); err != nil {
		t.Fatalf("parse: %v (%s)", err, resps[0])
	}
	if r.Result.ProtocolVersion != ProtocolVersion || r.Result.ServerInfo.Name != "hesper-test" {
		t.Fatalf("handshake: %+v", r.Result)
	}
}

func TestNotificationGetsNoResponse(t *testing.T) {
	resps := roundTrip(t, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	})
	if len(resps) != 1 {
		t.Fatalf("notification must not produce a response, got %d: %v", len(resps), resps)
	}
}

func TestToolsListAndCall(t *testing.T) {
	resps := roundTrip(t, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`,
	})
	if len(resps) != 2 {
		t.Fatalf("responses=%d", len(resps))
	}
	var list struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(resps[0]), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Result.Tools) != 2 {
		t.Fatalf("tools=%d", len(list.Result.Tools))
	}
	var call struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(resps[1]), &call); err != nil {
		t.Fatal(err)
	}
	if call.Result.IsError || len(call.Result.Content) != 1 || call.Result.Content[0].Text != "echo: hi" {
		t.Fatalf("call result: %+v", call.Result)
	}
}

func TestToolErrorIsObservationNotTransport(t *testing.T) {
	resps := roundTrip(t, []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"boom"}}`,
	})
	var r struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(resps[0]), &r); err != nil {
		t.Fatal(err)
	}
	if !r.Result.IsError {
		t.Fatal("expected isError=true")
	}
	if len(r.Result.Content) != 1 || r.Result.Content[0].Text == "" {
		t.Fatal("error text content missing")
	}
}

func TestUnknownMethodAndTool(t *testing.T) {
	resps := roundTrip(t, []string{
		`{"jsonrpc":"2.0","id":1,"method":"no/such"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nope"}}`,
	})
	for i, want := range []int{-32601, -32602} {
		var r struct {
			Error struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(resps[i]), &r); err != nil {
			t.Fatal(err)
		}
		if r.Error.Code != want {
			t.Fatalf("resp %d: code=%d want %d", i, r.Error.Code, want)
		}
	}
}
