// Package mcp implements a minimal MCP server (stdio transport, JSON-RPC
// 2.0, protocol 2024-11-05) exposing Hesper's run/lab/report surface to
// coding agents (design §11: MCP is one of the shells above the headless
// core; the engine itself never changes for it).
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ProtocolVersion is the MCP protocol this server speaks.
const ProtocolVersion = "2024-11-05"

// ToolFunc executes one tool call; the returned string becomes the tool
// result's text content. Returning an error marks the result isError=true
// (an observation for the calling agent, not a transport failure).
type ToolFunc func(ctx context.Context, args json.RawMessage) (string, error)

// Tool is one MCP tool.
type Tool struct {
	Name        string
	Description string
	// InputSchema is a JSON-Schema object describing the arguments.
	InputSchema map[string]any
	Fn          ToolFunc
}

// Server dispatches MCP JSON-RPC over any reader/writer pair.
type Server struct {
	Name    string
	Version string
	tools   map[string]Tool
}

func NewServer(name, version string, tools []Tool) *Server {
	s := &Server{Name: name, Version: version, tools: map[string]Tool{}}
	for _, t := range tools {
		s.tools[t.Name] = t
	}
	return s
}

// Serve reads line-delimited JSON-RPC requests from r and writes responses
// to w until EOF. It returns on read error/EOF or writer failure.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(w)
	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			if err := enc.Encode(rpcError(nil, -32700, "parse error")); err != nil {
				return err
			}
			continue
		}
		// Notifications (no id) never get a response.
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue
		}
		result, err := s.dispatch(ctx, req.Method, req.Params)
		var resp any
		if err != nil {
			resp = rpcError(req.ID, err.code, err.message)
		} else {
			resp = map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(req.ID), "result": result}
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

type rpcErr struct {
	code    int
	message string
}

func (e *rpcErr) Error() string { return fmt.Sprintf("mcp: %d %s", e.code, e.message) }

func rpcError(id json.RawMessage, code int, msg string) any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": msg},
	}
}

func (s *Server) dispatch(ctx context.Context, method string, params json.RawMessage) (any, *rpcErr) {
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		tools := make([]map[string]any, 0, len(s.tools))
		for _, t := range s.tools {
			schema := t.InputSchema
			if schema == nil {
				schema = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			tools = append(tools, map[string]any{
				"name": t.Name, "description": t.Description, "inputSchema": schema,
			})
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &rpcErr{-32602, "invalid params: " + err.Error()}
		}
		tool, ok := s.tools[p.Name]
		if !ok {
			return nil, &rpcErr{-32602, fmt.Sprintf("unknown tool %q", p.Name)}
		}
		out, err := tool.Fn(ctx, p.Arguments)
		isErr := false
		if err != nil {
			out = err.Error()
			isErr = true
		}
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": out}},
			"isError": isErr,
		}, nil
	default:
		return nil, &rpcErr{-32601, "method not found: " + method}
	}
}
