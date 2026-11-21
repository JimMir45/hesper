package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/JimMir45/hesper/internal/planner"
)

// ModelPlanner adapts the model client to the Planner interface: compose the
// prompt from the StateView, call the model, parse a JSON proposal batch.
type ModelPlanner struct {
	c              *Client
	maxProposals   int
}

// NewModelPlanner builds a model-backed planner. maxProposals mirrors
// run.config.planner.max_proposals_per_turn (0 → unlimited parse, engine
// still trims).
func NewModelPlanner(c *Client, maxProposals int) *ModelPlanner {
	return &ModelPlanner{c: c, maxProposals: maxProposals}
}

func (m *ModelPlanner) Next(ctx context.Context, s planner.StateView) ([]planner.Proposal, error) {
	system, user := planner.Compose(s)
	content, err := m.c.Complete(ctx, system, user)
	if err != nil {
		return nil, err
	}
	ps, err := ParseProposals(content)
	if err != nil {
		return nil, fmt.Errorf("planner: model output unparseable: %w", err)
	}
	if m.maxProposals > 0 && len(ps) > m.maxProposals {
		ps = ps[:m.maxProposals]
	}
	return ps, nil
}

// ParseProposals extracts a proposal array from model text. Models wrap JSON
// in prose or markdown fences despite instructions; the parser tolerates
// that but refuses anything without a JSON array.
func ParseProposals(content string) ([]planner.Proposal, error) {
	text := strings.TrimSpace(content)
	// Fast path: the whole reply is the array.
	if strings.HasPrefix(text, "[") {
		var ps []planner.Proposal
		if err := json.Unmarshal([]byte(text), &ps); err == nil {
			return ps, nil
		}
	}
	// {"proposals": [...]} object form.
	if strings.HasPrefix(text, "{") {
		var wrap struct {
			Proposals []planner.Proposal `json:"proposals"`
		}
		if err := json.Unmarshal([]byte(text), &wrap); err == nil && wrap.Proposals != nil {
			return wrap.Proposals, nil
		}
	}
	// Fenced or embedded: take the outermost [ ... ] span.
	start := strings.Index(text, "[")
	end := strings.LastIndex(text, "]")
	if start >= 0 && end > start {
		var ps []planner.Proposal
		if err := json.Unmarshal([]byte(text[start:end+1]), &ps); err == nil {
			return ps, nil
		}
	}
	return nil, fmt.Errorf("no JSON proposal array found in %.120s", text)
}
