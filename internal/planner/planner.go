// Package planner defines the planner contract (design §5.6): the model (or
// a deterministic stub) proposes actions; the engine resolves, gates, and
// executes. The planner never executes anything — its output is advisory
// until the kernel permits, and unknown cards / invalid params are rejected
// as observations, never crashes (hallucination containment).
package planner

import (
	"context"
)

// Proposal is one proposed action (design §5.6). Params are string-keyed to
// match the card argv template contract ({params.NAME}); the required set is
// derived from the card's argv — a proposal missing a required param is
// schema-invalid and rejected.
type Proposal struct {
	CardID    string            `json:"card_id"`
	Class     string            `json:"class,omitempty"`
	Params    map[string]string `json:"params,omitempty"`
	Target    string            `json:"target"`
	Assertion string            `json:"assertion,omitempty"`
	Repro     []string          `json:"repro,omitempty"`
	Rationale string            `json:"rationale,omitempty"`
}

// FeedbackKind classifies what happened to a proposal last turn.
const (
	FeedbackRejected = "rejected" // unknown card, invalid params, quarantined
	FeedbackDenied   = "denied"   // kernel gate refusal (scope)
	FeedbackBudget   = "budget"   // action/time budget exhausted
	FeedbackExecuted = "executed" // action ran (success or failure recorded)
	FeedbackFailed   = "failed"   // adapter error / unavailable
)

// Feedback is one structured observation returned to the planner (design
// §3: a denied or budget-failed step is feedback, not a crash).
type Feedback struct {
	CardID string `json:"card_id"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// BudgetView exposes run accounting to the planner (no secrets, no raw
// manifest — a digest only, design §5.6 prompt composition).
type BudgetView struct {
	MaxActions int `json:"max_actions"`
	UsedActions int `json:"used_actions"`
}

// CardDigest is the registry digest a planner sees: id, mapping,
// preconditions — never card internals like argv.
type CardDigest struct {
	ID          string `json:"id"`
	TechniqueID string `json:"technique_id"`
	Tactic      string `json:"tactic,omitempty"`
	Phase       string `json:"phase,omitempty"`
	Adapter     string `json:"adapter"`
	Title       string `json:"title"`
	Notes       string `json:"notes,omitempty"`
}

// StateView is everything the planner may observe on one turn (design §5.6):
// scope digest, registry digest, bounded evidence tail, last round's
// feedback. It deliberately excludes the raw scope manifest.
type StateView struct {
	RunID        string        `json:"run_id"`
	State        string        `json:"state"`
	Mode         string        `json:"mode"`
	Turn         int           `json:"turn"`
	Targets      []string      `json:"targets"`
	Classes      []string      `json:"classes,omitempty"`
	Adapters     []string      `json:"adapters"`
	Budget       BudgetView    `json:"budget"`
	Cards        []CardDigest  `json:"cards"`
	Feedback     []Feedback    `json:"feedback,omitempty"`
	FindingsSoFar int          `json:"findings_so_far"`
	EvidenceTail []string      `json:"evidence_tail,omitempty"`
}

// Planner proposes the next batch of actions. Returning an empty slice (nil
// included) means convergence: the planner has nothing more to propose and
// the run finishes gracefully (design §6).
type Planner interface {
	Next(ctx context.Context, s StateView) ([]Proposal, error)
}
