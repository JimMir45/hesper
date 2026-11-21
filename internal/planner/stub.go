package planner

import (
	"context"
)

// Stub is the deterministic planner: it replays a fixed per-turn proposal
// script and converges when the script is exhausted — or, with
// ConvergeOnAllRejected, as soon as a whole round produced nothing but
// rejections/denials (used to model a planner that gives up).
//
// It powers the engine loop tests and the M3 benchmark run
// (`--planner stub --stub-plan plans/…`), where unattended completion must
// not depend on a live model.
type Stub struct {
	Turns                [][]Proposal
	ConvergeOnAllRejected bool

	calls int
}

// Next returns the proposals of the current turn, indexed by view.Turn.
func (s *Stub) Next(_ context.Context, view StateView) ([]Proposal, error) {
	s.calls++
	if s.ConvergeOnAllRejected && len(view.Feedback) > 0 && allRejected(view.Feedback) {
		return nil, nil
	}
	i := view.Turn - 1
	if i < 0 || i >= len(s.Turns) {
		return nil, nil
	}
	return s.Turns[i], nil
}

// Calls reports how many times Next was invoked (test/benchmark evidence).
func (s *Stub) Calls() int { return s.calls }

func allRejected(fb []Feedback) bool {
	for _, f := range fb {
		if f.Kind == FeedbackExecuted || f.Kind == FeedbackFailed {
			return false
		}
	}
	return true
}
