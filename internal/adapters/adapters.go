// Package adapters defines the unified Adapter interface (design §5.3):
// one Execute method plus an evidence emitter — collect is part of execute,
// driven by the card's evidence.must_capture kinds, never a separate phase.
//
// Contract, enforced by construction: adapters accept kernel-validated
// target references only (never raw hosts from planner output), and
// planner-supplied values never pass through a shell.
package adapters

import (
	"context"

	"github.com/JimMir45/hesper/internal/actions"
	"github.com/JimMir45/hesper/internal/evidence"
	"github.com/JimMir45/hesper/internal/kernel"
)

// ExecRequest is one authorized action execution.
type ExecRequest struct {
	RunID    string
	ActionID string
	Card     actions.Card
	// Params are the planner/driver-supplied parameters, already validated
	// against the card's params_schema when one is defined.
	Params map[string]string
	// Target is the kernel-validated reference (design §5.3).
	Target kernel.Target
	// WorkDir is the action's artifact directory:
	// <run-dir>/evidence/<action_id>/
	WorkDir string
}

// ExecResult is the adapter's verdict for one action.
type ExecResult struct {
	Success bool
	Detail  string
	// NotHappened marks actions whose evidence.must_capture kinds were not
	// fully captured: by design §4.4 the action "did not happen" and no
	// finding may reference it.
	NotHappened bool
	ExitCode    int
	// EgressViolations lists destinations the runtime guard refused during
	// THIS action (design §5.3/§7). Non-empty ⇒ the action failed.
	EgressViolations []string
	// EnforcedEgress reports which egress enforcement level actually applied
	// (egress.LevelProxy | LevelDeclared | LevelNone) — the engine audits it
	// so claims always match enforcement reality.
	EnforcedEgress string
}

// EmitFunc persists one evidence record (the driver binds it to the chain).
// Implementations may rewrite artifact paths relative to the run directory.
type EmitFunc func(r evidence.Record) error

// Adapter executes one action of its kind.
type Adapter interface {
	Kind() string
	Execute(ctx context.Context, req ExecRequest, emit EmitFunc) (ExecResult, error)
}
