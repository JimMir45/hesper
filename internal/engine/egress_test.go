package engine

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/JimMir45/hesper/internal/adapters"
	"github.com/JimMir45/hesper/internal/egress"
	"github.com/JimMir45/hesper/internal/planner"
)

// violatingAdapter wraps the fake proc adapter and reports one egress
// violation for a chosen card — the runtime-guard outcome shape, without
// needing live curl in engine tests.
type violatingAdapter struct {
	*fakeAdapter
	mu           sync.Mutex
	violateCards map[string]bool
	level        string
}

func (v *violatingAdapter) Execute(ctx context.Context, req adapters.ExecRequest, emit adapters.EmitFunc) (adapters.ExecResult, error) {
	res, err := v.fakeAdapter.Execute(ctx, req, emit)
	if err != nil {
		return res, err
	}
	v.mu.Lock()
	violates := v.violateCards[req.Card.ID]
	v.mu.Unlock()
	if violates {
		res.EgressViolations = []string{"203.0.113.42:443"}
		res.Success = false
		res.Detail = "egress violation: refused [203.0.113.42:443] — destination outside scope; fake-ok"
	}
	res.EnforcedEgress = v.level
	return res, nil
}

func newEgressEnv(t *testing.T, maxActions int, level string, violate map[string]bool, cards ...string) *env {
	t.Helper()
	e := newEnv(t, maxActions, cards...)
	e.opts.Adapters["proc"] = &violatingAdapter{fakeAdapter: e.fake, violateCards: violate, level: level}
	return e
}

// TestEgressThreeStrikesStopsRunWithExit1: three violating actions ⇒ policy
// stop (design §6): terminal STOPPED, exit 1 (NOT the kill switch's 130),
// three kernel.egress_violation audit events, and the post-stop proposal
// never executes (stop accepting, drain done — actions are sequential).
func TestEgressThreeStrikesStopsRunWithExit1(t *testing.T) {
	e := newEgressEnv(t, 20, egress.LevelProxy, map[string]bool{"viol": true}, "viol", "ok1")
	viol := []planner.Proposal{prop("viol", "u"), prop("viol", "u"), prop("viol", "u")}
	e.opts.Planner = &planner.Stub{Turns: [][]planner.Proposal{viol, {prop("ok1", "u")}}}

	res, err := Run(context.Background(), e.opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Terminal != TerminalStopped {
		t.Fatalf("terminal=%s, want STOPPED", res.Terminal)
	}
	if res.ExitCode != ExitEgressPolicy {
		t.Fatalf("exit=%d, want 1 (egress policy stop, not kill 130)", res.ExitCode)
	}
	audit := e.auditText()
	if got := strings.Count(audit, "kernel.egress_violation"); got != 3 {
		t.Fatalf("kernel.egress_violation events=%d, want 3", got)
	}
	if !strings.Contains(audit, "\"level\":\""+egress.LevelProxy+"\"") {
		t.Fatal("audit missing egress.enforcement level proxy")
	}
	if got := e.fake.callsFor("ok1"); got != 0 {
		t.Fatalf("ok1 executed %d times after policy stop; must be 0", got)
	}
	if e.finalState() != TerminalStopped {
		t.Fatalf("state=%s", e.finalState())
	}
}

// TestEgressTwoStrikesKeepsRunning: below threshold the run continues —
// violations are audited, the actions fail, the run still reaches DONE.
func TestEgressTwoStrikesKeepsRunning(t *testing.T) {
	e := newEgressEnv(t, 20, egress.LevelProxy, map[string]bool{"viol": true}, "viol", "ok1")
	turns := [][]planner.Proposal{
		{prop("viol", "u"), prop("viol", "u")},
		{prop("ok1", "u")},
	}
	e.opts.Planner = &planner.Stub{Turns: turns}

	res, err := Run(context.Background(), e.opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Terminal != TerminalDone || res.ExitCode != 0 {
		t.Fatalf("terminal=%s exit=%d, want DONE/0", res.Terminal, res.ExitCode)
	}
	if got := strings.Count(e.auditText(), "kernel.egress_violation"); got != 2 {
		t.Fatalf("violation events=%d, want 2", got)
	}
	if got := e.fake.callsFor("ok1"); got != 1 {
		t.Fatalf("ok1 calls=%d, want 1 (run must continue below threshold)", got)
	}
}

// TestEgressDeclaredLevelAuditedForVM: the vm adapter's declared+audit level
// is audited as-is — claims always match enforcement reality (design §7).
func TestEgressDeclaredLevelAuditedForVM(t *testing.T) {
	e := newEgressEnv(t, 10, egress.LevelDeclared, map[string]bool{}, "ok1")
	e.opts.Planner = &planner.Stub{Turns: [][]planner.Proposal{{prop("ok1", "u")}}}

	res, err := Run(context.Background(), e.opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Terminal != TerminalDone {
		t.Fatalf("terminal=%s", res.Terminal)
	}
	if !strings.Contains(e.auditText(), "\"level\":\""+egress.LevelDeclared+"\"") {
		t.Fatal("audit missing declared+audit enforcement level")
	}
}

// TestEgressViolationsPersistInAuditShape: the audit line carries the refused
// destination and strike count — machine-consumable policy evidence.
func TestEgressViolationsPersistInAuditShape(t *testing.T) {
	e := newEgressEnv(t, 20, egress.LevelProxy, map[string]bool{"viol": true}, "viol")
	e.opts.Planner = &planner.Stub{Turns: [][]planner.Proposal{{prop("viol", "u")}}}

	_, err := Run(context.Background(), e.opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	audit := e.auditText()
	if !strings.Contains(audit, `"dest":"203.0.113.42:443"`) || !strings.Contains(audit, `"strikes":1`) {
		t.Fatalf("violation audit line missing dest/strikes: %s", audit)
	}
}
