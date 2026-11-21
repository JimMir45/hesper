package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JimMir45/hesper/internal/planner"
)

func repeatTurns(cardID string, n int) [][]planner.Proposal {
	turns := make([][]planner.Proposal, 0, n)
	for i := 0; i < n; i++ {
		turns = append(turns, []planner.Proposal{prop(cardID, "u")})
	}
	return turns
}

// TestKillBySignalDuringAction: SIGINT (ctx cancel) mid-action drains the
// in-flight action, stops accepting proposals, terminal STOPPED, exit 130.
func TestKillBySignalDuringAction(t *testing.T) {
	e := newEnv(t, 20, "ok1")
	e.fake.delay = 250 * time.Millisecond
	e.opts.Planner = &planner.Stub{Turns: repeatTurns("ok1", 20)}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(60*time.Millisecond, cancel)
	res, err := Run(ctx, e.opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Terminal != TerminalStopped || res.ExitCode != ExitKill {
		t.Fatalf("terminal=%s exit=%d, want STOPPED/130", res.Terminal, res.ExitCode)
	}
	if e.finalState() != TerminalStopped {
		t.Fatalf("persisted state=%s", e.finalState())
	}
	// Drain proof: the in-flight action RETURNED (adapter completed), the
	// engine did not abandon the goroutine.
	if e.fake.completes < 1 {
		t.Fatal("in-flight action did not drain (adapter never returned)")
	}
	if !containsAudit(e, "kill.requested") {
		t.Fatal("audit missing kill.requested")
	}
}

// TestKillForcedAbort: the second signal (ForceAbort closed) escalates to
// ABORTED, still exit 130.
func TestKillForcedAbort(t *testing.T) {
	e := newEnv(t, 20, "ok1")
	e.fake.delay = 250 * time.Millisecond
	e.opts.Planner = &planner.Stub{Turns: repeatTurns("ok1", 20)}

	ctx, cancel := context.WithCancel(context.Background())
	abort := make(chan struct{})
	time.AfterFunc(60*time.Millisecond, func() { cancel(); close(abort) })
	e.opts.ForceAbort = abort

	res, err := Run(ctx, e.opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Terminal != TerminalAborted || res.ExitCode != ExitKill {
		t.Fatalf("terminal=%s exit=%d, want ABORTED/130", res.Terminal, res.ExitCode)
	}
}

// TestStopFile: `hesper stop --run` writes state/STOP; the engine stops
// before ever calling the planner.
func TestStopFile(t *testing.T) {
	e := newEnv(t, 20, "ok1")
	if err := os.MkdirAll(filepath.Join(e.runDir, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.runDir, "state", "STOP"), []byte("stop"), 0o644); err != nil {
		t.Fatal(err)
	}
	stub := &planner.Stub{Turns: repeatTurns("ok1", 5)}
	e.opts.Planner = stub

	res, err := Run(context.Background(), e.opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Terminal != TerminalStopped || res.ExitCode != ExitKill {
		t.Fatalf("terminal=%s exit=%d", res.Terminal, res.ExitCode)
	}
	if stub.Calls() != 0 {
		t.Fatalf("planner called %d times after STOP file, want 0", stub.Calls())
	}
}

// TestResumeAfterStop: a killed run resumes under the ORIGINAL budget and
// deadline, continues the chain, and finishes DONE with verifiable evidence
// across both segments.
func TestResumeAfterStop(t *testing.T) {
	e := newEnv(t, 10, "ok1")
	e.fake.delay = 200 * time.Millisecond
	e.opts.Planner = &planner.Stub{Turns: repeatTurns("ok1", 20)}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	res1, err := Run(ctx, e.opts)
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if res1.Terminal != TerminalStopped {
		t.Fatalf("run 1 terminal=%s", res1.Terminal)
	}

	// Read persisted accounting; resume with the ORIGINAL limits.
	b, err := os.ReadFile(filepath.Join(e.runDir, "state", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		BudgetUsed int    `json:"budget_used"`
		Deadline   string `json:"budget_deadline"`
		Turn       int    `json:"turn"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	deadline, _ := time.Parse(time.RFC3339, st.Deadline)

	// Fresh bindings on the SAME run directory (append-mode audit, resuming
	// chain), budget restored — never minted.
	audit2, err := openAppend(e.runDir)
	if err != nil {
		t.Fatal(err)
	}
	defer audit2.Close()
	chain2, err := openChain(e.runDir)
	if err != nil {
		t.Fatal(err)
	}
	e.opts.Audit = audit2
	e.opts.Chain = chain2
	e.opts.Budget = restoreBudget(e.opts.Scope.Budget, st.BudgetUsed, deadline)
	// Turn numbering continues (run 1 processed turn 1): enough turns remain.
	e.opts.Planner = &planner.Stub{Turns: repeatTurns("ok1", 5)}

	res2, err := Run(context.Background(), e.opts)
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if res2.Terminal != TerminalDone || res2.ExitCode != 0 {
		t.Fatalf("run 2 terminal=%s exit=%d", res2.Terminal, res2.ExitCode)
	}
	if err := verifyChain(e.runDir); err != nil {
		t.Fatalf("cross-segment evidence verify: %v", err)
	}
	if len(res2.Findings) < 1 {
		t.Fatalf("resumed run produced no findings: %+v", res2.Findings)
	}
	// Budget accounting continued (run 1 spent ≥1, run 2 spent ≥1).
	if used, _ := e.opts.Budget.Dump(); used < 2 {
		t.Fatalf("budget used=%d after resume, want ≥2", used)
	}
}
