package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JimMir45/hesper/internal/actions"
	"github.com/JimMir45/hesper/internal/adapters"
	"github.com/JimMir45/hesper/internal/config"
	"github.com/JimMir45/hesper/internal/evidence"
	"github.com/JimMir45/hesper/internal/findings"
	"github.com/JimMir45/hesper/internal/kernel"
	"github.com/JimMir45/hesper/internal/planner"
)

// ---- test doubles ----

// fakeAdapter is an injectable proc-kind adapter: it writes artifacts for
// every must_capture kind, can force-fail cards, and can delay (kill tests).
type fakeAdapter struct {
	mu        sync.Mutex
	calls     []string
	completes int
	failCards map[string]bool
	delay     time.Duration
}

func (f *fakeAdapter) Kind() string { return "proc" }

func (f *fakeAdapter) Execute(ctx context.Context, req adapters.ExecRequest, emit adapters.EmitFunc) (adapters.ExecResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req.Card.ID)
	f.mu.Unlock()

	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			f.mu.Lock()
			f.completes++
			f.mu.Unlock()
			return adapters.ExecResult{Success: false, Detail: "ctx cancelled"}, nil
		}
	}
	success := !f.failCards[req.Card.ID]
	var artifacts []evidence.Artifact
	if err := os.MkdirAll(req.WorkDir, 0o755); err != nil {
		return adapters.ExecResult{}, err
	}
	for _, kind := range req.Card.Evidence.MustCapture {
		p := filepath.Join(req.WorkDir, kind+".txt")
		if err := os.WriteFile(p, []byte(kind+"-content"), 0o644); err != nil {
			return adapters.ExecResult{}, err
		}
		sum, err := evidence.HashFile(p)
		if err != nil {
			return adapters.ExecResult{}, err
		}
		artifacts = append(artifacts, evidence.Artifact{Path: kind + ".txt", SHA256: sum, Kind: kind})
	}
	detail := "fake-ok"
	if !success {
		detail = "forced failure"
	}
	f.mu.Lock()
	f.completes++
	f.mu.Unlock()
	res := adapters.ExecResult{Success: success, Detail: detail}
	_ = emit(evidence.Record{
		RunID: req.RunID, ActionID: req.ActionID, Event: "action.executed",
		Artifacts: artifacts,
		Result:    &evidence.Result{Success: success, Detail: detail, ExitCode: 0},
	})
	return res, nil
}

func (f *fakeAdapter) callsFor(cardID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == cardID {
			n++
		}
	}
	return n
}

// ---- fixtures ----

func testScope(maxActions int) *kernel.ScopeManifest {
	return &kernel.ScopeManifest{
		Version: "0.1", Mode: kernel.ModeValidate, Name: "engine-test",
		Targets: []kernel.Target{
			{Kind: "cidr", Value: "172.20.0.0/16"},
			{Kind: "host", Value: "localhost"},
		},
		Allow:  kernel.Allow{Classes: []string{"web"}, Adapters: []string{"proc"}},
		Budget: kernel.Budget{MaxActions: maxActions, MaxMinutes: 30},
	}
}

func writeCard(t *testing.T, dir, id, technique string) {
	t.Helper()
	card := map[string]any{
		"version": "0.1", "id": id, "title": "test card " + id,
		"attack":   map[string]any{"technique_id": technique, "tactic": "initial-access"},
		"provenance": map[string]any{"source_repo": "https://example/repo", "commit": "deadbeef", "license": "MIT"},
		"reuse":    "embedded",
		"executor": map[string]any{"adapter": "proc", "argv": []string{"curl", "{params.url}"}},
		"evidence": map[string]any{"must_capture": []string{"stdout"}},
	}
	b, _ := json.Marshal(card)
	if err := os.WriteFile(filepath.Join(dir, id+".card.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

type env struct {
	t       *testing.T
	runDir  string
	opts    Options
	fake    *fakeAdapter
}

func newEnv(t *testing.T, maxActions int, cards ...string) *env {
	t.Helper()
	runDir := t.TempDir()
	for _, d := range []string{filepath.Join(runDir, "state"), filepath.Join(runDir, "evidence")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cardDir := t.TempDir()
	for i, id := range cards {
		writeCard(t, cardDir, id, fmt.Sprintf("T119%d", i))
	}
	registry, err := actions.LoadRegistry(cardDir)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := kernel.OpenAudit(filepath.Join(runDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	chain, err := evidence.OpenChain(runDir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeAdapter{failCards: map[string]bool{}}
	e := &env{t: t, runDir: runDir, fake: fake}
	e.opts = Options{
		RunDir: runDir, RunID: "test-run", Scope: testScope(maxActions),
		Cfg: config.DefaultRunConfig(), Registry: registry,
		Adapters: map[string]adapters.Adapter{"proc": fake},
		Audit:    audit, Chain: chain, Budget: kernel.NewBudgeter(testScope(maxActions).Budget),
	}
	return e
}

func (e *env) auditText() string {
	b, err := os.ReadFile(filepath.Join(e.runDir, "audit.jsonl"))
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func (e *env) finalState() string {
	b, err := os.ReadFile(filepath.Join(e.runDir, "state", "state.json"))
	if err != nil {
		e.t.Fatal(err)
	}
	var st struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		e.t.Fatal(err)
	}
	return st.State
}

// ---- small helpers reused by kill/resume tests ----

func containsAudit(e *env, needle string) bool {
	return strings.Contains(e.auditText(), needle)
}

func openAppend(runDir string) (*kernel.AuditLog, error) {
	return kernel.OpenAudit(filepath.Join(runDir, "audit.jsonl"))
}

func openChain(runDir string) (*evidence.Chain, error) {
	return evidence.OpenChain(runDir)
}

func restoreBudget(b kernel.Budget, used int, deadline time.Time) *kernel.Budgeter {
	return kernel.RestoreBudgeter(b, used, deadline, time.Now)
}

func verifyChain(runDir string) error {
	return evidence.Verify(runDir)
}

func prop(cardID, url string) planner.Proposal {
	return planner.Proposal{
		CardID: cardID, Class: "web", Target: "localhost",
		Params: map[string]string{"url": "http://127.0.0.1:5002/" + cardID},
		Assertion: "probe " + cardID,
	}
}

// ---- loop tests (M3-1/M3-4) ----

func TestLoopNormalCompletion(t *testing.T) {
	e := newEnv(t, 10, "ok1", "ok2")
	e.opts.Planner = &planner.Stub{Turns: [][]planner.Proposal{{prop("ok1", "u"), prop("ok2", "u")}}}

	res, err := Run(context.Background(), e.opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Terminal != TerminalDone || res.ExitCode != 0 {
		t.Fatalf("terminal=%s exit=%d", res.Terminal, res.ExitCode)
	}
	if res.Executed != 2 {
		t.Fatalf("executed=%d", res.Executed)
	}
	if len(res.Findings) != 2 || res.Findings[0].Status != findings.StatusProven {
		t.Fatalf("findings=%+v", res.Findings)
	}
	if e.finalState() != TerminalDone {
		t.Fatalf("state=%s", e.finalState())
	}
	if err := evidence.Verify(e.runDir); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.runDir, "findings.json")); err != nil {
		t.Fatal("findings.json missing")
	}
	if _, err := os.Stat(filepath.Join(e.runDir, "report.md")); err != nil {
		t.Fatal("report.md missing")
	}
	if !strings.Contains(e.auditText(), "run.finished") {
		t.Fatal("audit missing run.finished")
	}
}

func TestLoopBudgetExhaustionIsGraceful(t *testing.T) {
	e := newEnv(t, 1, "ok1", "ok2") // one action of budget
	e.opts.Planner = &planner.Stub{Turns: [][]planner.Proposal{{prop("ok1", "u"), prop("ok2", "u")}}}

	res, err := Run(context.Background(), e.opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Design §6: BudgetExhausted ⇒ drain, CORRELATE→REPORT→DONE, exit 0.
	if res.Terminal != TerminalDone || res.ExitCode != 0 {
		t.Fatalf("terminal=%s exit=%d (budget exhaustion must be graceful)", res.Terminal, res.ExitCode)
	}
	if res.Executed != 1 {
		t.Fatalf("executed=%d", res.Executed)
	}
	if !strings.Contains(e.auditText(), "budget.exhausted") {
		t.Fatal("audit missing budget.exhausted")
	}
}

func TestLoopAllRejectedConverges(t *testing.T) {
	e := newEnv(t, 10, "ok1")
	unknown := planner.Proposal{CardID: "ghost-card", Target: "localhost", Class: "web"}
	badParams := planner.Proposal{CardID: "ok1", Target: "localhost", Class: "web", Params: map[string]string{}}
	e.opts.Planner = &planner.Stub{Turns: [][]planner.Proposal{{unknown, badParams}}, ConvergeOnAllRejected: true}

	res, err := Run(context.Background(), e.opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Terminal != TerminalDone || res.ExitCode != 0 {
		t.Fatalf("terminal=%s exit=%d (rejection must not crash)", res.Terminal, res.ExitCode)
	}
	if res.Executed != 0 || len(res.Findings) != 0 {
		t.Fatalf("executed=%d findings=%d", res.Executed, len(res.Findings))
	}
	audit := e.auditText()
	if !strings.Contains(audit, `"reason":"unknown_card"`) {
		t.Fatal("audit missing unknown_card rejection")
	}
	if !strings.Contains(audit, "params_invalid") {
		t.Fatal("audit missing params_invalid rejection")
	}
	if !strings.Contains(audit, "planner.converged") {
		t.Fatal("audit missing planner.converged")
	}
}

func TestQuarantineAfterThreeConsecutiveFailures(t *testing.T) {
	e := newEnv(t, 20, "bad1", "ok1")
	e.fake.failCards["bad1"] = true
	fails := []planner.Proposal{prop("bad1", "u"), prop("bad1", "u"), prop("bad1", "u"), prop("bad1", "u")}
	turns := [][]planner.Proposal{fails, {prop("bad1", "u")}, {prop("ok1", "u")}}
	e.opts.Planner = &planner.Stub{Turns: turns}

	res, err := Run(context.Background(), e.opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Terminal != TerminalDone {
		t.Fatalf("terminal=%s", res.Terminal)
	}
	// bad1 executed exactly 3 times; the 4th proposal was rejected by quarantine.
	if got := e.fake.callsFor("bad1"); got != 3 {
		t.Fatalf("bad1 calls=%d, want 3 (4th must be quarantined)", got)
	}
	if got := e.fake.callsFor("ok1"); got != 1 {
		t.Fatalf("ok1 calls=%d, want 1", got)
	}
	if !strings.Contains(e.auditText(), "card.quarantined") {
		t.Fatal("audit missing card.quarantined")
	}
	if !strings.Contains(e.auditText(), "card quarantined for this run") {
		t.Fatal("audit missing quarantine rejection of the 4th proposal")
	}
}
