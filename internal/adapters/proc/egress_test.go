package proc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JimMir45/hesper/internal/actions"
	"github.com/JimMir45/hesper/internal/egress"
	"github.com/JimMir45/hesper/internal/evidence"
	"github.com/JimMir45/hesper/internal/kernel"
)

// The committed fixture card is the enforcement acceptance artifact: this
// test loads it through the real registry (lint included) and executes it
// through the guard against an out-of-scope address.
func loadViolationCard(t *testing.T) actions.Card {
	t.Helper()
	dir := filepath.Join("testdata")
	reg, err := actions.LoadRegistry(dir)
	if err != nil {
		t.Fatalf("LoadRegistry(testdata): %v", err)
	}
	card, ok := reg.Get("fixture.egress-violation")
	if !ok {
		t.Fatal("fixture.egress-violation card not found")
	}
	return card
}

func guardScope() *kernel.ScopeManifest {
	return &kernel.ScopeManifest{
		Version: "0.1", Mode: kernel.ModeValidate,
		Targets: []kernel.Target{
			{Kind: "host", Value: "localhost"},
			{Kind: "cidr", Value: "127.0.0.0/8"},
			{Kind: "host", Value: "::1"}, // httptest falls back to [::1] on hosts with broken IPv4 loopback
		},
		Allow:  kernel.Allow{Classes: []string{"web"}, Adapters: []string{"proc"}},
		Budget: kernel.Budget{MaxActions: 5, MaxMinutes: 5},
	}
}

func startedGuard(t *testing.T) *egress.Guard {
	t.Helper()
	g, err := egress.NewGuard(guardScope())
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	g.Start()
	t.Cleanup(func() { _ = g.Close() })
	return g
}

// TestGuardedViolationFailsAction: the fixture card connecting to TEST-NET-3
// through the guard ⇒ curl gets 403 (non-zero exit), the action FAILS, the
// destination is reported in ExecResult.EgressViolations, and the enforced
// level is proxy. Design §5.3/§7 acceptance, offline (guard answers locally).
func TestGuardedViolationFailsAction(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	card := loadViolationCard(t)
	g := startedGuard(t)
	p := NewWithGuard(g)

	workDir := t.TempDir()
	res, err := p.Execute(tContext(), mkReq(card, "run", "a-001",
		map[string]string{"url": "http://203.0.113.13:80/x", "out_file": "out.bin"},
		kernelTarget("203.0.113.13"), workDir), func(r evidence.Record) error { return nil })
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Success {
		t.Fatal("violating action must fail")
	}
	if res.NotHappened {
		t.Fatalf("action happened (stderr captured) — must not be NotHappened; detail=%s", res.Detail)
	}
	if len(res.EgressViolations) == 0 || !strings.HasPrefix(res.EgressViolations[0], "203.0.113.13") {
		t.Fatalf("EgressViolations=%v, want [203.0.113.13:80]", res.EgressViolations)
	}
	if res.EnforcedEgress != egress.LevelProxy {
		t.Fatalf("EnforcedEgress=%q, want %q", res.EnforcedEgress, egress.LevelProxy)
	}
	if !strings.Contains(res.Detail, "egress violation") {
		t.Fatalf("detail must name the violation: %s", res.Detail)
	}
	// stderr artifact (curl's error output) was captured: the attempt is
	// evidenced, classified failed — not vanished.
	if _, err := os.Stat(filepath.Join(workDir, "stderr.txt")); err != nil {
		t.Fatal("stderr.txt (evidence of the refused attempt) missing")
	}
}

// TestGuardedAllowedTargetSucceeds: an in-scope loopback target flows THROUGH
// the guard and succeeds — enforcement must not break legitimate actions.
func TestGuardedAllowedTargetSucceeds(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("in-scope body"))
	}))
	defer srv.Close()

	card := loadViolationCard(t) // same argv shape; destination decides
	g := startedGuard(t)
	p := NewWithGuard(g)

	workDir := t.TempDir()
	res, err := p.Execute(tContext(), mkReq(card, "run", "a-002",
		map[string]string{"url": srv.URL + "/ok", "out_file": "out.bin"},
		kernelTarget("127.0.0.1"), workDir), func(r evidence.Record) error { return nil })
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Success {
		t.Fatalf("in-scope action must succeed; detail=%s", res.Detail)
	}
	if len(res.EgressViolations) != 0 {
		t.Fatalf("no violations expected, got %v", res.EgressViolations)
	}
	if g.ViolationCount() != 0 {
		t.Fatalf("guard violations=%d", g.ViolationCount())
	}
}

// TestUnguardedReportsLevelNone: without a guard the adapter reports
// LevelNone explicitly — no interception is claimed.
func TestUnguardedReportsLevelNone(t *testing.T) {
	p := New()
	card := loadViolationCard(t)
	workDir := t.TempDir()
	res, err := p.Execute(tContext(), mkReq(card, "run", "a-003",
		map[string]string{"url": "http://203.0.113.13:80/x", "out_file": "out.bin"},
		kernelTarget("203.0.113.13"), workDir), func(r evidence.Record) error { return nil })
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.EnforcedEgress != egress.LevelNone {
		t.Fatalf("EnforcedEgress=%q, want %q", res.EnforcedEgress, egress.LevelNone)
	}
	if len(res.EgressViolations) != 0 {
		t.Fatalf("unguarded adapter reports no violations (nothing intercepted), got %v", res.EgressViolations)
	}
}

// TestViolationCardFixtureShape: the committed fixture stays a valid,
// lint-passing card (provenance triple present).
func TestViolationCardFixtureShape(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "egress-violation.card.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c actions.Card
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if c.ID != "fixture.egress-violation" || c.Provenance.SourceRepo == "" || c.Provenance.Commit == "" || c.Provenance.License == "" {
		t.Fatalf("fixture card malformed: %+v", c)
	}
}
