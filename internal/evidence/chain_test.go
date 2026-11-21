package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newRun(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func appendAction(t *testing.T, c *Chain, runDir, actionID string) string {
	t.Helper()
	work := filepath.Join(runDir, "evidence", actionID)
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	body := filepath.Join(work, "body.json")
	if err := os.WriteFile(body, []byte(`{"user":"admin"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sum, err := HashFile(body)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := c.Append(Record{
		RunID:    "r",
		ActionID: actionID,
		Event:    "action.executed",
		Artifacts: []Artifact{
			{Path: "evidence/" + actionID + "/body.json", SHA256: sum, Kind: "body"},
		},
		Result: &Result{Success: true, Detail: "exit=0"},
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	return hash
}

func TestChainVerifyPassesOnFreshRun(t *testing.T) {
	runDir := newRun(t)
	c, err := OpenChain(runDir)
	if err != nil {
		t.Fatal(err)
	}
	appendAction(t, c, runDir, "step-1")
	appendAction(t, c, runDir, "step-2")

	if err := Verify(runDir); err != nil {
		t.Fatalf("verify on untampered chain must pass: %v", err)
	}
	tail, err := Tail(runDir, 1)
	if err != nil || len(tail) != 1 || tail[0].ActionID != "step-2" {
		t.Fatalf("Tail(1) wrong: %+v err=%v", tail, err)
	}
	all, err := Tail(runDir, 10)
	if err != nil || len(all) != 2 {
		t.Fatalf("Tail(10) = %d records, want 2", len(all))
	}
}

func TestChainVerifyFailsOnTamperedRecord(t *testing.T) {
	runDir := newRun(t)
	c, _ := OpenChain(runDir)
	appendAction(t, c, runDir, "step-1")
	appendAction(t, c, runDir, "step-2")

	// Flip one byte inside record #1's event field.
	path := filepath.Join(runDir, "evidence", chainFile)
	b, _ := os.ReadFile(path)
	s := strings.Replace(string(b), `"action.executed"`, `"action.TAMPERED"`, 1)
	if s == string(b) {
		t.Fatal("tamper substitution did not apply")
	}
	os.WriteFile(path, []byte(s), 0o644)

	if err := Verify(runDir); err == nil {
		t.Fatal("verify must fail on tampered record")
	}
}

func TestChainVerifyFailsOnTamperedArtifact(t *testing.T) {
	runDir := newRun(t)
	c, _ := OpenChain(runDir)
	appendAction(t, c, runDir, "step-1")

	// Rewrite the captured artifact file — chain hash no longer matches bytes.
	body := filepath.Join(runDir, "evidence", "step-1", "body.json")
	os.WriteFile(body, []byte(`{"user":"attacker"}`), 0o644)

	if err := Verify(runDir); err == nil {
		t.Fatal("verify must fail on tampered artifact bytes")
	}
}

func TestChainVerifyFailsOnBrokenLinkage(t *testing.T) {
	runDir := newRun(t)
	c, _ := OpenChain(runDir)
	appendAction(t, c, runDir, "step-1")
	h2 := appendAction(t, c, runDir, "step-2")

	// Drop record #1: record #2's prev_hash then points at nothing verifiable.
	path := filepath.Join(runDir, "evidence", chainFile)
	b, _ := os.ReadFile(path)
	lines := strings.Split(string(b), "\n")
	os.WriteFile(path, []byte(lines[1]), 0o644) // keep only record #2 (no trailing newline kept by Split semantics)

	_ = h2
	if err := Verify(runDir); err == nil {
		t.Fatal("verify must fail when a middle record is removed")
	}
}

func TestVerifyFailsOnMissingChain(t *testing.T) {
	if err := Verify(newRun(t)); err == nil {
		t.Fatal("verify without a chain must fail")
	}
}
