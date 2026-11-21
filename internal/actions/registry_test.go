package actions

import (
	"os"
	"path/filepath"
	"testing"
)

const goodCard = `{
  "version": "0.1",
  "id": "test-good-card",
  "title": "t",
  "attack": {"technique_id": "T1190", "tactic": "initial-access"},
  "provenance": {"source_repo": "https://github.com/JimMir45/hesper", "commit": "abc", "license": "Apache-2.0"},
  "reuse": "embedded",
  "executor": {"adapter": "proc", "argv": ["true"]},
  "evidence": {"must_capture": ["stdout"]}
}`

func writeCard(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRegistryGood(t *testing.T) {
	dir := t.TempDir()
	writeCard(t, dir, "a.card.json", goodCard)
	r, err := LoadRegistry(dir)
	if err != nil {
		t.Fatalf("good card must load: %v", err)
	}
	if r.Count() != 1 {
		t.Fatalf("count = %d, want 1", r.Count())
	}
	c, ok := r.Get("test-good-card")
	if !ok || c.Attack.TechniqueID != "T1190" {
		t.Fatalf("Get failed: %+v", c)
	}
	if got := r.Candidates(Filter{Adapter: "proc"}); len(got) != 1 {
		t.Fatalf("Candidates(proc) = %d, want 1", len(got))
	}
	if got := r.Candidates(Filter{Adapter: "vm"}); len(got) != 0 {
		t.Fatalf("Candidates(vm) = %d, want 0", len(got))
	}
}

func TestLintFailures(t *testing.T) {
	cases := map[string]string{
		"missing provenance":   `{"version":"0.1","id":"x","title":"t","attack":{"technique_id":"T1190"},"reuse":"embedded","executor":{"adapter":"proc","argv":["true"]},"evidence":{"must_capture":["stdout"]}}`,
		"external bound lib":   `{"version":"0.1","id":"x","title":"t","attack":{"technique_id":"T1190"},"provenance":{"source_repo":"a","commit":"b","license":"c"},"reuse":"external","executor":{"adapter":"lib"},"evidence":{"must_capture":["stdout"]}}`,
		"blocklisted source":   `{"version":"0.1","id":"x","title":"t","attack":{"technique_id":"T1190"},"provenance":{"source_repo":"https://github.com/peass-ng/PEASS-ng","commit":"b","license":"GPL"},"reuse":"data_borrow","executor":{"adapter":"proc","argv":["true"]},"evidence":{"must_capture":["stdout"]}}`,
		"unknown major":        `{"version":"1.0","id":"x","title":"t","attack":{"technique_id":"T1190"},"provenance":{"source_repo":"a","commit":"b","license":"c"},"reuse":"embedded","executor":{"adapter":"proc","argv":["true"]},"evidence":{"must_capture":["stdout"]}}`,
		"no must_capture":      `{"version":"0.1","id":"x","title":"t","attack":{"technique_id":"T1190"},"provenance":{"source_repo":"a","commit":"b","license":"c"},"reuse":"embedded","executor":{"adapter":"proc","argv":["true"]},"evidence":{"must_capture":[]}}`,
		"bad reuse":            `{"version":"0.1","id":"x","title":"t","attack":{"technique_id":"T1190"},"provenance":{"source_repo":"a","commit":"b","license":"c"},"reuse":"borrowed","executor":{"adapter":"proc","argv":["true"]},"evidence":{"must_capture":["stdout"]}}`,
		"bad adapter":          `{"version":"0.1","id":"x","title":"t","attack":{"technique_id":"T1190"},"provenance":{"source_repo":"a","commit":"b","license":"c"},"reuse":"embedded","executor":{"adapter":"teleport","argv":["true"]},"evidence":{"must_capture":["stdout"]}}`,
		"no technique":         `{"version":"0.1","id":"x","title":"t","attack":{"technique_id":""},"provenance":{"source_repo":"a","commit":"b","license":"c"},"reuse":"embedded","executor":{"adapter":"proc","argv":["true"]},"evidence":{"must_capture":["stdout"]}}`,
		"external without argv": `{"version":"0.1","id":"x","title":"t","attack":{"technique_id":"T1190"},"provenance":{"source_repo":"a","commit":"b","license":"c"},"reuse":"external","executor":{"adapter":"proc"},"evidence":{"must_capture":["stdout"]}}`,
	}
	for name, body := range cases {
		dir := t.TempDir()
		writeCard(t, dir, "bad.card.json", body)
		if _, err := LoadRegistry(dir); err == nil {
			t.Errorf("%s: expected lint failure, got nil", name)
		}
	}
}

// TestBadFixturesFailLint is the unit half of the CI red gate: the checked-in
// bad fixtures must never pass lint. ci.yml proves the same at the CLI level.
func TestBadFixturesFailLint(t *testing.T) {
	dir := filepath.Join("testdata", "bad")
	if _, err := LoadRegistry(dir); err == nil {
		t.Fatal("bad fixtures must fail lint")
	}
}

func TestDuplicateIDRejected(t *testing.T) {
	dir := t.TempDir()
	writeCard(t, dir, "a.card.json", goodCard)
	writeCard(t, dir, "b.card.json", goodCard) // same id
	if _, err := LoadRegistry(dir); err == nil {
		t.Fatal("duplicate ids must be rejected")
	}
}

func TestRealCardsLint(t *testing.T) {
	r, err := LoadRegistry(filepath.Join("..", "..", "actions"))
	if err != nil {
		t.Fatalf("checked-in cards must lint clean: %v", err)
	}
	if r.Count() < 3 {
		t.Fatalf("expected at least 3 real cards, got %d", r.Count())
	}
}
