package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JimMir45/hesper/internal/actions"
	"github.com/JimMir45/hesper/internal/adapters"
	"github.com/JimMir45/hesper/internal/evidence"
	"github.com/JimMir45/hesper/internal/kernel"
)

// fakeWinRM records every interaction in memory.
type fakeWinRM struct {
	uploaded  map[string][]byte
	lastArgv  []string
	runStdout []byte
	runExit   int
	runErr    error
	files     map[string][]byte // downloadable guest files
	runCount  int
}

func newFakeWinRM() *fakeWinRM {
	return &fakeWinRM{uploaded: map[string][]byte{}, files: map[string][]byte{}}
}

func (f *fakeWinRM) Upload(p string, content []byte) error {
	f.uploaded[p] = content
	return nil
}

func (f *fakeWinRM) Run(_ context.Context, argv []string) ([]byte, int, error) {
	f.runCount++
	f.lastArgv = argv
	return f.runStdout, f.runExit, f.runErr
}

func (f *fakeWinRM) Download(p string) ([]byte, error) {
	if b, ok := f.files[p]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("guest file not found: %s", p)
}

func testCard() actions.Card {
	return actions.Card{
		Version: "0.1",
		ID:      "endpoint-test",
		Title:   "test technique",
		Attack:  actions.Attack{TechniqueID: "T1003.003", Tactic: "credential-access"},
		Provenance: actions.Provenance{
			SourceRepo: "https://github.com/redcanaryco/atomic-red-team",
			Commit:     "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6",
			License:    "MIT",
		},
		Reuse: "embedded",
		Executor: actions.Executor{
			Adapter: "vm",
			Argv:    []string{"actions/endpoint/files/test.ps1"},
		},
		Evidence: actions.EvidenceSpec{MustCapture: []string{"stdout", "file"}},
	}
}

type harness struct {
	adapter *Adapter
	winrm   *fakeWinRM
	req     adapters.ExecRequest
	records []evidence.Record
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	script := filepath.Join(root, "actions", "endpoint", "files", "test.ps1")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("# test script\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := newFakeWinRM()
	h := &harness{adapter: New(w, root), winrm: w}
	h.req = adapters.ExecRequest{
		RunID:    "run-1",
		ActionID: "act-1",
		Card:     testCard(),
		Params:   map[string]string{"remote_files": `C:\hesper\out\dump.marker`},
		Target:   kernel.Target{Kind: "host", Value: "dc01.lab"},
		WorkDir:  t.TempDir(),
	}
	return h
}

func (h *harness) emit(r evidence.Record) error { h.records = append(h.records, r); return nil }

func TestVMHappyPathCapturesAllKinds(t *testing.T) {
	h := newHarness(t)
	h.winrm.runStdout = []byte("technique executed")
	h.winrm.runExit = 0
	h.winrm.files[`C:\hesper\out\dump.marker`] = []byte("DUMP")

	res, err := h.adapter.Execute(context.Background(), h.req, h.emit)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Success || res.NotHappened {
		t.Fatalf("want success, got %+v", res)
	}
	if len(h.records) != 1 {
		t.Fatalf("want 1 evidence record, got %d", len(h.records))
	}
	kinds := map[string]bool{}
	for _, a := range h.records[0].Artifacts {
		kinds[a.Kind] = true
	}
	if !kinds["stdout"] || !kinds["file"] {
		t.Fatalf("must_capture kinds missing: %v", kinds)
	}
	// Invocation: the command travels as ONE string (Run psQuote-wraps the
	// whole element; per-token quoting explodes on the guest — m4-live).
	want := "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\hesper\\act-1.ps1 -ParamsFile C:\\hesper\\act-1.params.json"
	if len(h.winrm.lastArgv) != 1 || h.winrm.lastArgv[0] != want {
		t.Fatalf("remote argv = %v, want single command element %q", h.winrm.lastArgv, want)
	}
}

func TestVMParamsNeverReachCommandLine(t *testing.T) {
	h := newHarness(t)
	h.winrm.runStdout = []byte("ok")
	h.winrm.runExit = 0
	h.winrm.files[`C:\hesper\out\dump.marker`] = []byte("DUMP")
	// Hostile planner-supplied values — must travel ONLY in the params file.
	h.req.Params["marker"] = "; rm -rf /"
	h.req.Params["note"] = "`whoami` $(reboot) & calc.exe"

	if _, err := h.adapter.Execute(context.Background(), h.req, h.emit); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	cmdline := strings.Join(h.winrm.lastArgv, " ")
	for _, evil := range []string{"rm -rf", "whoami", "reboot", "calc.exe", "$(", "`"} {
		if strings.Contains(cmdline, evil) {
			t.Fatalf("injection: %q leaked into remote command line %q", evil, cmdline)
		}
	}
	paramsJSON := h.winrm.uploaded[`C:\hesper\act-1.params.json`]
	var carried map[string]string
	if err := json.Unmarshal(paramsJSON, &carried); err != nil {
		t.Fatalf("uploaded params file is not valid JSON: %v", err)
	}
	for k, want := range map[string]string{
		"marker": "; rm -rf /",
		"note":   "`whoami` $(reboot) & calc.exe",
	} {
		if carried[k] != want {
			t.Fatalf("params[%q] = %q, want exact literal %q", k, carried[k], want)
		}
	}
}

func TestVMMissingMustCaptureMeansNotHappened(t *testing.T) {
	h := newHarness(t)
	h.winrm.runStdout = []byte("script ran") // but no remote file produced
	h.winrm.runExit = 0

	res, err := h.adapter.Execute(context.Background(), h.req, h.emit)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Success || !res.NotHappened {
		t.Fatalf("missing must_capture must be NotHappened, got %+v", res)
	}
	if len(h.records) != 1 || !h.records[0].Result.NotHappened {
		t.Fatalf("evidence record must carry not_happened: %+v", h.records)
	}
}

func TestVMNonzeroExitIsFailureButHappened(t *testing.T) {
	h := newHarness(t)
	h.winrm.runStdout = []byte("boom")
	h.winrm.runExit = 1
	h.winrm.files[`C:\hesper\out\dump.marker`] = []byte("DUMP")

	res, err := h.adapter.Execute(context.Background(), h.req, h.emit)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Success || res.NotHappened {
		t.Fatalf("nonzero exit with complete evidence = failed-but-happened, got %+v", res)
	}
}
