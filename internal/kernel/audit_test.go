package kernel

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditAppendMonotonicJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAudit(path)
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}

	events := []struct {
		name string
		data map[string]any
	}{
		{"run.started", map[string]any{"mode": "validate"}},
		{"gate.decision", map[string]any{"allowed": false, "reason": "target outside scope"}},
		{"run.stopped", nil},
	}
	for _, e := range events {
		if err := a.Append(e.name, e.data); err != nil {
			t.Fatalf("Append(%s): %v", e.name, err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit file: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	wantSeq := 1
	prevTS := time.Time{}
	lines := 0
	for sc.Scan() {
		lines++
		var line struct {
			Seq   int    `json:"seq"`
			TS    string `json:"ts"`
			Event string `json:"event"`
			Data  map[string]any `json:"data"`
		}
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("line %d not valid JSON: %v", lines, err)
		}
		if line.Seq != wantSeq {
			t.Fatalf("line %d: seq = %d, want %d (monotonic)", lines, line.Seq, wantSeq)
		}
		ts, err := time.Parse(time.RFC3339Nano, line.TS)
		if err != nil {
			t.Fatalf("line %d: ts not RFC3339: %v", lines, err)
		}
		if !ts.After(prevTS) && lines > 1 {
			t.Fatalf("line %d: ts not monotonic", lines)
		}
		prevTS = ts
		wantSeq++
	}
	if lines != len(events) {
		t.Fatalf("got %d lines, want %d", lines, len(events))
	}
}

func TestAuditAppendRollsBackSeqOnMarshalFailure(t *testing.T) {
	a, err := OpenAudit(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("OpenAudit: %v", err)
	}
	defer a.Close()

	// map[string]any containing a channel is unmarshalable → marshal error.
	if err := a.Append("bad", map[string]any{"ch": make(chan int)}); err == nil {
		t.Fatal("unmarshalable data must error")
	}
	if err := a.Append("good", map[string]any{"ok": true}); err != nil {
		t.Fatalf("append after failure: %v", err)
	}
	// The good event must have seq 1, not 2 — seq rolled back.
	b, err := os.ReadFile(a.f.Name())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var line struct {
		Seq int `json:"seq"`
	}
	if err := json.Unmarshal(b[:len(b)-1], &line); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if line.Seq != 1 {
		t.Fatalf("seq after failed append = %d, want 1 (rollback)", line.Seq)
	}
}
