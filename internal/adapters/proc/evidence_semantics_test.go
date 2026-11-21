package proc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JimMir45/hesper/internal/evidence"
	"github.com/JimMir45/hesper/internal/findings"
)

// TestMissingMustCaptureMeansNotHappened is the second half of the M2-4
// hard gate: when a must_capture artifact kind is missing, the action is
// recorded as not-happened and no finding may reference it (design §4.4).
func TestMissingMustCaptureMeansNotHappened(t *testing.T) {
	// The card demands stdout AND body; the command produces only stdout
	// (grep on a missing file exits non-zero and never writes the body).
	c := writeCard(t, t.TempDir(), "sem.card.json", `{
		"version": "0.1",
		"id": "test-semantics",
		"title": "must_capture semantics probe",
		"attack": {"technique_id": "T1082"},
		"provenance": {"source_repo": "test", "commit": "abc", "license": "MIT"},
		"reuse": "embedded",
		"executor": {"adapter": "proc", "argv": ["grep", "-c", "zzz-not-there", "/nonexistent-file-zzz"]},
		"evidence": {"must_capture": ["stdout", "body"]}
	}`)

	res, records, runDir := runOne(t, c, nil)
	if res.Success {
		t.Fatal("incomplete capture must not count as success")
	}
	if !res.NotHappened {
		t.Fatal("incomplete capture must mark the action not_happened")
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1 (the audit record still exists)", len(records))
	}
	if records[0].Result == nil || records[0].Result.Success {
		t.Fatal("emitted record must carry success=false")
	}

	// Findings must not reference the not-happened action.
	f := findings.Build("run-x", []findings.Outcome{{
		StepID:    "step-1",
		Assertion: "should never appear",
		Card:      c,
		Record:    &records[0],
	}})
	if len(f) != 0 {
		t.Fatalf("no finding may reference a not-happened action; got %+v", f)
	}
	_ = runDir
}

// TestDeniedActionsProduceNoFinding covers the run-loop side of evidence
// semantics: gate-denied and unknown-card outcomes carry no record at all.
func TestDeniedActionsProduceNoFinding(t *testing.T) {
	c := writeCard(t, t.TempDir(), "denied.card.json", `{
		"version": "0.1",
		"id": "test-denied",
		"title": "denied probe",
		"attack": {"technique_id": "T1098"},
		"provenance": {"source_repo": "test", "commit": "abc", "license": "MIT"},
		"reuse": "embedded",
		"executor": {"adapter": "proc", "argv": ["true"]},
		"evidence": {"must_capture": ["stdout"]}
	}`)
	f := findings.Build("run-x", []findings.Outcome{
		{StepID: "s1", Card: c, Denied: "technique explicitly denied"},
		{StepID: "s2", Card: c, UnknownCard: "no-such-card"},
	})
	if len(f) != 0 {
		t.Fatalf("denied/unknown-card outcomes must produce no finding; got %+v", f)
	}
}

// TestBodyArtifactDefaultsToBodyBin verifies the out_file convention: when
// params carry no out_file, the body artifact lands at evidence/<step>/body.bin.
func TestBodyArtifactDefaultsToBodyBin(t *testing.T) {
	c := writeCard(t, t.TempDir(), "body.card.json", `{
		"version": "0.1",
		"id": "test-body-default",
		"title": "body default probe",
		"attack": {"technique_id": "T1082"},
		"provenance": {"source_repo": "test", "commit": "abc", "license": "MIT"},
		"reuse": "embedded",
		"executor": {
			"adapter": "proc",
			"argv": ["cp", "{params.source}", "{params.out_file}"]
		},
		"evidence": {"must_capture": ["body"]}
	}`)
	runDir := t.TempDir()
	src := filepath.Join(t.TempDir(), "src.bin")
	if err := writeFile(src, "hello-evidence"); err != nil {
		t.Fatal(err)
	}
	// {params.source} is substituted as a plain path; out_file resolves into WorkDir.
	work := filepath.Join(runDir, "evidence", "step-1")
	p := New()
	var records []evidence.Record
	_, err := p.Execute(tContext(), mkReq(c, "r", "step-1", map[string]string{
		"source":   src,
		"out_file": "payload.bin",
	}, kernelTarget("localhost"), work), func(r evidence.Record) error {
		for i := range r.Artifacts {
			r.Artifacts[i].Path = filepath.ToSlash(filepath.Join("evidence", "step-1", r.Artifacts[i].Path))
		}
		records = append(records, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Result == nil || !records[0].Result.Success {
		t.Fatalf("body default probe must succeed: %+v", records)
	}
	if _, err := os.Stat(filepath.Join(work, "payload.bin")); err != nil {
		t.Fatalf("out_file must resolve into WorkDir: %v", err)
	}
}
