package detection

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/JimMir45/hesper/internal/actions"
	"github.com/JimMir45/hesper/internal/evidence"
	"github.com/JimMir45/hesper/internal/findings"
)

// gapCard is an endpoint card with expected_sigma rules (design §4.4).
func gapCard() actions.Card {
	return actions.Card{
		Version: "0.1",
		ID:      "endpoint-ntds-ifm-dump",
		Title:   "ntdsutil IFM dump",
		Attack:  actions.Attack{TechniqueID: "T1003.003", Tactic: "credential-access"},
		Provenance: actions.Provenance{
			SourceRepo: "https://github.com/redcanaryco/atomic-red-team",
			Commit:     "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6",
			License:    "MIT",
		},
		Reuse:     "embedded",
		Executor:  actions.Executor{Adapter: "vm", Argv: []string{"actions/endpoint/files/ntds_ifm_dump.ps1"}},
		Evidence:  actions.EvidenceSpec{MustCapture: []string{"stdout", "file"}},
		Detection: actions.DetectionSpec{ExpectedSigma: []string{
			"Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)",
			"Suspicious Process Patterns NTDS.DIT Exfil",
		}},
	}
}

func gapOutcome(card actions.Card, rec *evidence.Record, hitsByRule map[string][]findings.Hit) findings.Outcome {
	return findings.Outcome{
		StepID:     "s1",
		Assertion:  "NTDS.dit can be dumped via ntdsutil IFM on the lab DC",
		Repro:      []string{"vm adapter: actions/endpoint/files/ntds_ifm_dump.ps1"},
		Card:       card,
		Record:     rec,
		HitsByRule: hitsByRule,
	}
}

func executedRecord() *evidence.Record {
	return &evidence.Record{
		Seq:       1,
		TS:        "2026-11-21T10:00:05Z",
		RunID:     "run-e2e",
		ActionID:  "act-1",
		Event:     "action.executed",
		Artifacts: []evidence.Artifact{{Path: "stdout.txt", Kind: "stdout"}, {Path: "pull_1_dump.marker", Kind: "file"}},
		Result:    &evidence.Result{Success: true},
	}
}

// TestGapE2EZeroHits emits detection_gap: action succeeded, evidence
// complete, expected_sigma non-empty, zero hits in window.
func TestGapE2EZeroHits(t *testing.T) {
	judge := offlineJudge(`{"timestamp":"2026-11-21T12:00:00Z","name":"Some Other Rule","level":"low","tags":["attack.t1111"]}`)
	judge.Index = RuleIndex{"Some Other Rule": {Author: "X"}}

	hits, err := judge.Correlate(context.Background(), Window{From: ts("2026-11-21T10:00:00Z"), To: ts("2026-11-21T10:02:00Z")},
		[]ActionRef{{ID: "act-1", AttackID: "T1003.003", TS: ts("2026-11-21T10:00:05Z")}})
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("fixture must produce zero relevant hits, got %+v", hits)
	}

	fs := findings.Build("run-e2e", []findings.Outcome{gapOutcome(gapCard(), executedRecord(), ByRule(hits))})
	if len(fs) != 2 {
		t.Fatalf("want proven + gap, got %d findings", len(fs))
	}
	var gap *findings.Finding
	for i := range fs {
		if fs[i].Status == findings.StatusDetectionGap {
			gap = &fs[i]
		}
	}
	if gap == nil {
		t.Fatalf("no detection_gap finding: %+v", fs)
	}
	if gap.AttackID != "T1003.003" || len(gap.Evidence) != 2 {
		t.Fatalf("gap finding shape wrong: %+v", gap)
	}
}

// TestGapE2EPartialHits attaches hits to the proven finding instead —
// partial coverage never yields a gap (design §4.4).
func TestGapE2EPartialHits(t *testing.T) {
	fixture := `{"timestamp":"2026-11-21T10:00:30Z","name":"Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)","level":"medium","tags":["attack.t1003.003"]}
{"timestamp":"2026-11-21T10:00:40Z","name":"Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)","level":"medium","tags":["attack.t1003.003"}`
	// (second line intentionally malformed: parser must skip, not crash)
	fixture += "}\n"
	judge := &OfflineJudge{
		ChainsawPath: "chainsaw", SamplesDir: "s", RulesDir: "r",
		Index: testIndex,
		CommandContext: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.CommandContext(ctx, "printf", "%s", fixture)
		},
	}
	hits, err := judge.Correlate(context.Background(), Window{From: ts("2026-11-21T10:00:00Z"), To: ts("2026-11-21T10:02:00Z")},
		[]ActionRef{{ID: "act-1", AttackID: "T1003.003", TS: ts("2026-11-21T10:00:05Z")}})
	if err != nil {
		t.Fatalf("judge: %v", err)
	}

	fs := findings.Build("run-e2e", []findings.Outcome{gapOutcome(gapCard(), executedRecord(), ByRule(hits))})
	if len(fs) != 1 {
		t.Fatalf("partial hits: want exactly the proven finding, got %+v", fs)
	}
	f := fs[0]
	if f.Status != findings.StatusProven || len(f.SigmaHits) != 1 {
		t.Fatalf("proven finding must carry the hit: %+v", f)
	}
	if f.SigmaHits[0].Author != "Thomas Patzke" {
		t.Fatalf("DRL-1.1 author must ride into the finding: %+v", f.SigmaHits)
	}

	// Golden: the canonical JSON keeps sigma_hits[].author.
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden := string(b)
	for _, want := range []string{`"author": "Thomas Patzke"`, `"attack_id": "T1003.003"`, `"status": "proven"`} {
		if !strings.Contains(golden, want) {
			t.Fatalf("golden missing %s:\n%s", want, golden)
		}
	}
}
