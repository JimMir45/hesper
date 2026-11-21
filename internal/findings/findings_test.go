package findings

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/JimMir45/hesper/internal/actions"
	"github.com/JimMir45/hesper/internal/evidence"
)

func cardWith(sigma []string, mustCapture []string) actions.Card {
	c := actions.Card{
		Version: "0.1", ID: "c1", Title: "t",
		Attack: actions.Attack{TechniqueID: "T1190"},
		Provenance: actions.Provenance{SourceRepo: "s", Commit: "c", License: "MIT"},
		Reuse:      "embedded",
		Executor:   actions.Executor{Adapter: "proc", Argv: []string{"true"}},
	}
	c.Evidence.MustCapture = mustCapture
	c.Detection.ExpectedSigma = sigma
	return c
}

func okRecord(kinds ...string) *evidence.Record {
	r := &evidence.Record{
		Seq: 1, TS: "2026-01-01T00:00:00Z", RunID: "r", ActionID: "a", Event: "action.executed",
		Result: &evidence.Result{Success: true, Detail: "exit=0"},
	}
	for _, k := range kinds {
		r.Artifacts = append(r.Artifacts, evidence.Artifact{Path: "evidence/a/" + k + ".txt", SHA256: "aa", Kind: k})
	}
	return r
}

func failRecord(kinds ...string) *evidence.Record {
	r := okRecord(kinds...)
	r.Result = &evidence.Result{Success: false, Detail: "stdout missing \"200\""}
	return r
}

// TestGapFourConditions is the truth table for the formal gap rule
// (design §4.4): all four conditions must hold, any violation blocks.
func TestGapFourConditions(t *testing.T) {
	card := cardWith([]string{"sigma-rule-1"}, []string{"stdout", "body"})
	full := okRecord("stdout", "body")
	partial := okRecord("stdout")
	emptyHits := map[string][]Hit{}
	firedHits := map[string][]Hit{"sigma-rule-1": {{RuleID: "sigma-rule-1", Matches: 1}}}

	cases := []struct {
		name    string
		card    actions.Card
		rec     *evidence.Record
		hits    map[string][]Hit
		wantGap bool
	}{
		{"all four hold", card, full, emptyHits, true},
		{"action failed", card, failRecord("stdout", "body"), emptyHits, false},
		{"capture incomplete", card, partial, emptyHits, false},
		{"no expected sigma", cardWith(nil, []string{"stdout", "body"}), full, emptyHits, false},
		{"rule fired", card, full, firedHits, false},
		{"nil record", card, nil, emptyHits, false},
	}
	for _, tc := range cases {
		got, reason := GapTriggered(tc.card, tc.rec, tc.hits)
		if got != tc.wantGap {
			t.Errorf("%s: gap=%v (reason=%s), want %v", tc.name, got, reason, tc.wantGap)
		}
	}
}

func TestBuildProvenAndGap(t *testing.T) {
	card := cardWith([]string{"sigma-1"}, []string{"stdout", "body"})
	o := Outcome{
		StepID: "s1", Assertion: "exposure exploitable", Repro: []string{"curl ..."},
		Card: card, Record: okRecord("stdout", "body"), HitsByRule: map[string][]Hit{},
	}
	f := Build("run-1", []Outcome{o})
	if len(f) != 2 {
		t.Fatalf("success + zero hits = proven + gap, got %d findings", len(f))
	}
	if f[0].Status != StatusProven || f[0].AttackID != "T1190" || f[0].ID != "f-001" {
		t.Fatalf("proven finding wrong: %+v", f[0])
	}
	if f[1].Status != StatusDetectionGap {
		t.Fatalf("second finding must be detection_gap: %+v", f[1])
	}
	if len(f[0].Evidence) != 2 {
		t.Fatalf("proven finding must carry its evidence artifacts")
	}
}

func TestBuildProvenWithHitsNoGap(t *testing.T) {
	card := cardWith([]string{"sigma-1"}, []string{"stdout"})
	o := Outcome{
		StepID: "s1", Assertion: "a", Card: card,
		Record: okRecord("stdout"),
		HitsByRule: map[string][]Hit{
			"sigma-1": {{RuleID: "sigma-1", Author: "some-author", Matches: 3}},
		},
	}
	f := Build("run-1", []Outcome{o})
	if len(f) != 1 || f[0].Status != StatusProven {
		t.Fatalf("hit means proven only, no gap: %+v", f)
	}
	if len(f[0].SigmaHits) != 1 || f[0].SigmaHits[0].Author != "some-author" {
		t.Fatalf("sigma hits (with DRL author) must ride on the proven finding: %+v", f[0].SigmaHits)
	}
}

func TestBuildFailedCompleteEvidenceIsDisproven(t *testing.T) {
	card := cardWith(nil, []string{"stdout"})
	o := Outcome{StepID: "s1", Assertion: "a", Card: card, Record: failRecord("stdout")}
	f := Build("run-1", []Outcome{o})
	if len(f) != 1 || f[0].Status != StatusDisproven {
		t.Fatalf("failed with complete evidence must be disproven: %+v", f)
	}
}

func TestGoldenFindingJSON(t *testing.T) {
	f := Finding{
		ID: "f-001", RunID: "run-1", Assertion: "VAmPI BOLA", AttackID: "T1190",
		Status: StatusProven,
		Evidence: []evidence.Artifact{{Path: "evidence/s1/body.json", SHA256: "abc", Kind: "body"}},
		Repro:    []string{"curl -s http://127.0.0.1:5002/user/v1/admin"},
	}
	b, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var back Finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	b2, err := json.MarshalIndent(&back, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(b2) != string(b) {
		t.Fatalf("round trip mismatch:\n got %s\nwant %s", b2, b)
	}
	for _, want := range []string{`"status": "proven"`, `"attack_id": "T1190"`, `"run_id": "run-1"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("golden JSON missing %s:\n%s", want, b)
		}
	}
}
