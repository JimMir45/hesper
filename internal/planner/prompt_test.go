package planner

import (
	"strings"
	"testing"
)

func TestComposeGolden(t *testing.T) {
	s := StateView{
		RunID:  "run-1",
		State:  "ENGAGE",
		Mode:   "validate",
		Turn:   2,
		Targets: []string{"172.16.0.0/16", "localhost"},
		Classes: []string{"web", "creds"},
		Adapters: []string{"proc", "lib"},
		Budget: BudgetView{MaxActions: 50, UsedActions: 3},
		Cards: []CardDigest{
			{ID: "web-vampi-bola-probe", TechniqueID: "T1190", Tactic: "initial-access", Phase: "entry", Adapter: "proc", Title: "VAmPI BOLA probe", Notes: "insecure instance on 5002"},
		},
		Feedback: []Feedback{
			{CardID: "nope", Kind: FeedbackRejected, Reason: "unknown_card"},
		},
		FindingsSoFar: 3,
		EvidenceTail: []string{"seq=7 action=a-001 event=action.executed success=true"},
	}
	system, user := Compose(s)

	for _, want := range []string{
		"JSON array",
		"mode: validate",
		"turn: 2",
		"budget: 3/50 actions used",
		"findings so far: 3",
		"authorized targets: 172.16.0.0/16, localhost",
		"authorized classes: web, creds",
		"authorized adapters: proc, lib",
		"web-vampi-bola-probe [T1190/initial-access] adapter=proc phase=\"entry\" — VAmPI BOLA probe (insecure instance on 5002)",
		"rejected: unknown_card (card nope)",
		"seq=7 action=a-001 event=action.executed success=true",
	} {
		if !strings.Contains(system+"\n"+user, want) {
			t.Errorf("composed prompt missing %q", want)
		}
	}

	// The digest must NOT leak internals: no argv templates, no manifest fields.
	for _, banned := range []string{"argv", "curl", "provenance", "max_minutes", "stop_conditions"} {
		if strings.Contains(system+"\n"+user, banned) {
			t.Errorf("composed prompt leaks internals: %q", banned)
		}
	}
}

func TestComposeDeterministic(t *testing.T) {
	s := StateView{Mode: "validate", Turn: 1, Targets: []string{"localhost"}, Adapters: []string{"proc"}, Budget: BudgetView{MaxActions: 5}}
	s1u, s1s := Compose(s)
	s2u, s2s := Compose(s)
	if s1u != s2u || s1s != s2s {
		t.Fatal("Compose must be deterministic for identical input")
	}
}
