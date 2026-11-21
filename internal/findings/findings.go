// Package findings turns executed-action outcomes into findings (design
// §4.4). The detection_gap rule is formal: all four conditions must hold.
// A finding without resolvable evidence is invalid by construction.
package findings

import (
	"fmt"

	"github.com/JimMir45/hesper/internal/actions"
	"github.com/JimMir45/hesper/internal/evidence"
)

// Status values of a finding.
const (
	StatusProven       = "proven"
	StatusDisproven    = "disproven"
	StatusDetectionGap = "detection_gap"
)

// Hit is one Sigma rule's correlation outcome. Author is required when the
// rule originates from SigmaHQ (DRL-1.1 attribution, design §4.4).
type Hit struct {
	RuleID  string `json:"rule_id"`
	Author  string `json:"author,omitempty"`
	Level   string `json:"level,omitempty"`
	Matches int    `json:"matches"`
}

// Finding is the canonical output unit (design §4.4).
type Finding struct {
	ID              string              `json:"id"`
	RunID           string              `json:"run_id"`
	Assertion       string              `json:"assertion"`
	AttackID        string              `json:"attack_id"`
	Status          string              `json:"status"`
	Evidence        []evidence.Artifact `json:"evidence"`
	Repro           []string            `json:"repro,omitempty"`
	SigmaHits       []Hit               `json:"sigma_hits,omitempty"`
	ModelConfidence string              `json:"model_confidence,omitempty"`
}

// Outcome is one scripted/planned step's result, as seen by the run loop.
type Outcome struct {
	StepID    string
	Assertion string
	Repro     []string
	Card      actions.Card
	// Record is the action.executed evidence record. Nil when the action
	// never ran (unknown card, gate denial).
	Record *evidence.Record
	// Denied carries the kernel deny reason when the gate refused the step.
	Denied string
	// UnknownCard is set when the proposal referenced an unregistered card.
	UnknownCard string
	// HitsByRule correlates detection results: rule_id → hits within the
	// correlation window. Empty/absent = zero hits.
	HitsByRule map[string][]Hit
}

// mustCapturePresent reports whether every kind declared by the card is
// present among the record's artifacts.
func mustCapturePresent(card actions.Card, r *evidence.Record) bool {
	got := map[string]bool{}
	for _, a := range r.Artifacts {
		got[a.Kind] = true
	}
	for _, k := range card.Evidence.MustCapture {
		if !got[k] {
			return false
		}
	}
	return true
}

// GapTriggered implements the formal detection_gap rule (design §4.4):
//
//	gap ⟺ action.result.success == true
//	    ∧ every must_capture kind is present
//	    ∧ expected_sigma is non-empty
//	    ∧ every expected rule has zero hits
//
// It returns the verdict and the reason a non-gap verdict was reached.
func GapTriggered(card actions.Card, r *evidence.Record, hitsByRule map[string][]Hit) (bool, string) {
	if r == nil || r.Result == nil || !r.Result.Success {
		return false, "condition i: action not successful"
	}
	if !mustCapturePresent(card, r) {
		return false, "condition ii: must_capture artifacts incomplete"
	}
	if len(card.Detection.ExpectedSigma) == 0 {
		return false, "condition iii: no expected_sigma declared"
	}
	for _, ruleID := range card.Detection.ExpectedSigma {
		if len(hitsByRule[ruleID]) > 0 {
			return false, fmt.Sprintf("condition iv: rule %s fired", ruleID)
		}
	}
	return true, "all four conditions hold"
}

// Build constructs the findings of a run. Actions that did not happen
// (denied, unknown card, incomplete must_capture) produce NO finding —
// evidence semantics forbid referencing them (design §4.4/§6).
//
// In pentest mode proposals carry no assertion (design §3: opportunistic
// findings) — an empty assertion falls back to the card title so every
// finding still states what it demonstrates.
func Build(runID string, outcomes []Outcome) []Finding {
	var out []Finding
	n := 0
	assertionOf := func(o Outcome) string {
		if o.Assertion != "" {
			return o.Assertion
		}
		return "demonstrated: " + o.Card.Title
	}
	for _, o := range outcomes {
		if o.UnknownCard != "" || o.Denied != "" || o.Record == nil || o.Record.Result == nil {
			continue // did not happen
		}
		if !mustCapturePresent(o.Card, o.Record) {
			continue // did not happen (design §4.4)
		}
		r := o.Record.Result
		if !r.Success {
			// Failed with complete evidence: the attempted technique did not
			// achieve its effect — assertion disproven.
			n++
			out = append(out, Finding{
				ID:        fmt.Sprintf("f-%03d", n),
				RunID:     runID,
				Assertion: assertionOf(o),
				AttackID:  o.Card.Attack.TechniqueID,
				Status:    StatusDisproven,
				Evidence:  o.Record.Artifacts,
				Repro:     o.Repro,
			})
			continue
		}
		// Success: proven, and check for an additional gap finding.
		n++
		f := Finding{
			ID:        fmt.Sprintf("f-%03d", n),
			RunID:     runID,
			Assertion: assertionOf(o),
			AttackID:  o.Card.Attack.TechniqueID,
			Status:    StatusProven,
			Evidence:  o.Record.Artifacts,
			Repro:     o.Repro,
		}
		for _, hits := range o.HitsByRule {
			f.SigmaHits = append(f.SigmaHits, hits...)
		}
		out = append(out, f)

		if gap, _ := GapTriggered(o.Card, o.Record, o.HitsByRule); gap {
			n++
			out = append(out, Finding{
				ID:        fmt.Sprintf("f-%03d", n),
				RunID:     runID,
				Assertion: fmt.Sprintf("detection gap: %s succeeded and no expected Sigma rule fired", o.Card.ID),
				AttackID:  o.Card.Attack.TechniqueID,
				Status:    StatusDetectionGap,
				Evidence:  o.Record.Artifacts,
				Repro:     o.Repro,
			})
		}
	}
	return out
}
