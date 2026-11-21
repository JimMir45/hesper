package planner

import (
	"fmt"
	"strings"
)

// Compose builds the deterministic prompt pair for one planner turn
// (design §5.6): system carries the role and the output contract; user
// carries the state digest. Only digests — never the raw scope manifest,
// never card internals like argv.
func Compose(s StateView) (system, user string) {
	system = strings.TrimSpace(`
You are the planning module of Hesper, a headless engine that validates
exposure and defenses by executing authorized attack-chain actions inside a
scoped range.

Contract:
- Reply with a JSON array of at most the allowed number of proposals, and
  nothing else. No prose, no markdown fences.
- Each proposal: {"card_id","target","class","params","assertion","repro","rationale"}.
  card_id and target are required; params keys must match the card.
- Only use card ids listed below. Unknown ids, invalid params, or
  out-of-scope targets are rejected and returned to you as feedback.
- When nothing more is useful, reply with [].
`)

	var b strings.Builder
	fmt.Fprintf(&b, "mode: %s\nturn: %d\n", s.Mode, s.Turn)
	fmt.Fprintf(&b, "budget: %d/%d actions used\n", s.Budget.UsedActions, s.Budget.MaxActions)
	fmt.Fprintf(&b, "findings so far: %d\n", s.FindingsSoFar)
	fmt.Fprintf(&b, "authorized targets: %s\n", strings.Join(s.Targets, ", "))
	if len(s.Classes) > 0 {
		fmt.Fprintf(&b, "authorized classes: %s\n", strings.Join(s.Classes, ", "))
	}
	fmt.Fprintf(&b, "authorized adapters: %s\n", strings.Join(s.Adapters, ", "))

	b.WriteString("cards:\n")
	for _, c := range s.Cards {
		line := fmt.Sprintf("- %s [%s/%s] adapter=%s phase=%q — %s", c.ID, c.TechniqueID, c.Tactic, c.Adapter, c.Phase, c.Title)
		if c.Notes != "" {
			line += " (" + c.Notes + ")"
		}
		b.WriteString(line + "\n")
	}

	if len(s.Feedback) > 0 {
		b.WriteString("last round feedback:\n")
		for _, f := range s.Feedback {
			fmt.Fprintf(&b, "- %s: %s (card %s)\n", f.Kind, f.Reason, f.CardID)
		}
	}

	if len(s.EvidenceTail) > 0 {
		b.WriteString("evidence tail (bounded):\n")
		for _, e := range s.EvidenceTail {
			b.WriteString("- " + e + "\n")
		}
	}

	user = strings.TrimSpace(b.String())
	return system, user
}
