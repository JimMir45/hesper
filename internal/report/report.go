// Package report renders a run's findings into deterministic markdown.
package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/JimMir45/hesper/internal/findings"
)

// Input is everything the renderer needs. Deliberately plain data so the
// renderer stays trivially testable (golden snapshots).
type Input struct {
	RunID      string
	ScopeName  string
	Mode       string
	StartedUTC time.Time
	Findings   []findings.Finding
	EvidenceOK bool
	Steps      []StepLine
}

// StepLine is one scripted/planned step's outcome for the run log table.
type StepLine struct {
	StepID  string
	CardID  string
	Target  string
	Status  string // executed | denied | unknown_card | not_happened
	Detail  string
}

// RenderMarkdown produces the canonical report.md content.
func RenderMarkdown(in Input) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Hesper run report — %s\n\n", in.RunID)
	fmt.Fprintf(&b, "- Scope: %s\n", in.ScopeName)
	fmt.Fprintf(&b, "- Mode: %s\n", in.Mode)
	fmt.Fprintf(&b, "- Started (UTC): %s\n", in.StartedUTC.Format(time.RFC3339))
	fmt.Fprintf(&b, "- Evidence chain verified: %v\n\n", in.EvidenceOK)

	fmt.Fprintf(&b, "## Summary\n\n")
	prov, disp, gap := 0, 0, 0
	for _, f := range in.Findings {
		switch f.Status {
		case findings.StatusProven:
			prov++
		case findings.StatusDisproven:
			disp++
		case findings.StatusDetectionGap:
			gap++
		}
	}
	fmt.Fprintf(&b, "| proven | disproven | detection_gap |\n|---|---|---|\n| %d | %d | %d |\n\n", prov, disp, gap)

	if len(in.Steps) > 0 {
		fmt.Fprintf(&b, "## Steps\n\n| step | card | target | status | detail |\n|---|---|---|---|---|\n")
		for _, s := range in.Steps {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", s.StepID, s.CardID, s.Target, s.Status, escapeCell(s.Detail))
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Findings\n\n")
	if len(in.Findings) == 0 {
		b.WriteString("_No findings._\n")
	}
	for _, f := range in.Findings {
		fmt.Fprintf(&b, "### %s — %s [%s]\n\n", f.ID, f.Status, f.AttackID)
		fmt.Fprintf(&b, "- Assertion: %s\n", f.Assertion)
		if len(f.Evidence) > 0 {
			fmt.Fprintf(&b, "- Evidence (run-relative, sha256-verified):\n")
			for _, a := range f.Evidence {
				fmt.Fprintf(&b, "  - `%s` (%s, %s)\n", a.Path, a.Kind, shortHash(a.SHA256))
			}
		}
		if len(f.Repro) > 0 {
			fmt.Fprintf(&b, "- Repro:\n")
			for _, r := range f.Repro {
				fmt.Fprintf(&b, "  1. `%s`\n", r)
			}
		}
		if len(f.SigmaHits) > 0 {
			fmt.Fprintf(&b, "- Sigma hits:\n")
			for _, h := range f.SigmaHits {
				fmt.Fprintf(&b, "  - %s (author: %s, level: %s, matches: %d)\n", h.RuleID, h.Author, h.Level, h.Matches)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}

func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
