package report

import (
	"strings"
	"testing"
	"time"

	"github.com/JimMir45/hesper/internal/evidence"
	"github.com/JimMir45/hesper/internal/findings"
)

func TestRenderMarkdownGolden(t *testing.T) {
	in := Input{
		RunID:      "20260101T000000Z",
		ScopeName:  "lab-lite-demo",
		Mode:       "validate",
		StartedUTC: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		EvidenceOK: true,
		Steps: []StepLine{
			{StepID: "step-1", CardID: "web-vampi-bola-probe", Target: "localhost", Status: "executed", Detail: "exit=0; stdout contains \"200\""},
			{StepID: "step-2", CardID: "no-such-card", Target: "localhost", Status: "unknown_card", Detail: "unknown card"},
		},
		Findings: []findings.Finding{
			{
				ID: "f-001", RunID: "20260101T000000Z", Assertion: "VAmPI serves /user/v1/admin unauthenticated",
				AttackID: "T1190", Status: findings.StatusProven,
				Evidence: []evidence.Artifact{{Path: "evidence/step-1/body.json", SHA256: "0123456789abcdef", Kind: "body"}},
				Repro:    []string{"curl -s http://127.0.0.1:5002/user/v1/admin"},
			},
		},
	}
	got := RenderMarkdown(in)
	for _, want := range []string{
		"# Hesper run report — 20260101T000000Z",
		"- Scope: lab-lite-demo",
		"- Evidence chain verified: true",
		"| proven | disproven | detection_gap |",
		"| 1 | 0 | 0 |",
		"| step-1 | web-vampi-bola-probe | localhost | executed |",
		"### f-001 — proven [T1190]",
		"- Assertion: VAmPI serves /user/v1/admin unauthenticated",
		"`evidence/step-1/body.json` (body, 0123456789ab…)",
		"1. `curl -s http://127.0.0.1:5002/user/v1/admin`",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("golden markdown missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "f-002") {
		t.Fatal("unknown_card steps must not become findings")
	}
}
