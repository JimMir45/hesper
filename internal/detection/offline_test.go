package detection

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/JimMir45/hesper/internal/findings"
)

// runFakeChainsaw returns a CommandContext whose output is fully controlled
// via a script echo. We run the real binary "printf" with the fixture as
// argv — deterministic and dependency-free.
func runFakeChainsaw(fixture string) func(ctx context.Context, name string, args ...string) *exec.Cmd {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		_ = name
		return exec.CommandContext(ctx, "printf", "%s", fixture)
	}
}

var testIndex = RuleIndex{
	"Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)": {Author: "Thomas Patzke", Level: "medium"},
	"HackTool - Mimikatz Execution":                                  {Author: "Teymur Kheirkhabarov, oscd.community", Level: "high"},
}

func offlineJudge(fixture string) *OfflineJudge {
	return &OfflineJudge{
		ChainsawPath:   "chainsaw",
		SamplesDir:     "samples",
		RulesDir:       "rules",
		MappingPath:    "mapping.yml",
		Index:          testIndex,
		CommandContext: runFakeChainsaw(fixture),
	}
}

const sampleNDJSON = `{"timestamp":"2026-11-21T10:00:05Z","name":"Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)","level":"medium","tags":["attack.t1003.003"],"path":"a.evtx"}
{"timestamp":"2026-11-21T10:00:40Z","name":"Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)","level":"medium","tags":["attack.t1003.003"],"path":"a.evtx"}
{"timestamp":"2026-11-21T10:01:00Z","name":"HackTool - Mimikatz Execution","level":"high","tags":["attack.t1003.001"],"path":"b.evtx"}
{"timestamp":"2026-11-21T23:59:00Z","name":"Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)","level":"medium","tags":["attack.t1003.003"],"path":"a.evtx"}
{"timestamp":"2026-11-21T10:00:10Z","name":"Unrelated Rule","level":"low","tags":["attack.t9999"],"path":"c.evtx"}
chainsaw banner line that is not JSON
`

func TestOfflineJudgeWindowAndTagFilter(t *testing.T) {
	j := offlineJudge(sampleNDJSON)
	w := Window{From: ts("2026-11-21T10:00:00Z"), To: ts("2026-11-21T10:02:00Z")}
	refs := []ActionRef{{ID: "a1", AttackID: "T1003.003", TS: ts("2026-11-21T10:00:05Z")}}

	hits, err := j.Correlate(context.Background(), w, refs)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly the ntdsutil rule (window+tag filtered), got %d: %+v", len(hits), hits)
	}
	h := hits[0]
	if h.RuleID != "Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)" {
		t.Fatalf("wrong rule: %s", h.RuleID)
	}
	if h.Author != "Thomas Patzke" {
		t.Fatalf("DRL-1.1 author missing: %+v", h)
	}
	if h.Matches != 2 {
		t.Fatalf("want 2 in-window matches, got %d", h.Matches)
	}
	// Mimikatz rule is in-window but its tag (t1003.001) does not intersect refs.
	for _, h := range hits {
		if strings.Contains(h.RuleID, "Mimikatz") {
			t.Fatalf("unreferenced technique leaked: %+v", h)
		}
	}
}

func TestOfflineJudgeZeroHits(t *testing.T) {
	j := offlineJudge(sampleNDJSON)
	w := Window{From: ts("2026-11-21T10:00:00Z"), To: ts("2026-11-21T10:02:00Z")}
	refs := []ActionRef{{ID: "a1", AttackID: "T1486", TS: ts("2026-11-21T10:00:00Z")}}
	hits, err := j.Correlate(context.Background(), w, refs)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("want zero hits, got %+v", hits)
	}
}

func TestOfflineJudgeAttributionFailClosed(t *testing.T) {
	j := offlineJudge(sampleNDJSON)
	j.Index = RuleIndex{} // rule present in output, author unknown
	w := Window{From: ts("2026-11-21T10:00:00Z"), To: ts("2026-11-21T10:02:00Z")}
	refs := []ActionRef{{ID: "a1", AttackID: "T1003.003", TS: ts("2026-11-21T10:00:05Z")}}
	if _, err := j.Correlate(context.Background(), w, refs); err == nil {
		t.Fatal("unattributed rule must be a hard error (DRL-1.1 fail-closed)")
	}
}

func TestRuleIndexRequiresAuthors(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/idx.json"
	if err := writeFile(p, `{"R1":{"author":"A"},"R2":{"level":"high"}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuleIndex(p); err == nil {
		t.Fatal("index entry without author must fail to load")
	}
}

func TestByRuleGroupsHits(t *testing.T) {
	hits := []findings.Hit{
		{RuleID: "R1", Author: "A", Matches: 2},
		{RuleID: "R1", Author: "A", Matches: 1},
		{RuleID: "R2", Author: "B", Matches: 1},
	}
	m := ByRule(hits)
	if len(m["R1"]) != 2 || len(m["R2"]) != 1 {
		t.Fatalf("grouping wrong: %+v", m)
	}
	if ByRule(nil) != nil {
		t.Fatal("nil in, nil out")
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}
