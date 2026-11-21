package detection

import (
	"testing"
	"time"
)

// Real element shape from chainsaw v2.18 "hunt --json" (M4 live verification,
// lab/state/chainsaw-out/findings.json): one JSON ARRAY; name/level/tags/
// timestamp are top-level per element.
func TestParseChainsawArrayShapeV218(t *testing.T) {
	fixture := `[{"group":"Sigma","kind":"individual","document":{"kind":"evtx","path":"/data/samples/Credential Access/4794_DSRM_password_change_t1098.evtx"},"name":"Password Change on Directory Service Restore Mode (DSRM) Account","level":"high","tags":["attack.privilege-escalation","attack.persistence","attack.t1098"],"timestamp":"2017-06-09T19:21:26.968669900+00:00","authors":["Friedrich West","Thomas Patzke"],"id":"0x0","status":"stable"}]`
	hits, err := parseChainsawOutput([]byte(fixture))
	if err != nil {
		t.Fatalf("array parse: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	h := hits[0]
	if h.Name != "Password Change on Directory Service Restore Mode (DSRM) Account" {
		t.Fatalf("name not parsed: %q", h.Name)
	}
	if h.Level != "high" {
		t.Fatalf("level not parsed: %q", h.Level)
	}
	if len(h.Tags) != 3 || h.Tags[2] != "attack.t1098" {
		t.Fatalf("tags not parsed: %v", h.Tags)
	}
	w := Window{
		From: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if !hitInWindow(h.Timestamp, w) {
		t.Fatal("v2.18 nanosecond timestamp must parse and fall inside its window")
	}
	before := Window{From: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)}
	if hitInWindow(h.Timestamp, before) {
		t.Fatal("real parsing required: 2017 timestamp must fall outside a 2020 window")
	}
}

// Legacy fallback: NDJSON lines with a text banner are still accepted.
func TestParseChainsawNDJSONFallback(t *testing.T) {
	fixture := "chainsaw v1.x banner\n" +
		`{"timestamp":"2026-11-22T06:00:00Z","name":"Rule A","level":"medium","tags":["attack.t1003.003"]}` + "\n" +
		"\n"
	hits, err := parseChainsawOutput([]byte(fixture))
	if err != nil {
		t.Fatalf("ndjson parse: %v", err)
	}
	if len(hits) != 1 || hits[0].Name != "Rule A" {
		t.Fatalf("want 1 NDJSON hit, got %+v", hits)
	}
}
