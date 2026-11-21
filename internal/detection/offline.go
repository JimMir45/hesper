package detection

import (
	"bufio"
	"encoding/json"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/JimMir45/hesper/internal/findings"
)

// OfflineJudge is the offline detection path (design §5.5): it runs the
// chainsaw binary (the same engine as the zero-vm profile, license layer
// "external": invoked as a process, never linked) over exported EVTX and
// parses its NDJSON hit stream.
//
// chainsaw NDJSON contract (one object per line, fields we consume):
//
//	{"timestamp":"2026-11-21T10:00:00Z","name":"<rule title>",
//	 "level":"high","tags":["attack.t1003.003"],"path":"..."}
//
// `name` is the rule identifier shared with the RuleIndex and the cards'
// detection.expected_sigma entries. Live-shape verification against a real
// chainsaw run is on the M4 live checklist (docs/m4-live-checklist.md).
type OfflineJudge struct {
	ChainsawPath string // resolved binary path (LookPath result or absolute)
	SamplesDir   string // exported EVTX (or the EVTX-ATTACK-SAMPLES set)
	RulesDir     string // Sigma rules directory
	MappingPath  string // sigma event-logs mapping (as in compose.zero-vm)
	Index        RuleIndex

	// CommandContext is injectable for tests; defaults to exec.CommandContext.
	CommandContext func(ctx context.Context, name string, args ...string) *exec.Cmd
}

// argv returns the strict argv — no shell, fixed order.
func (o *OfflineJudge) argv() []string {
	argv := []string{o.ChainsawPath, "hunt", o.SamplesDir, "-s", o.RulesDir, "--json"}
	if o.MappingPath != "" {
		argv = append(argv, "--mapping", o.MappingPath)
	}
	return argv
}

type chainsawHit struct {
	Timestamp string   `json:"timestamp"`
	Name      string   `json:"name"`
	Level     string   `json:"level"`
	Tags      []string `json:"tags"`
	Path      string   `json:"path"`
}

// Correlate runs chainsaw and returns hits whose ATT&CK tag intersects one
// of the referenced actions' technique ids and whose timestamp falls inside
// the window. Rules missing from the index are a hard attribution error.
func (o *OfflineJudge) Correlate(ctx context.Context, w Window, refs []ActionRef) ([]findings.Hit, error) {
	if o.CommandContext == nil {
		o.CommandContext = exec.CommandContext
	}
	cmd := o.CommandContext(ctx, o.argv()[0], o.argv()[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("offline judge: chainsaw: %v: %s", err, strings.TrimSpace(stderr.String()))
	}

	want := map[string]bool{}
	for _, r := range refs {
		want[strings.ToLower(strings.TrimSpace(r.AttackID))] = true
	}

	counts := map[string]*findings.Hit{}
	sc := bufio.NewScanner(&stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var h chainsawHit
		if err := json.Unmarshal(line, &h); err != nil {
			continue // non-JSON line (chainsaw banner): skip
		}
		if h.Name == "" {
			continue
		}
		if !hitInWindow(h.Timestamp, w) {
			continue
		}
		tagged := false
		for _, t := range h.Tags {
			id := strings.TrimPrefix(strings.ToLower(t), "attack.")
			if want[id] {
				tagged = true
				break
			}
		}
		if !tagged {
			continue
		}
		if existing, ok := counts[h.Name]; ok {
			existing.Matches++
			continue
		}
		meta, ok := o.Index[h.Name]
		if !ok || meta.Author == "" {
			return nil, fmt.Errorf("offline judge: rule %q missing attribution in rule index (DRL-1.1 fail-closed)", h.Name)
		}
		counts[h.Name] = &findings.Hit{RuleID: h.Name, Author: meta.Author, Level: meta.Level, Matches: 1}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("offline judge: scan: %w", err)
	}

	hits := make([]findings.Hit, 0, len(counts))
	for name := range counts {
		hits = append(hits, *counts[name])
	}
	// Deterministic order for goldens.
	sortHits(hits)
	return hits, nil
}

func hitInWindow(ts string, w Window) bool {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		// Unparseable timestamps count as in-window: never let a broken
		// timestamp silently suppress a detection.
		return true
	}
	return !t.Before(w.From) && !t.After(w.To)
}

func sortHits(hits []findings.Hit) {
	for i := 1; i < len(hits); i++ {
		for j := i; j > 0 && hits[j].RuleID < hits[j-1].RuleID; j-- {
			hits[j], hits[j-1] = hits[j-1], hits[j]
		}
	}
}
