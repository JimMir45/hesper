package detection

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/JimMir45/hesper/internal/findings"
)

// runFakeVelo returns a CommandContext whose output is a controlled fixture
// via the real "printf" binary (deterministic, dependency-free — same trick
// as the chainsaw fakes). argv is captured for strictness assertions.
func runFakeVelo(fixture string) (func(ctx context.Context, name string, args ...string) *exec.Cmd, *sync.Mutex, *[]string) {
	var mu sync.Mutex
	var calls []string
	factory := func(ctx context.Context, name string, args ...string) *exec.Cmd {
		mu.Lock()
		calls = append(append([]string{name}, args...))
		mu.Unlock()
		return exec.CommandContext(ctx, "printf", "%s", fixture)
	}
	return factory, &mu, &calls
}

func runFailingVelo() func(ctx context.Context, name string, args ...string) *exec.Cmd {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "echo velo-down >&2; exit 3")
	}
}

// Live-verified CLI response shape: one JSON array of row objects.
const veloArrayFixture = `[
 {"rule":"Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)","author":"Thomas Patzke","level":"medium","attack":"t1003.003","count":3,"timestamp":"2026-11-21T10:00:10Z"},
 {"rule":"Suspicious Process Patterns NTDS.DIT Exfil","author":"","level":"","attack":"t1003.003","count":1,"timestamp":"2026-11-21T10:00:20Z"}
]`

func TestVelociraptorJudgeContract(t *testing.T) {
	t.Setenv("HESPER_VELO_CFG", "/opt/hesper/velo-api-client.yaml")
	factory, mu, calls := runFakeVelo(veloArrayFixture)
	client := &VeloClient{BinaryPath: "velociraptor", APIConfigEnv: "HESPER_VELO_CFG", CommandContext: factory}
	if !client.Health(context.Background()) {
		t.Fatal("health must be true when the CLI query succeeds")
	}

	j := &VelociraptorJudge{Client: client, Index: RuleIndex{
		"Suspicious Process Patterns NTDS.DIT Exfil": {Author: "Florian Roth (Nextron Systems)", Level: "high"},
	}}
	w := Window{From: ts("2026-11-21T10:00:00Z"), To: ts("2026-11-21T10:02:00Z")}
	refs := []ActionRef{{ID: "a1", AttackID: "T1003.003", TS: ts("2026-11-21T10:00:05Z")}}

	hits, err := j.Correlate(context.Background(), w, refs)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("want 2 hits, got %+v", hits)
	}

	mu.Lock()
	got := strings.Join(*calls, " ")
	mu.Unlock()
	if !strings.HasPrefix(got, "velociraptor -a /opt/hesper/velo-api-client.yaml query ") {
		t.Fatalf("argv must be strict (-a <cfg> query <vql>): %q", got)
	}
	if !strings.Contains(got, `"t1003.003"`) {
		t.Fatalf("VQL must filter on the technique join key: %q", got)
	}

	byRule := hitMap(hits)
	if byRule["Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)"].Matches != 3 {
		t.Fatalf("match count wrong: %+v", hits)
	}
	// Row without author falls back to the index (DRL-1.1).
	if byRule["Suspicious Process Patterns NTDS.DIT Exfil"].Author != "Florian Roth (Nextron Systems)" {
		t.Fatalf("index author fallback failed: %+v", hits)
	}
}

func TestVelociraptorConfigEnvFailClosed(t *testing.T) {
	client := &VeloClient{BinaryPath: "velociraptor", APIConfigEnv: "HESPER_VELO_CFG_MISSING"}
	if _, err := client.Query(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("query without the api-config env set must fail closed, not run unauthenticated")
	}
}

func TestVelociraptorJudgeAttributionFailClosed(t *testing.T) {
	t.Setenv("HESPER_VELO_CFG", "/opt/hesper/velo-api-client.yaml")
	factory, _, _ := runFakeVelo(`[{"rule":"Ghost Rule","attack":"t1003.003","count":1,"timestamp":"2026-11-21T10:00:10Z"}]`)
	j := &VelociraptorJudge{Client: &VeloClient{APIConfigEnv: "HESPER_VELO_CFG", CommandContext: factory}}
	w := Window{From: ts("2026-11-21T10:00:00Z"), To: ts("2026-11-21T10:02:00Z")}
	refs := []ActionRef{{ID: "a1", AttackID: "T1003.003", TS: ts("2026-11-21T10:00:05Z")}}
	if _, err := j.Correlate(context.Background(), w, refs); err == nil {
		t.Fatal("hit without any author source must be a hard error")
	}
}

func TestVelociraptorQuerySurfacesStderr(t *testing.T) {
	t.Setenv("HESPER_VELO_CFG", "/opt/hesper/velo-api-client.yaml")
	client := &VeloClient{APIConfigEnv: "HESPER_VELO_CFG", CommandContext: runFailingVelo()}
	_, err := client.Query(context.Background(), "SELECT 1")
	if err == nil || !strings.Contains(err.Error(), "velo-down") {
		t.Fatalf("CLI failure must surface stderr: %v", err)
	}
}

func TestAutoJudgePicksHealthyPath(t *testing.T) {
	t.Setenv("HESPER_VELO_CFG", "/opt/hesper/velo-api-client.yaml")
	onlineFactory, _, _ := runFakeVelo(`[{"rule":"Online Rule","author":"A","attack":"t1003.003","count":1,"timestamp":"2026-11-21T10:00:10Z"}]`)
	offline := offlineJudge(`{"timestamp":"2026-11-21T10:00:05Z","name":"Offline Rule","level":"high","tags":["attack.t1003.003"]}`)
	offline.Index = RuleIndex{"Offline Rule": {Author: "B"}}
	client := &VeloClient{APIConfigEnv: "HESPER_VELO_CFG", CommandContext: onlineFactory}
	auto := &AutoJudge{
		Online:  &VelociraptorJudge{Client: client},
		Offline: offline,
	}
	w := Window{From: ts("2026-11-21T10:00:00Z"), To: ts("2026-11-21T10:02:00Z")}
	refs := []ActionRef{{ID: "a1", AttackID: "T1003.003", TS: ts("2026-11-21T10:00:05Z")}}

	hits, err := auto.Correlate(context.Background(), w, refs)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if auto.LastPath() != "velociraptor" || len(hits) != 1 || hits[0].RuleID != "Online Rule" {
		t.Fatalf("online path not used: path=%s hits=%+v", auto.LastPath(), hits)
	}

	// CLI starts failing -> auto falls back offline.
	client.CommandContext = runFailingVelo()
	hits, err = auto.Correlate(context.Background(), w, refs)
	if err != nil {
		t.Fatalf("Correlate offline fallback: %v", err)
	}
	if auto.LastPath() != "offline" || len(hits) != 1 || hits[0].RuleID != "Offline Rule" {
		t.Fatalf("offline fallback not used: path=%s hits=%+v", auto.LastPath(), hits)
	}
}

func hitMap(hits []findings.Hit) map[string]findings.Hit {
	m := make(map[string]findings.Hit, len(hits))
	for _, h := range hits {
		m[h.RuleID] = h
	}
	return m
}
