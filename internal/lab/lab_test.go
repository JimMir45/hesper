package lab

import (
	"context"
	"strings"
	"testing"
)

// fakeRunner captures the command and returns canned output.
func fakeRunner(out string, err error) (Runner, *[][]string) {
	captured := &[][]string{}
	return func(_ context.Context, _ string, args ...string) (string, error) {
		cp := make([]string, len(args))
		copy(cp, args)
		*captured = append(*captured, cp)
		return out, err
	}, captured
}

const psAllHealthy = `[
 {"Name":"hesper-vampi","State":"running","Health":"healthy"},
 {"Name":"hesper-dvwa","State":"running","Health":"healthy"},
 {"Name":"hesper-velociraptor","State":"running","Health":"healthy"}
]`

const psOneUnhealthy = `[
 {"Name":"hesper-vampi","State":"running","Health":"healthy"},
 {"Name":"hesper-dvwa","State":"restarting","Health":""}
]`

func TestUpBuildsCorrectArgsAndReportsHealthy(t *testing.T) {
	run, captured := fakeRunner(psAllHealthy, nil)
	o := &ComposeOrchestrator{LabRoot: "lab",
		Profiles: map[string]string{"lite": "compose.lite.yaml"}, Runner: run}

	h, err := o.Up(context.Background(), "lite")
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if !h.Healthy || len(h.Services) != 3 {
		t.Fatalf("health wrong: %+v", h)
	}

	args := (*captured)[0]
	joined := strings.Join(args, " ")
	for _, want := range []string{"--project-name", "hesper-lab-lite", "-f", "lab/compose.lite.yaml", "up", "-d", "--wait"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("up args missing %q: %v", want, args)
		}
	}
}

func TestUpFailsWhenUnhealthy(t *testing.T) {
	run, _ := fakeRunner(psOneUnhealthy, nil)
	o := &ComposeOrchestrator{LabRoot: "lab",
		Profiles: map[string]string{"lite": "compose.lite.yaml"}, Runner: run}

	h, err := o.Up(context.Background(), "lite")
	if err == nil {
		t.Fatal("Up must error when a service is unhealthy")
	}
	if h.Healthy {
		t.Fatalf("Health.Healthy must be false: %+v", h)
	}
	if !strings.Contains(h.Detail, "restarting") {
		t.Fatalf("Detail must name the unhealthy service: %q", h.Detail)
	}
}

func TestStatusParsesNDJSONFallback(t *testing.T) {
	ndjson := "{\"Name\":\"a\",\"State\":\"running\",\"Health\":\"healthy\"}\n{\"Name\":\"b\",\"State\":\"running\",\"Health\":\"healthy\"}\n"
	run, _ := fakeRunner(ndjson, nil)
	o := &ComposeOrchestrator{LabRoot: "lab",
		Profiles: map[string]string{"lite": "compose.lite.yaml"}, Runner: run}

	h, err := o.Status(context.Background(), "lite")
	if err != nil || !h.Healthy || len(h.Services) != 2 {
		t.Fatalf("NDJSON parse failed: %+v err=%v", h, err)
	}
}

func TestStatusEmptyMeansDown(t *testing.T) {
	run, _ := fakeRunner("", nil)
	o := &ComposeOrchestrator{LabRoot: "lab",
		Profiles: map[string]string{"lite": "compose.lite.yaml"}, Runner: run}

	h, err := o.Status(context.Background(), "lite")
	if err != nil {
		t.Fatalf("Status on down profile must not error: %v", err)
	}
	if h.Healthy || len(h.Services) != 0 {
		t.Fatalf("down profile: healthy=%v services=%d", h.Healthy, len(h.Services))
	}
}

func TestDownBuildsCorrectArgs(t *testing.T) {
	run, captured := fakeRunner("", nil)
	o := &ComposeOrchestrator{LabRoot: "lab",
		Profiles: map[string]string{"lite": "compose.lite.yaml"}, Runner: run}

	if err := o.Down(context.Background(), "lite"); err != nil {
		t.Fatalf("Down: %v", err)
	}
	joined := strings.Join((*captured)[0], " ")
	if !strings.Contains(joined, "down") || !strings.Contains(joined, "compose.lite.yaml") {
		t.Fatalf("down args wrong: %v", (*captured)[0])
	}
}

func TestUnknownProfileRefused(t *testing.T) {
	run, _ := fakeRunner("", nil)
	o := &ComposeOrchestrator{LabRoot: "lab",
		Profiles: map[string]string{"lite": "compose.lite.yaml"}, Runner: run}

	if _, err := o.Up(context.Background(), "full"); err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("unknown profile must be refused, got %v", err)
	}
}

func TestEnsureHealthyRefusesWhenDown(t *testing.T) {
	run, _ := fakeRunner("", nil)
	o := &ComposeOrchestrator{LabRoot: "lab",
		Profiles: map[string]string{"lite": "compose.lite.yaml"}, Runner: run}

	err := o.EnsureHealthy(context.Background(), "lite")
	if err == nil || !strings.Contains(err.Error(), "not healthy") {
		t.Fatalf("EnsureHealthy must refuse when down, got %v", err)
	}
}
