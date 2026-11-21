// Package lab implements the Lab Orchestrator (design §5.7): bringing the
// bundled practice range up/down per profile and reporting its health via
// `docker compose`. The orchestrator never makes run-scoped decisions.
package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ServiceHealth is one container's state as reported by `docker compose ps`.
type ServiceHealth struct {
	Name   string `json:"Name"`
	State  string `json:"State"`
	Health string `json:"Health"`
}

// Health is the aggregate health of a profile.
type Health struct {
	Profile  string          `json:"profile"`
	Healthy  bool            `json:"healthy"`
	Services []ServiceHealth `json:"services"`
	Detail   string          `json:"detail,omitempty"`
}

// Runner executes a command with the given working directory and returns
// combined output and an error. Injectable for tests.
type Runner func(ctx context.Context, dir string, args ...string) (string, error)

// WarmupStep is a post-Up initialization probe against a freshly started
// lab service — provisioning belongs to the orchestrator, not to
// engagements (e.g. VAmPI's /createdb must run before any user probe can
// succeed; found live in M2).
type WarmupStep struct {
	Name string
	URL  string
}

// ComposeOrchestrator drives `docker compose` per profile.
type ComposeOrchestrator struct {
	// LabRoot is the directory containing the compose files (default "lab").
	LabRoot string
	// Profiles maps a profile name to its compose file name.
	Profiles map[string]string
	// Runner is the command runner (default: exec docker compose).
	Runner Runner
	// Warmups are post-Up initialization steps per profile. Nil skips
	// warmup entirely (tests, profiles without provisioning needs).
	Warmups map[string][]WarmupStep
	// WarmupClient is injectable for tests; the default client bypasses
	// ambient proxies explicitly (Transport.Proxy = nil).
	WarmupClient *http.Client
}

const upTimeout = 15 * time.Minute
const statusTimeout = 1 * time.Minute

func New(labRoot string) *ComposeOrchestrator {
	return &ComposeOrchestrator{
		LabRoot: labRoot,
		Profiles: map[string]string{
			"lite":    "compose.lite.yaml",
			"zero-vm": "compose.zero-vm.yaml",
			// "full" lands with M4 (GOAD-Light VM layer); refused until then.
		},
		Runner: dockerComposeRunner,
		Warmups: map[string][]WarmupStep{
			"lite": {
				// VAmPI's SQLite schema exists only after /createdb; without
				// it every user probe 500s ("no such table: users").
				{Name: "vampi-createdb", URL: "http://127.0.0.1:5002/createdb"},
				// DVWA first-deploy setup page (GET warms it; full table
				// creation via the wizard stays manual for M4 VM labs).
				{Name: "dvwa-setup-page", URL: "http://127.0.0.1:4280/setup.php"},
			},
		},
		WarmupClient: &http.Client{
			Transport: &http.Transport{Proxy: nil},
			Timeout:   15 * time.Second,
		},
	}
}

func dockerComposeRunner(ctx context.Context, dir string, args ...string) (string, error) {
	full := append([]string{"compose"}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (o *ComposeOrchestrator) fileFor(profile string) (string, error) {
	f, ok := o.Profiles[profile]
	if !ok {
		return "", fmt.Errorf("lab: unknown profile %q (known: lite, zero-vm)", profile)
	}
	// Absolute: the runner's working directory is LabRoot, so a relative -f
	// would double the path prefix.
	p, err := filepath.Abs(filepath.Join(o.LabRoot, f))
	if err != nil {
		return "", fmt.Errorf("lab: resolve %s: %w", f, err)
	}
	return p, nil
}

func (o *ComposeOrchestrator) baseArgs(profile, file string) []string {
	return []string{"--project-name", "hesper-lab-" + profile, "-f", file}
}

// Up brings the profile up in detached mode and waits until every service
// is healthy (compose --wait). Returns an error when unhealthy.
func (o *ComposeOrchestrator) Up(ctx context.Context, profile string) (Health, error) {
	file, err := o.fileFor(profile)
	if err != nil {
		return Health{}, err
	}
	cctx, cancel := context.WithTimeout(ctx, upTimeout)
	defer cancel()
	args := append(o.baseArgs(profile, file), "up", "-d", "--wait")
	if out, err := o.Runner(cctx, o.LabRoot, args...); err != nil {
		return Health{Profile: profile, Detail: out},
			fmt.Errorf("lab: up %s failed: %w\n%s", profile, err, out)
	}
	h, err := o.Status(ctx, profile)
	if err != nil {
		return h, err
	}
	if !h.Healthy {
		return h, fmt.Errorf("lab: profile %q did not come up healthy (%s)", profile, h.Detail)
	}
	if err := o.runWarmups(profile); err != nil {
		h.Detail = strings.TrimSpace(h.Detail + "; warmup: " + err.Error())
		return h, fmt.Errorf("lab: warmup failed: %w", err)
	}
	return h, nil
}

// runWarmups executes the profile's post-Up initialization probes with
// retries. Provisioning failures fail the Up loudly — downstream engagements
// would otherwise fail confusingly mid-run.
func (o *ComposeOrchestrator) runWarmups(profile string) error {
	steps := o.Warmups[profile]
	if len(steps) == 0 {
		return nil
	}
	client := o.WarmupClient
	if client == nil {
		client = &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 15 * time.Second}
	}
	for _, s := range steps {
		var lastErr error
		ok := false
		for attempt := 0; attempt < 3 && !ok; attempt++ {
			if attempt > 0 {
				time.Sleep(2 * time.Second)
			}
			resp, err := client.Get(s.URL)
			if err != nil {
				lastErr = err
				continue
			}
			drainAndClose(resp)
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				ok = true
				continue
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if !ok {
			return fmt.Errorf("%s (%s): %w", s.Name, s.URL, lastErr)
		}
	}
	return nil
}

func drainAndClose(resp *http.Response) {
	if resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// Down tears the profile down. State under lab/state/ (bind-mount trees and
// named volumes' disk content) is preserved by design.
func (o *ComposeOrchestrator) Down(ctx context.Context, profile string) error {
	file, err := o.fileFor(profile)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	args := append(o.baseArgs(profile, file), "down")
	if out, err := o.Runner(cctx, o.LabRoot, args...); err != nil {
		return fmt.Errorf("lab: down %s failed: %w\n%s", profile, err, out)
	}
	return nil
}

// Status reports per-service state/health and an aggregate verdict.
// Services with a healthcheck must report "healthy" to count toward health.
func (o *ComposeOrchestrator) Status(ctx context.Context, profile string) (Health, error) {
	file, err := o.fileFor(profile)
	if err != nil {
		return Health{}, err
	}
	cctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	args := append(o.baseArgs(profile, file), "ps", "--format", "json", "--all")
	out, err := o.Runner(cctx, o.LabRoot, args...)
	if err != nil {
		return Health{Profile: profile, Detail: out},
			fmt.Errorf("lab: status %s failed: %w\n%s", profile, err, out)
	}
	services := parseComposePS(out)
	h := Health{Profile: profile, Services: services}
	if len(services) == 0 {
		h.Detail = "no containers found (profile is down)"
		return h, nil
	}
	unhealthy := []string{}
	for _, s := range services {
		if s.State != "running" {
			unhealthy = append(unhealthy, fmt.Sprintf("%s: state=%s", s.Name, s.State))
			continue
		}
		if s.Health != "" && s.Health != "healthy" {
			unhealthy = append(unhealthy, fmt.Sprintf("%s: health=%s", s.Name, s.Health))
		}
	}
	h.Healthy = len(unhealthy) == 0
	h.Detail = strings.Join(unhealthy, "; ")
	return h, nil
}

// parseComposePS handles both output shapes of `docker compose ps --format json`:
// a JSON array (current compose) or newline-delimited objects (older builds).
func parseComposePS(out string) []ServiceHealth {
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	var fromArray []ServiceHealth
	if strings.HasPrefix(out, "[") {
		if err := json.Unmarshal([]byte(out), &fromArray); err == nil {
			return fromArray
		}
	}
	var services []ServiceHealth
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var s ServiceHealth
		if err := json.Unmarshal([]byte(line), &s); err == nil && s.Name != "" {
			services = append(services, s)
		}
	}
	return services
}

// EnsureHealthy is the INIT gate helper (design §5.7): run modes must refuse
// to start unless the config-declared profile is healthy. The run loop
// (M3) calls this at INIT.
func (o *ComposeOrchestrator) EnsureHealthy(ctx context.Context, profile string) error {
	h, err := o.Status(ctx, profile)
	if err != nil {
		return err
	}
	if !h.Healthy {
		return fmt.Errorf("lab: profile %q is not healthy (%s) — run `hesper lab up --profile %s` first", profile, h.Detail, profile)
	}
	return nil
}
