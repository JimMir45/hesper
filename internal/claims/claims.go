// Package claims implements the verify-claims harness (design §8.5): every
// public, machine-checkable assertion about Hesper lives in claims.json and
// is re-verified by `hesper claims verify` — README numbers must trace to a
// green claim, never to prose.
package claims

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// Tiers: "ci" claims run everywhere (unit-test backed, no lab, no network);
// "live" claims need the bundled lab and are skipped unless --with-live.
const (
	TierCI   = "ci"
	TierLive = "live"
)

// Claim is one machine-checkable assertion.
type Claim struct {
	ID      string `json:"id"`
	Text    string `json:"claim"`  // the human sentence being asserted
	Command string `json:"command"` // run with sh -c at the claims file's directory
	Tier    string `json:"tier"`   // ci | live (default ci)
}

// File is the claims.json document.
type File struct {
	Version string  `json:"version"`
	Claims  []Claim `json:"claims"`
}

// Result is one claim's verification outcome.
type Result struct {
	Claim
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped"`
	Output  string `json:"output,omitempty"`
}

// Load reads a claims file.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("claims: parse %s: %w", path, err)
	}
	for i := range f.Claims {
		c := &f.Claims[i]
		if c.ID == "" || c.Command == "" {
			return nil, fmt.Errorf("claims: entry %d missing id or command", i)
		}
		if c.Tier == "" {
			c.Tier = TierCI
		}
		if c.Tier != TierCI && c.Tier != TierLive {
			return nil, fmt.Errorf("claims: %s: tier must be ci|live, got %q", c.ID, c.Tier)
		}
	}
	return &f, nil
}

// Runner executes one claim command; injectable for tests.
type Runner func(command string, dir string) (exitCode int, output string, err error)

// ExecRunner runs commands with sh -c in dir.
func ExecRunner() Runner {
	return func(command, dir string) (int, string, error) {
		cmd := exec.Command("sh", "-c", command)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
			err = nil // a non-zero exit is a claim result, not a harness error
		}
		return code, string(out), err
	}
}

// Verify runs every claim. Skipped claims (live tier without withLive) are
// not failures. A claim passes when its command exits 0.
func Verify(path string, withLive bool, run Runner) ([]Result, error) {
	f, err := Load(path)
	if err != nil {
		return nil, err
	}
	var out []Result
	for _, c := range f.Claims {
		res := Result{Claim: c}
		if c.Tier == TierLive && !withLive {
			res.Skipped = true
			out = append(out, res)
			continue
		}
		code, output, rerr := run(c.Command, dirOf(path))
		if rerr != nil {
			return nil, fmt.Errorf("claims: %s: %w", c.ID, rerr)
		}
		res.OK = code == 0
		res.Output = trimOutput(output)
		out = append(out, res)
	}
	return out, nil
}

// Summary formats the green/red/skip list; returns false if any claim failed.
func Summary(results []Result) (string, bool) {
	allOK := true
	s := ""
	for _, r := range results {
		switch {
		case r.Skipped:
			s += fmt.Sprintf("[skip] %s (live tier; --with-live to run)\n", r.ID)
		case r.OK:
			s += fmt.Sprintf("[pass] %s — %s\n", r.ID, r.Text)
		default:
			allOK = false
			s += fmt.Sprintf("[FAIL] %s — %s\n       %s\n", r.ID, r.Text, firstLines(r.Output, 4))
		}
	}
	passed, failed, skipped := 0, 0, 0
	for _, r := range results {
		switch {
		case r.Skipped:
			skipped++
		case r.OK:
			passed++
		default:
			failed++
		}
	}
	s += fmt.Sprintf("%d passed, %d failed, %d skipped\n", passed, failed, skipped)
	return s, allOK
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}

func trimOutput(s string) string {
	if len(s) > 4000 {
		return s[:4000] + "…"
	}
	return s
}

func firstLines(s string, n int) string {
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			count++
			if count >= n {
				return s[:i]
			}
		}
	}
	return s
}
