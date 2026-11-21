// Package actions implements the Action Registry (design §5.2): loading,
// linting, and indexing action cards. The registry never executes anything.
//
// Lint rules are the license-layer contract from the selection research:
//   - provenance triple (source_repo, commit, license) is mandatory;
//   - reuse=external cards may only bind proc/vm executors (never linked);
//   - blocklisted projects (design §4.2) are refused outright.
package actions

import (
	"fmt"
	"strings"
)

// ContractMajor is the only accepted major version of the card contract.
const ContractMajor = "0"

// Provenance is the mandatory per-card source triple.
type Provenance struct {
	SourceRepo string `json:"source_repo"`
	Commit     string `json:"commit"`
	License    string `json:"license"`
}

// Attack maps the card to MITRE ATT&CK — the join key of the whole system.
type Attack struct {
	TechniqueID string `json:"technique_id"`
	Tactic      string `json:"tactic,omitempty"`
}

// Executor describes how the action runs. For proc/vm adapters, Argv is the
// strict argv template: "{params.NAME}" and "{target}" placeholders are
// substituted by the adapter; planner-supplied values never pass through a
// shell.
type Executor struct {
	Adapter string `json:"adapter"` // lib | proc | vm
	// Argv is the strict argv template (proc/vm). Never a shell line.
	Argv []string `json:"argv,omitempty"`
	// SuccessStdoutContains optionally narrows success: the executed command
	// must exit 0 AND stdout must contain this substring for the action to
	// count as succeeded (e.g. an HTTP status code echoed by curl -w).
	SuccessStdoutContains string `json:"success_stdout_contains,omitempty"`
}

// Preconditions match a card against the current StateView.
type Preconditions struct {
	Phase string   `json:"phase,omitempty"`
	OS    []string `json:"os,omitempty"`
	Ports []int    `json:"ports,omitempty"`
	Creds []string `json:"creds,omitempty"`
	Notes string   `json:"notes,omitempty"`
}

// EvidenceSpec declares the artifact kinds without which the action did not
// happen (design §4.4).
type EvidenceSpec struct {
	MustCapture []string `json:"must_capture"`
}

// DetectionSpec lists Sigma rule IDs that should fire if telemetry exists.
type DetectionSpec struct {
	ExpectedSigma []string `json:"expected_sigma,omitempty"`
}

// Card is one unit of the action vocabulary (design §4.2).
type Card struct {
	Version      string       `json:"version"`
	ID           string       `json:"id"`
	Title        string       `json:"title"`
	Attack       Attack       `json:"attack"`
	Provenance   Provenance   `json:"provenance"`
	Reuse        string       `json:"reuse"` // embedded | external | data_borrow
	Preconditions Preconditions `json:"preconditions,omitempty"`
	Executor     Executor     `json:"executor"`
	Evidence     EvidenceSpec `json:"evidence"`
	Detection    DetectionSpec `json:"detection,omitempty"`
	Risks        string       `json:"risks,omitempty"`
}

// blocklist carries the license-refused projects from the selection
// research; the check is a lint rule, not prose.
var blocklist = []string{
	"endgameinc/rta",          // AGPL-3.0 + unmaintained since 2019
	"peass-ng",                // custom COPYING: "executing and parsing output" = derivative
	"dmejo/sharpview",         // repository vanished (404)
	"offensive-security/exploitdb", // archived, GPL-2.0
	"exploitdb/exploitdb",
}

// Lint validates one card against the registry contract. The error text is
// planner- and CI-readable.
func (c *Card) Lint() error {
	if major := versionMajor(c.Version); major != ContractMajor {
		return fmt.Errorf("card %s: unsupported contract major version %q (supported: %s.x)", c.ID, c.Version, ContractMajor)
	}
	if c.ID == "" {
		return fmt.Errorf("card: id is required")
	}
	if c.Title == "" {
		return fmt.Errorf("card %s: title is required", c.ID)
	}
	if c.Attack.TechniqueID == "" {
		return fmt.Errorf("card %s: attack.technique_id is required", c.ID)
	}
	p := c.Provenance
	if p.SourceRepo == "" || p.Commit == "" || p.License == "" {
		return fmt.Errorf("card %s: provenance triple (source_repo, commit, license) is mandatory", c.ID)
	}
	low := strings.ToLower(p.SourceRepo)
	for _, b := range blocklist {
		if strings.Contains(low, b) {
			return fmt.Errorf("card %s: provenance source %q is on the license blocklist (%s)", c.ID, p.SourceRepo, b)
		}
	}
	switch c.Reuse {
	case "embedded", "external", "data_borrow":
	default:
		return fmt.Errorf("card %s: reuse must be embedded|external|data_borrow, got %q", c.ID, c.Reuse)
	}
	if c.Reuse == "external" && c.Executor.Adapter == "lib" {
		return fmt.Errorf("card %s: reuse=external cannot bind a lib executor (proc/vm only)", c.ID)
	}
	switch c.Executor.Adapter {
	case "lib", "proc", "vm":
	default:
		return fmt.Errorf("card %s: executor.adapter must be lib|proc|vm, got %q", c.ID, c.Executor.Adapter)
	}
	if c.Reuse == "external" && len(c.Executor.Argv) == 0 {
		return fmt.Errorf("card %s: external card must carry an argv binding", c.ID)
	}
	if len(c.Evidence.MustCapture) == 0 {
		return fmt.Errorf("card %s: evidence.must_capture is required (no capture = did not happen)", c.ID)
	}
	return nil
}

func versionMajor(v string) string {
	for i := 0; i < len(v); i++ {
		if v[i] == '.' {
			return v[:i]
		}
	}
	return v
}
