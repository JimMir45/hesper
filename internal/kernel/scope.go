// Package kernel implements Hesper's fail-closed governance core: scope
// manifests, authorization gates, budgets, and the append-only audit log.
//
// Design contract: docs/design.md §7. The kernel never plans and never
// executes; it only permits or denies, and records.
package kernel

import (
	"encoding/json"
	"fmt"
	"os"
)

// Mode selects the engagement objective of a run.
type Mode string

const (
	ModeValidate Mode = "validate"
	ModePentest  Mode = "pentest"
)

// ScopeManifest is the authorization contract for a run.
// Everything not explicitly allowed is denied (fail-closed).
type ScopeManifest struct {
	Version        string    `json:"version"`
	Mode           Mode      `json:"mode"`
	Name           string    `json:"name,omitempty"`
	Targets        []Target  `json:"targets"`
	Allow          Allow     `json:"allow"`
	Deny           []string  `json:"deny,omitempty"`
	Budget         Budget    `json:"budget"`
	StopConditions []string  `json:"stop_conditions,omitempty"`
}

// Target is one authorized destination. kind is "host" | "cidr" | "domain".
type Target struct {
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
}

// Allow lists what the scope permits. Empty technique/class lists deny all
// techniques (fail-closed), regardless of other settings.
type Allow struct {
	TechniqueIDs []string `json:"technique_ids,omitempty"`
	Classes      []string `json:"classes,omitempty"`
	Adapters     []string `json:"adapters"`
}

// Budget holds hard run limits.
type Budget struct {
	MaxActions int `json:"max_actions"`
	MaxMinutes int `json:"max_minutes"`
}

// TargetInScope reports whether a bare host/IP is an authorized target —
// the same fail-closed matching the authorization gate uses (design §5.3:
// adapters egress only toward in-scope targets; the egress guard reuses it).
func (m *ScopeManifest) TargetInScope(target string) bool {
	return m.targetAllowed(target)
}

// LoadScope reads and validates a scope manifest from a JSON file.
func LoadScope(path string) (*ScopeManifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scope: read %s: %w", path, err)
	}
	var m ScopeManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("scope: parse %s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("scope: %s: %w", path, err)
	}
	return &m, nil
}

// Validate enforces structural invariants of a manifest.
func (m *ScopeManifest) Validate() error {
	if m.Version == "" {
		return fmt.Errorf("version is required")
	}
	if m.Mode != ModeValidate && m.Mode != ModePentest {
		return fmt.Errorf("mode must be %q or %q, got %q", ModeValidate, ModePentest, m.Mode)
	}
	if len(m.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}
	for i, t := range m.Targets {
		switch t.Kind {
		case "host", "cidr", "domain":
			if t.Value == "" {
				return fmt.Errorf("target[%d]: value is required", i)
			}
		default:
			return fmt.Errorf("target[%d]: kind must be host|cidr|domain, got %q", i, t.Kind)
		}
	}
	if len(m.Allow.Adapters) == 0 {
		return fmt.Errorf("allow.adapters must not be empty (fail-closed)")
	}
	for _, a := range m.Allow.Adapters {
		if a != "lib" && a != "proc" && a != "vm" {
			return fmt.Errorf("allow.adapters: unknown adapter %q", a)
		}
	}
	if m.Budget.MaxActions <= 0 || m.Budget.MaxMinutes <= 0 {
		return fmt.Errorf("budget.max_actions and budget.max_minutes must be positive")
	}
	return nil
}
