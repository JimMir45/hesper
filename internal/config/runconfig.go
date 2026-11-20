// Package config implements the run.config contract (design §4.5): the
// operational settings of a run — model, planner, judge, budgets — kept
// strictly separate from scope (authorization).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// VersionMajor is the only accepted major version of the run.config
// contract. Readers refuse unknown majors (fail-closed).
const VersionMajor = "0"

// RunConfig is the resolved operational configuration of a run.
type RunConfig struct {
	Version string      `json:"version"`
	Model   *Model      `json:"model,omitempty"`
	Planner PlannerCfg  `json:"planner,omitempty"`
	Judge   JudgeCfg    `json:"judge,omitempty"`
	Budgets *CallBudgets `json:"budgets,omitempty"`
}

// Model describes the planner's model access. The API key is referenced by
// environment variable NAME only — a key value must never appear in files.
type Model struct {
	Provider  string   `json:"provider"` // openai_compatible | anthropic
	Endpoint  string   `json:"endpoint,omitempty"`
	Model     string   `json:"model"`
	APIKeyEnv string   `json:"api_key_env"`
	Fallback  []string `json:"fallback,omitempty"`
}

// PlannerCfg bounds planner behavior.
type PlannerCfg struct {
	MaxProposalsPerTurn int      `json:"max_proposals_per_turn,omitempty"`
	Temperature         *float64 `json:"temperature,omitempty"`
	MaxContextTokens    int      `json:"max_context_tokens,omitempty"`
}

// JudgeCfg selects the detection-judge path.
type JudgeCfg struct {
	Mode               string   `json:"mode,omitempty"` // auto | velociraptor | offline
	CorrelationWindowS int      `json:"correlation_window_s,omitempty"`
	Velociraptor       *VeloCfg `json:"velociraptor,omitempty"`
}

type VeloCfg struct {
	URL       string `json:"url,omitempty"`
	APIKeyEnv string `json:"api_key_env,omitempty"`
}

// CallBudgets bounds planner calls, separate from the scope action budget.
type CallBudgets struct {
	MaxPlannerCalls  int `json:"max_planner_calls,omitempty"`
	MaxPlannerTokens int `json:"max_planner_tokens,omitempty"`
}

var envNameRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// DefaultRunConfig returns the validated default configuration used when no
// run.config file is supplied.
func DefaultRunConfig() *RunConfig {
	c := &RunConfig{Version: "0.1"}
	c.applyDefaults()
	return c
}

// LoadRunConfig reads, defaults, and validates a run.config file.
func LoadRunConfig(path string) (*RunConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("run.config: read %s: %w", path, err)
	}
	var c RunConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("run.config: parse %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("run.config: %s: %w", path, err)
	}
	return &c, nil
}

func (c *RunConfig) applyDefaults() {
	if c.Planner.MaxProposalsPerTurn == 0 {
		c.Planner.MaxProposalsPerTurn = 3
	}
	if c.Planner.Temperature == nil {
		zero := 0.0
		c.Planner.Temperature = &zero
	}
	if c.Planner.MaxContextTokens == 0 {
		c.Planner.MaxContextTokens = 32000
	}
	if c.Judge.Mode == "" {
		c.Judge.Mode = "auto"
	}
	if c.Judge.CorrelationWindowS == 0 {
		c.Judge.CorrelationWindowS = 120
	}
}

// Validate enforces contract invariants. Fail-closed: unknown structure is
// refused rather than ignored.
func (c *RunConfig) Validate() error {
	if c.Version == "" {
		return fmt.Errorf("version is required")
	}
	if major := versionMajor(c.Version); major != VersionMajor {
		return fmt.Errorf("unsupported contract major version %q (supported: %s.x)", c.Version, VersionMajor)
	}
	if c.Model != nil {
		m := c.Model
		switch m.Provider {
		case "openai_compatible":
			if m.Endpoint == "" {
				return fmt.Errorf("model.endpoint is required for provider openai_compatible")
			}
		case "anthropic":
			// endpoint optional (official default)
		default:
			return fmt.Errorf("model.provider must be openai_compatible|anthropic, got %q", m.Provider)
		}
		if m.Model == "" {
			return fmt.Errorf("model.model is required")
		}
		if !envNameRe.MatchString(m.APIKeyEnv) {
			return fmt.Errorf("model.api_key_env must be an environment variable NAME (got %q); API keys never live in files", m.APIKeyEnv)
		}
	}
	if c.Judge.Mode != "" && c.Judge.Mode != "auto" && c.Judge.Mode != "velociraptor" && c.Judge.Mode != "offline" {
		return fmt.Errorf("judge.mode must be auto|velociraptor|offline, got %q", c.Judge.Mode)
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
