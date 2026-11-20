package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "run.config.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

func TestLoadExampleFixture(t *testing.T) {
	c, err := LoadRunConfig("../../schemas/v0/run.config.example.json")
	if err != nil {
		t.Fatalf("example fixture must load: %v", err)
	}
	if c.Model == nil || c.Model.Provider != "openai_compatible" {
		t.Fatalf("example model not parsed: %+v", c.Model)
	}
	if c.Judge.Mode != "offline" || c.Judge.CorrelationWindowS != 120 {
		t.Fatalf("judge not parsed: %+v", c.Judge)
	}
	if c.Planner.MaxProposalsPerTurn != 3 || c.Planner.Temperature == nil || *c.Planner.Temperature != 0 {
		t.Fatalf("planner defaults/values wrong: %+v", c.Planner)
	}
}

func TestDefaultsApplied(t *testing.T) {
	c, err := LoadRunConfig(writeConfig(t, `{"version":"0.1"}`))
	if err != nil {
		t.Fatalf("minimal config: %v", err)
	}
	if c.Planner.MaxProposalsPerTurn != 3 {
		t.Fatalf("max_proposals_per_turn default = %d, want 3", c.Planner.MaxProposalsPerTurn)
	}
	if c.Planner.Temperature == nil || *c.Planner.Temperature != 0 {
		t.Fatalf("temperature default must be 0")
	}
	if c.Planner.MaxContextTokens != 32000 {
		t.Fatalf("max_context_tokens default = %d, want 32000", c.Planner.MaxContextTokens)
	}
	if c.Judge.Mode != "auto" || c.Judge.CorrelationWindowS != 120 {
		t.Fatalf("judge defaults wrong: %+v", c.Judge)
	}
}

func TestDefaultRunConfigHasDefaults(t *testing.T) {
	c := DefaultRunConfig()
	if c.Judge.Mode != "auto" || c.Judge.CorrelationWindowS != 120 {
		t.Fatalf("DefaultRunConfig missing judge defaults: %+v", c.Judge)
	}
	if c.Planner.MaxProposalsPerTurn != 3 {
		t.Fatalf("DefaultRunConfig missing planner defaults: %+v", c.Planner)
	}
}

func TestValidateFailures(t *testing.T) {
	cases := map[string]string{
		"missing version":        `{}`,
		"unknown major version":  `{"version":"1.0"}`,
		"invalid provider":       `{"version":"0.1","model":{"provider":"telegram","model":"m","api_key_env":"K"}}`,
		"openai needs endpoint":  `{"version":"0.1","model":{"provider":"openai_compatible","model":"m","api_key_env":"K"}}`,
		"missing api_key_env":    `{"version":"0.1","model":{"provider":"anthropic","model":"m"}}`,
		"api key value in file":  `{"version":"0.1","model":{"provider":"anthropic","model":"m","api_key_env":"sk-live-secret"}}`,
		"bad env name format":    `{"version":"0.1","model":{"provider":"anthropic","model":"m","api_key_env":"lowercase-name"}}`,
		"missing model name":     `{"version":"0.1","model":{"provider":"anthropic","api_key_env":"K"}}`,
		"invalid judge mode":     `{"version":"0.1","judge":{"mode":"psychic"}}`,
		"anthropic ok (control)": "INVALID_MARKER",
	}
	for name, body := range cases {
		if name == "anthropic ok (control)" {
			continue
		}
		if _, err := LoadRunConfig(writeConfig(t, body)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestAnthropicWithoutEndpointIsValid(t *testing.T) {
	if _, err := LoadRunConfig(writeConfig(t, `{"version":"0.1","model":{"provider":"anthropic","model":"claude-haiku-5-5","api_key_env":"ANTHROPIC_API_KEY"}}`)); err != nil {
		t.Fatalf("anthropic without endpoint must be valid: %v", err)
	}
}
