package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/JimMir45/hesper/internal/findings"
)

// runState is the persisted, resumable state of a run (design §3): the
// state machine position plus the accounting a resume must inherit —
// budget spent, quarantine, planner calls. A resume never mints budget and
// never forgets a quarantine.
type runState struct {
	RunID        string   `json:"run_id"`
	Mode         string   `json:"mode"`
	State        string   `json:"state"`
	Turn         int      `json:"turn"`
	Executed     int      `json:"executed"`
	BudgetUsed   int      `json:"budget_used"`
	Deadline     string   `json:"budget_deadline"`
	Quarantine   []string `json:"quarantine,omitempty"`
	PlannerCalls int      `json:"planner_calls"`
	StartedUTC   string   `json:"started_utc"`
	UpdatedUTC   string   `json:"updated_utc"`
}

// Started parses the persisted start time (zero time when unparsable).
func (s *runState) Started() time.Time {
	t, _ := time.Parse(time.RFC3339, s.StartedUTC)
	return t
}

func statePath(runDir string) string      { return filepath.Join(runDir, "state", "state.json") }
func outcomesPath(runDir string) string   { return filepath.Join(runDir, "state", "outcomes.json") }

// loadOrCreateState reads state.json, or creates a fresh one. Fresh runs
// inherit nothing; resumed runs keep StartedUTC and accounting. Fields the
// prior session never wrote (e.g. a run stopped at turn 0 keeps no deadline)
// are merged from Options — never zero-valued garbage.
func loadOrCreateState(o Options, runDirAbs string) (*runState, error) {
	b, err := os.ReadFile(statePath(runDirAbs))
	if err == nil {
		var st runState
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, err
		}
		if st.RunID == "" {
			st.RunID = o.RunID
		}
		if st.Mode == "" {
			st.Mode = string(o.Scope.Mode)
		}
		if st.StartedUTC == "" {
			st.StartedUTC = o.StartedUTC.UTC().Format(time.RFC3339)
		}
		return &st, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	used, deadline := o.Budget.Dump()
	st := &runState{
		RunID:      o.RunID,
		Mode:       string(o.Scope.Mode),
		State:      "INIT",
		BudgetUsed: used,
		Deadline:   deadline.UTC().Format(time.RFC3339),
		StartedUTC: o.StartedUTC.UTC().Format(time.RFC3339),
	}
	if err := persistState(st, runDirAbs); err != nil {
		return nil, err
	}
	return st, nil
}

// setState transitions the persisted state machine position.
func setState(st *runState, state, runDirAbs string) {
	st.State = state
	_ = persistState(st, runDirAbs)
}

func persistState(st *runState, runDirAbs string) error {
	st.UpdatedUTC = time.Now().UTC().Format(time.RFC3339)
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(statePath(runDirAbs)), 0o755); err != nil {
		return err
	}
	return os.WriteFile(statePath(runDirAbs), b, 0o644)
}

// loadOutcomes restores previously accumulated outcomes (resume path).
func loadOutcomes(runDirAbs string) ([]findings.Outcome, error) {
	b, err := os.ReadFile(outcomesPath(runDirAbs))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []findings.Outcome
	return out, json.Unmarshal(b, &out)
}

func persistOutcomes(out []findings.Outcome, runDirAbs string) error {
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outcomesPath(runDirAbs)), 0o755); err != nil {
		return err
	}
	return os.WriteFile(outcomesPath(runDirAbs), b, 0o644)
}
