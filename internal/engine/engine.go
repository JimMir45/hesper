// Package engine implements the ENGAGE run loop (design §3): observe →
// propose → resolve → gate → spend → execute → update, with fail-closed
// governance throughout. Denials, budget exhaustion, and rejections are
// structured feedback to the planner — observations, never crashes. Budget
// exhaustion terminates gracefully toward DONE; the kill switch (ctx
// cancel, STOP file, or forced abort) drains and exits 130.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/JimMir45/hesper/internal/actions"
	"github.com/JimMir45/hesper/internal/adapters"
	"github.com/JimMir45/hesper/internal/config"
	"github.com/JimMir45/hesper/internal/detection"
	"github.com/JimMir45/hesper/internal/evidence"
	"github.com/JimMir45/hesper/internal/findings"
	"github.com/JimMir45/hesper/internal/kernel"
	"github.com/JimMir45/hesper/internal/planner"
	"github.com/JimMir45/hesper/internal/report"
)

// Terminal states (design §3).
const (
	TerminalDone    = "DONE"
	TerminalStopped = "STOPPED"
	TerminalAborted = "ABORTED"
)

// ExitKill is the kill-switch exit code (design §6).
const ExitKill = 130

// ExitEgressPolicy is the egress-violation policy stop exit code (design §6:
// AdapterEgressViolation count ≥3 ⇒ STOPPED, exit 1 — distinct from the kill
// switch's 130).
const ExitEgressPolicy = 1

const quarantineThreshold = 3 // consecutive failures before a card is quarantined for the run

// Options wires one run of the engine.
type Options struct {
	RunDir     string
	RunID      string
	Scope      *kernel.ScopeManifest
	Cfg        *config.RunConfig
	Registry   *actions.Registry
	Adapters   map[string]adapters.Adapter
	Planner    planner.Planner
	Audit      *kernel.AuditLog
	Chain      *evidence.Chain
	Budget     *kernel.Budgeter // pass kernel.RestoreBudgeter(...) output to resume
	StartedUTC time.Time        // zero = now; preserved on resume

	ActionTimeout    time.Duration // default 5m
	MaxEvidenceTail  int           // default 8
	// Judge, when non-nil, runs detection correlation over executed
	// outcomes in the CORRELATE phase (design §5.5); nil keeps the M3
	// behavior (findings without sigma attachment).
	Judge detection.Judge
	// ForceAbort, when closed, escalates a stop into ABORTED (second signal).
	ForceAbort <-chan struct{}
	// Egress is the violation monitor (design §6). Nil ⇒ default threshold.
	Egress *kernel.EgressMonitor
}

// Result is the run's outcome.
type Result struct {
	Terminal string // DONE | STOPPED | ABORTED
	ExitCode int    // 0 | 130
	Findings []findings.Finding
	Steps    []report.StepLine
	Turns    int
	Executed int
}

var paramsRef = regexp.MustCompile(`\{params\.([A-Za-z0-9_]+)\}`)

// Run drives the loop to a terminal state and writes findings.json/report.md
// (when the evidence chain verifies). It returns an error only for
// operational failures (design §6); graceful ends are results, not errors.
func Run(ctx context.Context, o Options) (*Result, error) {
	fillDefaults(&o)
	runDirAbs, err := filepath.Abs(o.RunDir)
	if err != nil {
		return nil, err
	}
	st, err := loadOrCreateState(o, runDirAbs)
	if err != nil {
		return nil, err
	}
	outcomes, err := loadOutcomes(runDirAbs)
	if err != nil {
		return nil, err
	}
	quarantine := map[string]bool{}
	for _, id := range st.Quarantine {
		quarantine[id] = true
	}
	failStreak := map[string]int{}

	stopFile := filepath.Join(runDirAbs, "state", "STOP")
	terminal := ""
	var steps []report.StepLine
	var lastFeedback []planner.Feedback
	budgetGone := false
	egressStopped := false
	if o.Egress == nil {
		o.Egress = kernel.NewEgressMonitor(0)
	}

	setState(st, "ENGAGE", runDirAbs)

	for {
		// Kill switch checks (design §5.1): forced abort > ctx cancel > STOP file.
		select {
		case <-o.ForceAbort:
			_ = o.Audit.Append("kill.requested", map[string]any{"source": "forced_abort"})
			terminal = TerminalAborted
		default:
		}
		if terminal == "" && ctx.Err() != nil {
			_ = o.Audit.Append("kill.requested", map[string]any{"source": "signal"})
			terminal = TerminalStopped
		}
		if terminal == "" {
			if _, err := os.Stat(stopFile); err == nil {
				_ = o.Audit.Append("kill.requested", map[string]any{"source": "stop_file"})
				// Consume the stop request: a later --resume of this run must
				// not immediately re-stop.
				_ = os.Remove(stopFile)
				terminal = TerminalStopped
			}
		}
		if terminal != "" {
			break
		}

		// Planner call budget (separate from the action budget, design §4.5).
		st.PlannerCalls++
		var maxPlannerCalls int
		if o.Cfg.Budgets != nil {
			maxPlannerCalls = o.Cfg.Budgets.MaxPlannerCalls
		}
		if maxPlannerCalls > 0 && st.PlannerCalls > maxPlannerCalls {
			_ = o.Audit.Append("planner.budget_exhausted", map[string]any{"calls": st.PlannerCalls - 1})
			break
		}

		// Observe.
		view := buildView(o, st, runDirAbs, lastFeedback)

		// Propose.
		proposals, err := o.Planner.Next(ctx, view)
		if err != nil {
			_ = o.Audit.Append("planner.error", map[string]any{"turn": st.Turn, "error": err.Error()})
			return nil, err
		}
		st.Turn++
		if len(proposals) == 0 {
			_ = o.Audit.Append("planner.converged", map[string]any{"turn": st.Turn})
			break
		}
		if max := o.Cfg.Planner.MaxProposalsPerTurn; max > 0 && len(proposals) > max {
			proposals = proposals[:max]
		}

		// Resolve → gate → spend → execute for each proposal.
		lastFeedback = nil
		for _, p := range proposals {
			if terminal != "" || ctx.Err() != nil {
				break // stop accepting; drain happened (actions are sequential)
			}
			fb, outcome, line, ran, estop := processProposal(ctx, o, st, runDirAbs, quarantine, failStreak, p)
			lastFeedback = append(lastFeedback, fb)
			if outcome != nil {
				outcomes = append(outcomes, *outcome)
				steps = append(steps, line)
			}
			if ran {
				st.Executed++
			}
			if estop {
				// Egress policy stop (design §6): ≥3 violations ⇒ STOPPED,
				// exit 1. Not a kill: the loop drains (sequential actions)
				// and reports normally.
				egressStopped = true
				terminal = TerminalStopped
				break
			}
			if fb.Kind == planner.FeedbackBudget {
				budgetGone = true
				break
			}
		}
		if err := persistState(st, runDirAbs); err != nil {
			return nil, err
		}
		if err := persistOutcomes(outcomes, runDirAbs); err != nil {
			return nil, err
		}
		if terminal == "" && budgetGone {
			// Graceful: drain is complete (sequential), finish toward DONE.
			break
		}
	}

	if terminal == "" {
		terminal = TerminalDone
	}
	exit := exitOf(terminal)
	if egressStopped {
		exit = ExitEgressPolicy
	}
	res := &Result{Terminal: terminal, ExitCode: exit, Steps: steps, Turns: st.Turn, Executed: st.Executed}

	// CORRELATE + REPORT (M3: detection correlation lands M4; Build applies
	// the formal gap rule over recorded evidence).
	setState(st, "CORRELATE", runDirAbs)
	if chainHasRecords(runDirAbs) {
		if err := evidence.Verify(runDirAbs); err != nil {
			_ = o.Audit.Append("evidence.violation", map[string]any{"error": err.Error()})
			if terminal == TerminalDone {
				return nil, fmt.Errorf("engine: %w", err)
			}
			// Stopped/aborted runs: keep the terminal result, skip outputs.
			setState(st, terminal, runDirAbs)
			return res, nil
		}
	}
	CorrelateOutcomes(ctx, o.Judge, o.Cfg.Judge.CorrelationWindowS, outcomes, o.Audit)
	res.Findings = findings.Build(o.RunID, outcomes)
	setState(st, "REPORT", runDirAbs)
	if err := writeOutputs(o, runDirAbs, st, res); err != nil {
		return nil, err
	}
	_ = o.Audit.Append("run.finished", map[string]any{
		"terminal": terminal, "turns": st.Turn, "executed": st.Executed, "findings": len(res.Findings),
	})
	setState(st, terminal, runDirAbs)
	return res, nil
}

// CorrelateOutcomes joins executed outcomes with judge hits (design §5.5),
// populating Outcome.HitsByRule before findings.Build consumes them. A judge
// error degrades to unjudged findings (§6 JudgeError) — never fails the run.
func CorrelateOutcomes(ctx context.Context, j detection.Judge, windowSec int, outcomes []findings.Outcome, audit *kernel.AuditLog) {
	if j == nil {
		return
	}
	refs, from, to := judgeRefs(outcomes)
	if len(refs) == 0 {
		return
	}
	w := detection.Window{From: from, To: to.Add(time.Duration(windowSec) * time.Second)}
	hits, err := j.Correlate(ctx, w, refs)
	if err != nil {
		if audit != nil {
			_ = audit.Append("judge.error", map[string]any{"error": err.Error(), "refs": len(refs)})
		}
		return
	}
	byRule := detection.ByRule(hits)
	for i := range outcomes {
		outcomes[i].HitsByRule = byRule // rule-keyed; GapTriggered consults only the card's expected rules
	}
	if audit != nil {
		_ = audit.Append("judge.correlated", map[string]any{"hits": len(hits), "refs": len(refs)})
	}
}

// judgeRefs extracts executed, timestamped, ATT&CK-mapped action references.
func judgeRefs(outcomes []findings.Outcome) ([]detection.ActionRef, time.Time, time.Time) {
	var refs []detection.ActionRef
	var from, to time.Time
	for _, o := range outcomes {
		if o.Record == nil || o.Record.Result == nil || o.Card.Attack.TechniqueID == "" {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, o.Record.TS)
		if err != nil {
			continue
		}
		refs = append(refs, detection.ActionRef{ID: o.StepID, AttackID: o.Card.Attack.TechniqueID, TS: ts})
		if from.IsZero() || ts.Before(from) {
			from = ts
		}
		if ts.After(to) {
			to = ts
		}
	}
	return refs, from, to
}

// processProposal walks one proposal through resolve → gate → spend →
// execute, producing feedback, an outcome (when the action was attempted or
// referenced), a step line, and whether the egress policy stop tripped.
func processProposal(
	ctx context.Context, o Options, st *runState, runDirAbs string,
	quarantine map[string]bool, failStreak map[string]int, p planner.Proposal,
) (planner.Feedback, *findings.Outcome, report.StepLine, bool, bool) {
	actionID := fmt.Sprintf("a-%03d", st.Executed+1)
	outcome := &findings.Outcome{StepID: actionID, Assertion: p.Assertion, Repro: p.Repro}
	line := report.StepLine{StepID: actionID, CardID: p.CardID, Target: p.Target, Status: "executed"}

	reject := func(reason string) planner.Feedback {
		_ = o.Audit.Append("proposal.rejected", map[string]any{"action": actionID, "card": p.CardID, "reason": reason})
		line.Status = "rejected"
		line.Detail = reason
		return planner.Feedback{CardID: p.CardID, Kind: planner.FeedbackRejected, Reason: reason}
	}

	// Resolve: quarantined?
	if quarantine[p.CardID] {
		return reject("card quarantined for this run"), outcome, line, false, false
	}
	// Resolve: unknown card = hallucination (design §5.6).
	card, ok := o.Registry.Get(p.CardID)
	if !ok {
		return reject("unknown_card"), outcome, line, false, false
	}
	outcome.Card = card
	// Resolve: params against the argv contract.
	if reason := validateParams(card, p); reason != "" {
		return reject(reason), outcome, line, false, false
	}
	if p.Target == "" {
		return reject("missing target"), outcome, line, false, false
	}

	// Gate (design §5.1 fixed order).
	dec := o.Scope.Check(kernel.Request{
		Adapter:     card.Executor.Adapter,
		TechniqueID: card.Attack.TechniqueID,
		Class:       p.Class,
		Target:      p.Target,
	})
	_ = o.Audit.Append("gate.decision", map[string]any{"action": actionID, "card": card.ID, "allowed": dec.Allowed, "reason": dec.Reason})
	if !dec.Allowed {
		outcome.Denied = dec.Reason
		line.Status = "denied"
		line.Detail = dec.Reason
		return planner.Feedback{CardID: card.ID, Kind: planner.FeedbackDenied, Reason: dec.Reason}, outcome, line, false, false
	}

	// Spend.
	if ok, reason := o.Budget.SpendAction(); !ok {
		_ = o.Audit.Append("budget.exhausted", map[string]any{"action": actionID, "reason": reason})
		line.Status = "skipped_budget"
		line.Detail = reason
		return planner.Feedback{CardID: card.ID, Kind: planner.FeedbackBudget, Reason: reason}, outcome, line, false, false
	}
	used, _ := o.Budget.Dump()
	st.BudgetUsed = used

	// Execute.
	adapter, ok := o.Adapters[card.Executor.Adapter]
	if !ok {
		reason := fmt.Sprintf("adapter %q not available", card.Executor.Adapter)
		_ = o.Audit.Append("adapter.unavailable", map[string]any{"action": actionID, "reason": reason})
		line.Status = "not_happened"
		line.Detail = reason
		return planner.Feedback{CardID: card.ID, Kind: planner.FeedbackFailed, Reason: reason}, outcome, line, false, false
	}

	workDir := filepath.Join(runDirAbs, "evidence", actionID)
	emit := func(r evidence.Record) error {
		for i := range r.Artifacts {
			r.Artifacts[i].Path = filepath.ToSlash(filepath.Join("evidence", actionID, r.Artifacts[i].Path))
		}
		_, err := o.Chain.Append(r)
		return err
	}
	actx, cancel := context.WithTimeout(ctx, o.ActionTimeout)
	res, execErr := adapter.Execute(actx, adapters.ExecRequest{
		RunID: o.RunID, ActionID: actionID, Card: card,
		Params: p.Params, Target: kernel.Target{Kind: "host", Value: p.Target},
		WorkDir: workDir,
	}, emit)
	cancel()
	if execErr != nil {
		_ = o.Audit.Append("adapter.error", map[string]any{"action": actionID, "error": execErr.Error()})
		line.Status = "not_happened"
		line.Detail = execErr.Error()
		failStreak[card.ID]++
		return planner.Feedback{CardID: card.ID, Kind: planner.FeedbackFailed, Reason: execErr.Error()}, outcome, line, false, false
	}

	// Egress enforcement honesty + violations (design §5.3/§6/§7): the level
	// that ACTUALLY applied is audited per action; every refused destination
	// is a kernel.egress_violation event; the monitor trips the policy stop.
	if res.EnforcedEgress != "" {
		_ = o.Audit.Append("egress.enforcement", map[string]any{
			"action": actionID, "adapter": card.Executor.Adapter, "level": res.EnforcedEgress,
		})
	}
	egressStop := false
	for _, dest := range res.EgressViolations {
		strikes, stop := o.Egress.Record()
		_ = o.Audit.Append("kernel.egress_violation", map[string]any{
			"action": actionID, "dest": dest, "strikes": strikes, "threshold": "3",
		})
		if stop {
			egressStop = true
		}
	}

	outcome.Record = tailRecord(runDirAbs)
	if res.NotHappened {
		line.Status = "not_happened"
	}
	line.Detail = res.Detail

	// Failure quarantine: 3 consecutive failures on the same card (design §6).
	if res.Success {
		failStreak[card.ID] = 0
	} else {
		failStreak[card.ID]++
		if failStreak[card.ID] >= quarantineThreshold && !quarantine[card.ID] {
			quarantine[card.ID] = true
			st.Quarantine = quarantineIDs(quarantine)
			_ = o.Audit.Append("card.quarantined", map[string]any{"card": card.ID, "consecutive_failures": failStreak[card.ID]})
		}
	}
	kind := planner.FeedbackExecuted
	if !res.Success {
		kind = planner.FeedbackFailed
	}
	return planner.Feedback{CardID: card.ID, Kind: kind, Reason: res.Detail}, outcome, line, true, egressStop
}

// validateParams enforces the v0 params contract: every {params.NAME} the
// card's argv references must be supplied (out_file excepted — it has a
// default). This is the "params failing params_schema ⇒ rejected" path of
// design §5.6.
func validateParams(card actions.Card, p planner.Proposal) string {
	need := map[string]bool{}
	for _, a := range card.Executor.Argv {
		for _, m := range paramsRef.FindAllStringSubmatch(a, -1) {
			name := m[1]
			if name == "out_file" {
				continue
			}
			need[name] = true
		}
	}
	for name := range need {
		if p.Params == nil || p.Params[name] == "" {
			return fmt.Sprintf("params_invalid: missing required param %q", name)
		}
	}
	return ""
}

func buildView(o Options, st *runState, runDirAbs string, feedback []planner.Feedback) planner.StateView {
	targets := make([]string, 0, len(o.Scope.Targets))
	for _, t := range o.Scope.Targets {
		targets = append(targets, t.Value)
	}
	used, _ := o.Budget.Dump()
	st.BudgetUsed = used

	cards := make([]planner.CardDigest, 0)
	for _, c := range o.Registry.Candidates(actions.Filter{}) {
		cards = append(cards, planner.CardDigest{
			ID: c.ID, TechniqueID: c.Attack.TechniqueID, Tactic: c.Attack.Tactic,
			Phase: c.Preconditions.Phase, Adapter: c.Executor.Adapter,
			Title: c.Title, Notes: c.Preconditions.Notes,
		})
	}

	view := planner.StateView{
		RunID: o.RunID, State: "ENGAGE", Mode: string(o.Scope.Mode), Turn: st.Turn + 1,
		Targets: targets, Classes: o.Scope.Allow.Classes, Adapters: o.Scope.Allow.Adapters,
		Budget:  planner.BudgetView{MaxActions: o.Scope.Budget.MaxActions, UsedActions: used},
		Cards:   cards, Feedback: feedback,
		FindingsSoFar: st.Executed,
	}
	if tail, err := evidence.Tail(runDirAbs, o.MaxEvidenceTail); err == nil {
		for _, r := range tail {
			s := fmt.Sprintf("seq=%d action=%s event=%s", r.Seq, r.ActionID, r.Event)
			if r.Result != nil {
				s += fmt.Sprintf(" success=%v", r.Result.Success)
			}
			view.EvidenceTail = append(view.EvidenceTail, s)
		}
	}
	return view
}

func tailRecord(runDir string) *evidence.Record {
	tail, err := evidence.Tail(runDir, 1)
	if err != nil || len(tail) == 0 {
		return nil
	}
	r := tail[0]
	return &r
}

func chainHasRecords(runDir string) bool {
	st, err := os.Stat(filepath.Join(runDir, "evidence", "chain.jsonl"))
	return err == nil && st.Size() > 0
}

func exitOf(terminal string) int {
	if terminal == TerminalDone {
		return 0
	}
	return ExitKill
}

func quarantineIDs(m map[string]bool) []string {
	var out []string
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func fillDefaults(o *Options) {
	if o.ActionTimeout <= 0 {
		o.ActionTimeout = 5 * time.Minute
	}
	if o.MaxEvidenceTail <= 0 {
		o.MaxEvidenceTail = 8
	}
	if o.StartedUTC.IsZero() {
		o.StartedUTC = time.Now().UTC()
	}
}

// writeOutputs persists findings.json and report.md.
func writeOutputs(o Options, runDirAbs string, st *runState, res *Result) error {
	fb, err := json.MarshalIndent(res.Findings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runDirAbs, "findings.json"), fb, 0o644); err != nil {
		return err
	}
	md := report.RenderMarkdown(report.Input{
		RunID: o.RunID, ScopeName: o.Scope.Name, Mode: string(o.Scope.Mode),
		StartedUTC: st.Started(), EvidenceOK: chainHasRecords(runDirAbs),
		Findings: res.Findings, Steps: res.Steps,
	})
	return os.WriteFile(filepath.Join(runDirAbs, "report.md"), []byte(md), 0o644)
}
