// Command hesper is the headless engine entrypoint (design §0/§6).
//
// Exit codes follow the error taxonomy (design §6): scope/config errors
// exit 2; lab-unhealthy and operational failures exit 1; the kill path
// reserves 130.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/JimMir45/hesper/internal/actions"
	"github.com/JimMir45/hesper/internal/adapters"
	"github.com/JimMir45/hesper/internal/adapters/proc"
	"github.com/JimMir45/hesper/internal/config"
	"github.com/JimMir45/hesper/internal/evidence"
	"github.com/JimMir45/hesper/internal/findings"
	"github.com/JimMir45/hesper/internal/kernel"
	"github.com/JimMir45/hesper/internal/lab"
	"github.com/JimMir45/hesper/internal/report"
)

const version = "0.1.0-dev"

const exitOK = 0
const exitOperational = 1 // lab unhealthy, evidence violation, environment failures
const exitUsageOrContract = 2
const exitKill = 130 // reserved: kill switch (M3)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return exitUsageOrContract
	}
	switch args[0] {
	case "version":
		fmt.Println("hesper", version)
		return exitOK
	case "scope":
		return cmdScope(args[1:])
	case "cards":
		return cmdCards(args[1:])
	case "validate":
		return cmdRun(kernel.ModeValidate, args[1:])
	case "pentest":
		return cmdRun(kernel.ModePentest, args[1:])
	case "lab":
		return cmdLab(args[1:])
	case "evidence":
		return cmdEvidence(args[1:])
	case "report", "mcp":
		fmt.Fprintf(os.Stderr, "hesper %s: not implemented yet (see docs/plan.md)\n", args[0])
		return exitUsageOrContract
	default:
		usage()
		return exitUsageOrContract
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `hesper — headless AI-native agent for adversarial exposure validation

Usage:
  hesper scope check <scope.json>          validate a scope manifest
  hesper cards lint <dir>                  lint a directory of action cards
  hesper validate --scope <file> [--scripted <plan.json> --lab-profile lite]
                                           start a validation run
  hesper pentest  --scope <file>           start a pentest run (engine: M5)
  hesper lab <up|down|status> [--profile]  manage the bundled lab
  hesper evidence verify <run-dir>         verify the evidence hash chain
  hesper report <show|render>              inspect run output (M3+)
  hesper mcp                               serve MCP tools (M5)
  hesper version
`)
}

func cmdScope(args []string) int {
	if len(args) != 2 || args[0] != "check" {
		fmt.Fprintln(os.Stderr, "usage: hesper scope check <scope.json>")
		return exitUsageOrContract
	}
	m, err := kernel.LoadScope(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "scope check:", err)
		return exitUsageOrContract
	}
	fmt.Printf("scope OK: %s\n  mode=%s  targets=%d  budget=%d actions / %d min\n  classes=%v  adapters=%v  deny=%v\n",
		m.Name, m.Mode, len(m.Targets), m.Budget.MaxActions, m.Budget.MaxMinutes,
		m.Allow.Classes, m.Allow.Adapters, m.Deny)
	return exitOK
}

// cmdCards implements `hesper cards lint <dir>` — the registry lint as a
// CLI verb. Contract failures exit 2 (design §6).
func cmdCards(args []string) int {
	if len(args) != 2 || args[0] != "lint" {
		fmt.Fprintln(os.Stderr, "usage: hesper cards lint <dir>")
		return exitUsageOrContract
	}
	reg, err := actions.LoadRegistry(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "cards lint:", err)
		return exitUsageOrContract
	}
	fmt.Printf("cards lint OK: %d card(s) in %s\n", reg.Count(), args[1])
	return exitOK
}

// cmdEvidence implements `hesper evidence verify <run-dir>` (design §4.3).
func cmdEvidence(args []string) int {
	if len(args) != 2 || args[0] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: hesper evidence verify <run-dir>")
		return exitUsageOrContract
	}
	if err := evidence.Verify(args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "evidence verify:", err)
		return exitOperational
	}
	fmt.Printf("evidence verify OK: %s\n", filepath.Join(args[1], "evidence", "chain.jsonl"))
	return exitOK
}

// cmdLab implements `hesper lab up|down|status --profile <p>` (design §5.7).
func cmdLab(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: hesper lab <up|down|status> [--profile <p>] [--lab-root <dir>]")
		return exitUsageOrContract
	}
	verb := args[0]
	fs := flag.NewFlagSet("lab "+verb, flag.ContinueOnError)
	profile := fs.String("profile", "lite", "lab profile: lite | zero-vm")
	labRoot := fs.String("lab-root", "lab", "directory containing compose files")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsageOrContract
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: hesper lab <up|down|status> [--profile <p>] [--lab-root <dir>]")
		return exitUsageOrContract
	}
	o := lab.New(*labRoot)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	switch verb {
	case "up":
		h, err := o.Up(ctx, *profile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitOperational
		}
		printHealth(h)
		return healthExit(h)
	case "down":
		if err := o.Down(ctx, *profile); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitOperational
		}
		fmt.Printf("lab %s: down\n", *profile)
		return exitOK
	case "status":
		h, err := o.Status(ctx, *profile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitOperational
		}
		printHealth(h)
		return healthExit(h)
	default:
		fmt.Fprintf(os.Stderr, "hesper lab: unknown verb %q (want up|down|status)\n", verb)
		return exitUsageOrContract
	}
}

func printHealth(h lab.Health) {
	fmt.Printf("lab %s: healthy=%v\n", h.Profile, h.Healthy)
	for _, s := range h.Services {
		health := s.Health
		if health == "" {
			health = "n/a"
		}
		fmt.Printf("  %-24s state=%-10s health=%s\n", s.Name, s.State, health)
	}
	if h.Detail != "" {
		fmt.Printf("  detail: %s\n", h.Detail)
	}
}

func healthExit(h lab.Health) int {
	if h.Healthy {
		return exitOK
	}
	return exitOperational
}

func cmdRun(mode kernel.Mode, args []string) int {
	fs := flag.NewFlagSet(string(mode), flag.ContinueOnError)
	scopePath := fs.String("scope", "", "path to scope manifest (required)")
	configPath := fs.String("config", "", "path to run.config (optional; defaults apply)")
	runDir := fs.String("run-dir", "", "run directory (default: runs/<UTC timestamp>)")
	scripted := fs.String("scripted", "", "deterministic plan.json (no LLM) — M2 driver")
	labProfile := fs.String("lab-profile", "", "require this lab profile healthy at INIT")
	labRoot := fs.String("lab-root", "lab", "directory containing compose files")
	actionsRoot := fs.String("actions-root", "actions", "directory containing action cards")
	if err := fs.Parse(args); err != nil {
		return exitUsageOrContract
	}
	if *scopePath == "" {
		fmt.Fprintf(os.Stderr, "%s: --scope is required\n", mode)
		return exitUsageOrContract
	}

	// Contract loading — ScopeMissing/Parse/Invalid and ConfigInvalid exit 2
	// (design §6), before any state on disk is touched (fail-closed).
	scope, err := kernel.LoadScope(*scopePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsageOrContract
	}
	var cfg *config.RunConfig
	if *configPath != "" {
		cfg, err = config.LoadRunConfig(*configPath)
	} else {
		cfg = config.DefaultRunConfig()
		err = cfg.Validate()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsageOrContract
	}
	if scope.Mode != mode {
		fmt.Fprintf(os.Stderr, "scope mode is %q; cannot start a %s run with it\n", scope.Mode, mode)
		return exitUsageOrContract
	}

	if *runDir == "" {
		*runDir = filepath.Join("runs", time.Now().UTC().Format("20060102T150405Z"))
	}

	// INIT gate: a declared lab profile must be healthy before anything is
	// written (design §5.7, LabUnhealthy ⇒ exit 1).
	if *labProfile != "" {
		o := lab.New(*labRoot)
		lctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		err := o.EnsureHealthy(lctx, *labProfile)
		cancel()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitOperational
		}
		fmt.Printf("lab profile %q healthy\n", *labProfile)
	}

	audit, err := startRun(mode, scope, cfg, *configPath, *runDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}
	defer audit.Close()

	if *scripted == "" {
		fmt.Printf("run initialized: %s\n  mode=%s  scope=%s  targets=%d  budget=%d actions / %d min\n  judge=%s (window %ds)\n  no --scripted plan given: engine loop lands in M3\n",
			*runDir, scope.Mode, scope.Name, len(scope.Targets), scope.Budget.MaxActions, scope.Budget.MaxMinutes,
			cfg.Judge.Mode, cfg.Judge.CorrelationWindowS)
		return exitOK
	}
	return runScripted(scriptedRunInput{
		mode: mode, scope: scope, cfg: cfg, audit: audit,
		planPath: *scripted, runDir: *runDir,
		actionsRoot: *actionsRoot,
	})
}

// startRun creates the run directory and its INIT artifacts (audit, scope
// snapshot, config snapshot, state), auditing run.started.
func startRun(mode kernel.Mode, scope *kernel.ScopeManifest, cfg *config.RunConfig, configPath, runDir string) (*kernel.AuditLog, error) {
	if err := initRunDir(runDir); err != nil {
		return nil, err
	}
	audit, err := kernel.OpenAudit(filepath.Join(runDir, "audit.jsonl"))
	if err != nil {
		return nil, err
	}
	runID := filepath.Base(runDir)
	if err := writeJSON(filepath.Join(runDir, "scope.snapshot.json"), scope); err != nil {
		audit.Close()
		return nil, err
	}
	if err := writeJSON(filepath.Join(runDir, "run.config.json"), cfg); err != nil {
		audit.Close()
		return nil, err
	}
	if err := writeJSON(filepath.Join(runDir, "state", "state.json"), map[string]any{
		"run_id": runID, "state": "INIT", "mode": scope.Mode, "started_utc": time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		audit.Close()
		return nil, err
	}
	if err := audit.Append("run.started", map[string]any{
		"mode": scope.Mode, "config": configPath, "budget": scope.Budget,
	}); err != nil {
		audit.Close()
		return nil, err
	}
	return audit, nil
}

// ---- M2: deterministic scripted driver (no LLM; design §5.6 arrives M3) ----

type scriptedStep struct {
	ID        string            `json:"id"`
	CardID    string            `json:"card_id"`
	Class     string            `json:"class"`
	Target    string            `json:"target"`
	Params    map[string]string `json:"params"`
	Assertion string            `json:"assertion"`
	Repro     []string          `json:"repro"`
}

type scriptedPlan struct {
	Version string         `json:"version"`
	Steps   []scriptedStep `json:"steps"`
}

type scriptedRunInput struct {
	mode        kernel.Mode
	scope       *kernel.ScopeManifest
	cfg         *config.RunConfig
	audit       *kernel.AuditLog
	planPath    string
	runDir      string
	actionsRoot string
}

func runScripted(in scriptedRunInput) int {
	runDirAbs, err := filepath.Abs(in.runDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}
	runID := filepath.Base(in.runDir)

	// Registry: a contract failure here refuses the run (fail-closed, exit 2).
	registry, err := actions.LoadRegistry(in.actionsRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "registry:", err)
		return exitUsageOrContract
	}
	fmt.Printf("registry: %d card(s) loaded from %s\n", registry.Count(), in.actionsRoot)

	// Plan: parse + contract-check.
	b, err := os.ReadFile(in.planPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return exitUsageOrContract
	}
	var plan scriptedPlan
	if err := json.Unmarshal(b, &plan); err != nil {
		fmt.Fprintln(os.Stderr, "plan: parse:", err)
		return exitUsageOrContract
	}
	if !strings.HasPrefix(plan.Version, "0.") {
		fmt.Fprintf(os.Stderr, "plan: unsupported major version %q\n", plan.Version)
		return exitUsageOrContract
	}
	if len(plan.Steps) == 0 {
		fmt.Fprintln(os.Stderr, "plan: no steps")
		return exitUsageOrContract
	}

	// Adapters: proc is the only kind implemented in M2 (lib/vm land with M4).
	adaptersByName := map[string]adapters.Adapter{"proc": proc.New()}

	budgeter := kernel.NewBudgeter(in.scope.Budget)
	chain, err := evidence.OpenChain(runDirAbs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}

	var outcomes []findings.Outcome
	var stepLines []report.StepLine
	stepsExecuted := 0

	for _, step := range plan.Steps {
		outcome := findings.Outcome{StepID: step.ID, Assertion: step.Assertion, Repro: step.Repro}
		line := report.StepLine{StepID: step.ID, CardID: step.CardID, Target: step.Target, Status: "executed"}

		card, ok := registry.Get(step.CardID)
		if !ok {
			// Hallucination containment, deterministic edition (design §5.6).
			in.audit.Append("proposal.rejected", map[string]any{"step": step.ID, "reason": "unknown_card", "card": step.CardID})
			outcome.UnknownCard = step.CardID
			line.Status = "unknown_card"
			line.Detail = "unknown card"
			outcomes = append(outcomes, outcome)
			stepLines = append(stepLines, line)
			continue
		}
		// The finding contract needs the card (ATT&CK join key, must_capture
		// semantics) — an outcome without its card is uninterpretable.
		outcome.Card = card

		dec := in.scope.Check(kernel.Request{
			Adapter:     card.Executor.Adapter,
			TechniqueID: card.Attack.TechniqueID,
			Class:       step.Class,
			Target:      step.Target,
		})
		in.audit.Append("gate.decision", map[string]any{
			"step": step.ID, "card": card.ID, "allowed": dec.Allowed, "reason": dec.Reason,
		})
		if !dec.Allowed {
			outcome.Denied = dec.Reason
			line.Status = "denied"
			line.Detail = dec.Reason
			outcomes = append(outcomes, outcome)
			stepLines = append(stepLines, line)
			continue
		}

		if ok, reason := budgeter.SpendAction(); !ok {
			in.audit.Append("budget.exhausted", map[string]any{"step": step.ID, "reason": reason})
			line.Status = "skipped_budget"
			line.Detail = reason
			outcomes = append(outcomes, outcome)
			stepLines = append(stepLines, line)
			continue
		}

		adapter, ok := adaptersByName[card.Executor.Adapter]
		if !ok {
			reason := fmt.Sprintf("adapter %q not implemented in M2", card.Executor.Adapter)
			in.audit.Append("adapter.unavailable", map[string]any{"step": step.ID, "reason": reason})
			outcome.Denied = reason
			line.Status = "not_happened"
			line.Detail = reason
			outcomes = append(outcomes, outcome)
			stepLines = append(stepLines, line)
			continue
		}

		stepID := step.ID
		emit := func(r evidence.Record) error {
			for i := range r.Artifacts {
				r.Artifacts[i].Path = filepath.ToSlash(filepath.Join("evidence", stepID, r.Artifacts[i].Path))
			}
			_, aerr := chain.Append(r)
			return aerr
		}
		workDir := filepath.Join(runDirAbs, "evidence", stepID)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		res, execErr := adapter.Execute(ctx, mkDriverReq(card, runID, step.ID, step.Params, step.Target, workDir), emit)
		cancel()
		if execErr != nil {
			fmt.Fprintf(os.Stderr, "step %s: adapter error: %v\n", step.ID, execErr)
			in.audit.Append("adapter.error", map[string]any{"step": step.ID, "error": execErr.Error()})
			line.Status = "not_happened"
			line.Detail = execErr.Error()
			outcomes = append(outcomes, outcome)
			stepLines = append(stepLines, line)
			continue
		}

		// The adapter emits exactly one action.executed record per execution.
		outcome.Record = lastExecutedRecord(chain, runDirAbs)
		if res.NotHappened {
			line.Status = "not_happened"
		}
		line.Detail = res.Detail
		outcomes = append(outcomes, outcome)
		stepLines = append(stepLines, line)
		stepsExecuted++
	}

	// Evidence gate: findings may only rest on a verified chain (design
	// §4.3/§6 EvidenceViolation).
	if err := evidence.Verify(runDirAbs); err != nil {
		in.audit.Append("evidence.violation", map[string]any{"error": err.Error()})
		fmt.Fprintln(os.Stderr, "evidence verify:", err)
		return exitOperational
	}

	found := findings.Build(runID, outcomes)
	if err := writeJSON(filepath.Join(runDirAbs, "findings.json"), found); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}
	md := report.RenderMarkdown(report.Input{
		RunID:      runID,
		ScopeName:  in.scope.Name,
		Mode:       string(in.mode),
		StartedUTC: time.Now().UTC(),
		Findings:   found,
		EvidenceOK: true,
		Steps:      stepLines,
	})
	if err := os.WriteFile(filepath.Join(runDirAbs, "report.md"), []byte(md), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}

	prov, disp, gap := 0, 0, 0
	for _, f := range found {
		switch f.Status {
		case findings.StatusProven:
			prov++
		case findings.StatusDisproven:
			disp++
		case findings.StatusDetectionGap:
			gap++
		}
	}
	in.audit.Append("run.finished", map[string]any{
		"steps_executed": stepsExecuted, "findings": len(found),
	})
	fmt.Printf("scripted run done: %s\n  steps executed: %d / %d\n  findings: %d (proven=%d disproven=%d detection_gap=%d)\n  outputs: findings.json report.md evidence/chain.jsonl\n",
		in.runDir, stepsExecuted, len(plan.Steps), len(found), prov, disp, gap)
	return exitOK
}

// lastExecutedRecord reads the newest action.executed record from the chain.
func lastExecutedRecord(chain *evidence.Chain, runDir string) *evidence.Record {
	tail, err := evidence.Tail(runDir, 1)
	if err != nil || len(tail) == 0 {
		return nil
	}
	r := tail[0]
	return &r
}

func mkDriverReq(card actions.Card, runID, actionID string, params map[string]string, target, workDir string) adapters.ExecRequest {
	if params == nil {
		params = map[string]string{}
	}
	return adapters.ExecRequest{
		RunID:    runID,
		ActionID: actionID,
		Card:     card,
		Params:   params,
		Target:   kernel.Target{Kind: "host", Value: target},
		WorkDir:  workDir,
	}
}

func initRunDir(dir string) error {
	for _, d := range []string{dir, filepath.Join(dir, "state"), filepath.Join(dir, "evidence")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("run dir: mkdir %s: %w", d, err)
		}
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	return os.WriteFile(path, b, 0o644)
}
