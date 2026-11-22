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
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/JimMir45/hesper/internal/actions"
	"github.com/JimMir45/hesper/internal/adapters"
	"github.com/JimMir45/hesper/internal/adapters/proc"
	"github.com/JimMir45/hesper/internal/adapters/vm"
	"github.com/JimMir45/hesper/internal/claims"
	"github.com/JimMir45/hesper/internal/config"
	"github.com/JimMir45/hesper/internal/detection"
	"github.com/JimMir45/hesper/internal/egress"
	"github.com/JimMir45/hesper/internal/engine"
	"github.com/JimMir45/hesper/internal/evidence"
	"github.com/JimMir45/hesper/internal/findings"
	"github.com/JimMir45/hesper/internal/kernel"
	"github.com/JimMir45/hesper/internal/lab"
	"github.com/JimMir45/hesper/internal/mcp"
	"github.com/JimMir45/hesper/internal/planner"
	plannerclient "github.com/JimMir45/hesper/internal/planner/client"
	"github.com/JimMir45/hesper/internal/report"
)

// version is overridable at build time: release builds inject it with
// -ldflags "-X main.version=<tag>".
var version = "0.1.0-dev"

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
	case "stop":
		return cmdStop(args[1:])
	case "mcp":
		return cmdMCP(args[1:])
	case "claims":
		return cmdClaims(args[1:])
	case "report":
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
  hesper validate --scope <file> [--planner stub --stub-plan <plan.json>]
                          [--lab-profile lite] [--resume <run-dir>]      run the engine
  hesper validate --scope <file> --scripted <plan.json>                 M2 deterministic driver
  hesper pentest  --scope <file>           start a pentest run
  hesper lab <up|down|status|preflight> [--profile]  manage the bundled lab / VM readiness gate
  hesper stop --run <run-dir>              request a graceful stop (STOP file)
  hesper evidence verify <run-dir>         verify the evidence hash chain
  hesper report <show|render>              inspect run output (M3+)
  hesper mcp                               serve MCP tools over stdio (M5-2)
  hesper claims verify [--with-live]       re-verify every machine-checkable claim (M5-3)
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

// cmdLab implements `hesper lab up|down|status|preflight` (design §5.7, M4-0 gate).
func cmdLab(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: hesper lab <up|down|status|preflight> [--profile <p>] [--lab-root <dir>]")
		return exitUsageOrContract
	}
	verb := args[0]
	fs := flag.NewFlagSet("lab "+verb, flag.ContinueOnError)
	profile := fs.String("profile", "lite", "lab profile: lite | zero-vm")
	labRoot := fs.String("lab-root", "lab", "directory containing compose files")
	asJSON := fs.Bool("json", false, "preflight only: emit the report as JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsageOrContract
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: hesper lab <up|down|status|preflight> [--profile <p>] [--lab-root <dir>]")
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
	case "preflight":
		// M4-0 gate: observe VM-layer readiness; never installs anything.
		// Gaps ⇒ exit 1 (same semantics as an unhealthy lab).
		r := lab.NewPreflight(*labRoot).Run()
		if *asJSON {
			b, err := json.MarshalIndent(r, "", "  ")
			if err != nil {
				fmt.Fprintln(os.Stderr, "preflight:", err)
				return exitOperational
			}
			fmt.Println(string(b))
		} else {
			fmt.Print(r.Human())
		}
		if !r.Ready {
			return exitOperational
		}
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "hesper lab: unknown verb %q (want up|down|status|preflight)\n", verb)
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
	plannerKind := fs.String("planner", "", "planner: stub | model (default: model when run.config.model is set)")
	stubPlan := fs.String("stub-plan", "", "plan.json driving --planner stub (reuses the M2 plan format)")
	resumeDir := fs.String("resume", "", "resume the run in this run directory")
	labProfile := fs.String("lab-profile", "", "require this lab profile healthy at INIT")
	labRoot := fs.String("lab-root", "lab", "directory containing compose files")
	actionsRoot := fs.String("actions-root", "actions", "directory containing action cards")
	if err := fs.Parse(args); err != nil {
		return exitUsageOrContract
	}

	var scope *kernel.ScopeManifest
	var cfg *config.RunConfig
	var err error

	if *resumeDir != "" {
		// Resume: the run directory IS the contract source — its snapshots
		// were frozen at INIT and must not be silently replaced.
		scope, err = kernel.LoadScope(filepath.Join(*resumeDir, "scope.snapshot.json"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "resume:", err)
			return exitUsageOrContract
		}
		cfg, err = config.LoadRunConfig(filepath.Join(*resumeDir, "run.config.json"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "resume:", err)
			return exitUsageOrContract
		}
		if scope.Mode != mode {
			fmt.Fprintf(os.Stderr, "resume: scope mode is %q; cannot resume as %s\n", scope.Mode, mode)
			return exitUsageOrContract
		}
		*runDir = *resumeDir
	} else {
		if *scopePath == "" {
			fmt.Fprintf(os.Stderr, "%s: --scope is required\n", mode)
			return exitUsageOrContract
		}
		// Contract loading — ScopeMissing/Parse/Invalid and ConfigInvalid
		// exit 2 (design §6), before any state on disk is touched.
		scope, err = kernel.LoadScope(*scopePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitUsageOrContract
		}
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

	var audit *kernel.AuditLog
	if *resumeDir != "" {
		// Resume: never rewrite the frozen snapshots; just reopen the audit.
		audit, err = kernel.OpenAudit(filepath.Join(*runDir, "audit.jsonl"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitOperational
		}
	} else {
		audit, err = startRun(mode, scope, cfg, *configPath, *runDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return exitOperational
		}
	}
	defer audit.Close()

	if *scripted != "" {
		return runScripted(scriptedRunInput{
			mode: mode, scope: scope, cfg: cfg, audit: audit,
			planPath: *scripted, runDir: *runDir,
			actionsRoot: *actionsRoot,
		})
	}
	return runEngine(engineInput{
		mode: mode, scope: scope, cfg: cfg, audit: audit,
		runDir: *runDir, actionsRoot: *actionsRoot,
		plannerKind: *plannerKind, stubPlan: *stubPlan, resume: *resumeDir != "",
	})
}

// ---- M3: the ENGAGE engine loop (design §3/§5.6) ----

type engineInput struct {
	mode        kernel.Mode
	scope       *kernel.ScopeManifest
	cfg         *config.RunConfig
	audit       *kernel.AuditLog
	runDir      string
	actionsRoot string
	plannerKind string
	stubPlan    string
	resume      bool
}

func runEngine(in engineInput) int {
	registry, err := actions.LoadRegistry(in.actionsRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "registry:", err)
		return exitUsageOrContract
	}
	fmt.Printf("registry: %d card(s) loaded from %s\n", registry.Count(), in.actionsRoot)

	kind := in.plannerKind
	if kind == "" {
		if in.cfg.Model != nil {
			kind = "model"
		} else {
			fmt.Fprintln(os.Stderr, "planner: run.config has no model configured; pass --planner stub --stub-plan <plan.json> or configure run.config model")
			return exitUsageOrContract
		}
	}

	var p planner.Planner
	switch kind {
	case "stub":
		if in.stubPlan == "" {
			fmt.Fprintln(os.Stderr, "planner: --planner stub requires --stub-plan <plan.json>")
			return exitUsageOrContract
		}
		plan, err := loadPlan(in.stubPlan)
		if err != nil {
			fmt.Fprintln(os.Stderr, "stub plan:", err)
			return exitUsageOrContract
		}
		p = &planner.Stub{Turns: planToTurns(plan)}
		fmt.Printf("planner: stub (%d turns from %s)\n", len(plan.Steps), in.stubPlan)
	case "model":
		if in.cfg.Model == nil {
			fmt.Fprintln(os.Stderr, "planner: --planner model requires run.config model")
			return exitUsageOrContract
		}
		temp := 0.0
		if in.cfg.Planner.Temperature != nil {
			temp = *in.cfg.Planner.Temperature
		}
		p = plannerclient.NewModelPlanner(plannerclient.New(*in.cfg.Model, temp, 4096), in.cfg.Planner.MaxProposalsPerTurn)
		fmt.Printf("planner: model %s (%s, key env %s)\n", in.cfg.Model.Model, in.cfg.Model.Provider, in.cfg.Model.APIKeyEnv)
	default:
		fmt.Fprintf(os.Stderr, "planner: unknown kind %q (stub | model)\n", kind)
		return exitUsageOrContract
	}

	runDirAbs, err := filepath.Abs(in.runDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}
	chain, err := evidence.OpenChain(runDirAbs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}

	// Budget: a resume inherits the ORIGINAL accounting — never mints.
	// A run stopped at turn 0 never persisted a deadline; that resume gets a
	// fresh time window (action accounting is still inherited).
	var budgeter *kernel.Budgeter
	if in.resume {
		used, deadline, err := loadBudgetState(runDirAbs)
		if err != nil {
			fmt.Fprintln(os.Stderr, "resume:", err)
			return exitUsageOrContract
		}
		if deadline.IsZero() {
			budgeter = kernel.NewBudgeter(in.scope.Budget)
			fmt.Printf("resume: budget deadline unknown (stopped at turn 0) — fresh time window, %d actions already used\n", used)
		} else {
			budgeter = kernel.RestoreBudgeter(in.scope.Budget, used, deadline, time.Now)
			fmt.Printf("resume: budget restored (%d actions used, deadline %s)\n", used, deadline.Format(time.RFC3339))
		}
	} else {
		budgeter = kernel.NewBudgeter(in.scope.Budget)
	}

	// Kill switch: first SIGINT drains (STOPPED); second escalates (ABORTED).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	abort := make(chan struct{})
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	go func() {
		<-sig
		cancel()
		<-sig
		close(abort)
	}()

	// Runtime egress enforcement (design §7): the guard lives for the whole
	// run; children of proc actions egress through it.
	procAdapter := proc.New()
	if in.cfg.EgressEnabled() {
		guard, gerr := egress.NewGuard(in.scope)
		if gerr != nil {
			fmt.Fprintln(os.Stderr, "egress guard:", gerr)
			return exitOperational
		}
		guard.Start()
		defer guard.Close()
		procAdapter = proc.NewWithGuard(guard)
		fmt.Printf("egress: runtime enforcement on (local guard %s, level %s)\n", guard.Addr(), egress.LevelProxy)
	}

	adapterMap := map[string]adapters.Adapter{"proc": procAdapter}
	if vmA, ok := vmAdapterIfConfigured(in.actionsRoot); ok {
		adapterMap["vm"] = vmA
	}

	res, err := engine.Run(ctx, engine.Options{
		RunDir: in.runDir, RunID: filepath.Base(in.runDir),
		Scope: in.scope, Cfg: in.cfg, Registry: registry,
		Adapters: adapterMap,
		Judge:    judgeIfConfigured(in.cfg),
		Planner:  p, Audit: in.audit, Chain: chain, Budget: budgeter,
		ForceAbort: abort,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}
	prov, disp, gap := 0, 0, 0
	for _, f := range res.Findings {
		switch f.Status {
		case findings.StatusProven:
			prov++
		case findings.StatusDisproven:
			disp++
		case findings.StatusDetectionGap:
			gap++
		}
	}
	fmt.Printf("run %s: %s\n  turns=%d executed=%d findings=%d (proven=%d disproven=%d detection_gap=%d)\n  outputs: findings.json report.md evidence/chain.jsonl\n",
		res.Terminal, in.runDir, res.Turns, res.Executed, len(res.Findings), prov, disp, gap)
	if res.ExitCode == engine.ExitKill {
		fmt.Fprintln(os.Stderr, "hesper: stopped by kill switch (exit 130)")
	}
	return res.ExitCode
}

// loadBudgetState reads the persisted budget accounting for a resume. An
// empty deadline (a run stopped at turn 0 persists none) is unknown, not an
// error — the caller grants a fresh time window in that case.
func loadBudgetState(runDir string) (int, time.Time, error) {
	b, err := os.ReadFile(filepath.Join(runDir, "state", "state.json"))
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("state: %w", err)
	}
	var st struct {
		BudgetUsed int    `json:"budget_used"`
		Deadline   string `json:"budget_deadline"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return 0, time.Time{}, fmt.Errorf("state parse: %w", err)
	}
	if st.Deadline == "" {
		return st.BudgetUsed, time.Time{}, nil
	}
	deadline, err := time.Parse(time.RFC3339, st.Deadline)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("state deadline: %w", err)
	}
	return st.BudgetUsed, deadline, nil
}

// planToTurns maps an M2 plan to stub turns: one step per turn, exercising
// the full observe→propose→…→update cycle per action.
func planToTurns(plan scriptedPlan) [][]planner.Proposal {
	turns := make([][]planner.Proposal, 0, len(plan.Steps))
	for _, s := range plan.Steps {
		turns = append(turns, []planner.Proposal{{
			CardID: s.CardID, Class: s.Class, Params: s.Params, Target: s.Target,
			Assertion: s.Assertion, Repro: s.Repro,
		}})
	}
	return turns
}

// cmdStop implements `hesper stop --run <dir>`: writes the STOP file the
// engine polls between iterations (design §5.1 kill switch).
func cmdStop(args []string) int {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	run := fs.String("run", "", "run directory (required)")
	if err := fs.Parse(args); err != nil {
		return exitUsageOrContract
	}
	if *run == "" {
		fmt.Fprintln(os.Stderr, "usage: hesper stop --run <run-dir>")
		return exitUsageOrContract
	}
	dir := filepath.Join(*run, "state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}
	if err := os.WriteFile(filepath.Join(dir, "STOP"), []byte("stop\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}
	fmt.Printf("stop requested: %s (engine drains its in-flight action, then STOPPED)\n", *run)
	return exitOK
}

// cmdMCP implements `hesper mcp`: serves the MCP tool surface over stdio
// (design §11 — one of the shells above the headless core).
func cmdMCP(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: hesper mcp")
		return exitUsageOrContract
	}
	srv := mcp.NewServer("hesper", version, mcp.RealTools(mcp.ToolsOptions{}))
	if err := srv.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mcp:", err)
		return exitOperational
	}
	return exitOK
}

// cmdClaims implements `hesper claims verify` (design §8.5): re-runs every
// machine-checkable claim in claims.json. CI tier must be green; live tier
// is skipped unless --with-live.
func cmdClaims(args []string) int {
	fs := flag.NewFlagSet("claims", flag.ContinueOnError)
	withLive := fs.Bool("with-live", false, "also run live-tier claims (need the bundled lab)")
	file := fs.String("file", "claims.json", "path to the claims file")
	if err := fs.Parse(args); err != nil {
		return exitUsageOrContract
	}
	if fs.NArg() != 1 || fs.Arg(0) != "verify" {
		fmt.Fprintln(os.Stderr, "usage: hesper claims verify [--with-live] [--file <claims.json>]")
		return exitUsageOrContract
	}
	results, err := claims.Verify(*file, *withLive, claims.ExecRunner())
	if err != nil {
		fmt.Fprintln(os.Stderr, "claims:", err)
		return exitUsageOrContract
	}
	summary, allOK := claims.Summary(results)
	fmt.Print(summary)
	if !allOK {
		return exitOperational
	}
	return exitOK
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

// loadPlan parses and contract-checks an M2 plan.json (shared by the
// scripted driver and the stub planner source).
func loadPlan(path string) (scriptedPlan, error) {
	var plan scriptedPlan
	b, err := os.ReadFile(path)
	if err != nil {
		return plan, err
	}
	if err := json.Unmarshal(b, &plan); err != nil {
		return plan, fmt.Errorf("parse %s: %w", path, err)
	}
	if !strings.HasPrefix(plan.Version, "0.") {
		return plan, fmt.Errorf("unsupported major version %q", plan.Version)
	}
	if len(plan.Steps) == 0 {
		return plan, fmt.Errorf("no steps")
	}
	return plan, nil
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
	plan, err := loadPlan(in.planPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan:", err)
		return exitUsageOrContract
	}

	// Adapters: proc is the only kind implemented in M2 (lib/vm land with M4).
	// Egress enforcement (design §7) applies to the scripted driver too.
	scriptedProc := proc.New()
	if in.cfg.EgressEnabled() {
		guard, gerr := egress.NewGuard(in.scope)
		if gerr != nil {
			fmt.Fprintln(os.Stderr, "egress guard:", gerr)
			return exitOperational
		}
		guard.Start()
		defer guard.Close()
		scriptedProc = proc.NewWithGuard(guard)
		fmt.Printf("egress: runtime enforcement on (local guard %s, level %s)\n", guard.Addr(), egress.LevelProxy)
	}
	adaptersByName := map[string]adapters.Adapter{"proc": scriptedProc}
	if vmA, ok := vmAdapterIfConfigured(in.actionsRoot); ok {
		adaptersByName["vm"] = vmA
	}
	egressMonitor := kernel.NewEgressMonitor(0)
	egressStopped := false

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
		// Egress violations: audited per destination; 3 strikes stop the run
		// (design §6) — the scripted driver drains to REPORT then exits 1.
		for _, dest := range res.EgressViolations {
			strikes, stop := egressMonitor.Record()
			in.audit.Append("kernel.egress_violation", map[string]any{
				"step": step.ID, "dest": dest, "strikes": strikes,
			})
			if stop {
				egressStopped = true
			}
		}
		if res.EnforcedEgress != "" {
			in.audit.Append("egress.enforcement", map[string]any{"step": step.ID, "level": res.EnforcedEgress})
		}
		line.Detail = res.Detail
		outcomes = append(outcomes, outcome)
		stepLines = append(stepLines, line)
		stepsExecuted++
		if egressStopped {
			fmt.Fprintf(os.Stderr, "hesper: egress policy stop after %d violation(s) — remaining steps skipped, exit 1\n", egressMonitor.Count())
			break // stop accepting; this step drained (design §6)
		}
	}

	// Evidence gate: findings may only rest on a verified chain (design
	// §4.3/§6 EvidenceViolation).
	if err := evidence.Verify(runDirAbs); err != nil {
		in.audit.Append("evidence.violation", map[string]any{"error": err.Error()})
		fmt.Fprintln(os.Stderr, "evidence verify:", err)
		return exitOperational
	}

	// Offline-judge glue: copy EVTX artifacts pulled from VMs into the
	// samples dir so chainsaw sees the run's own telemetry (design §5.5;
	// the last card exports the Sysmon log — see m4-live plan).
	if os.Getenv("HESPER_EVTX_COLLECT") == "1" {
		if dir := os.Getenv("HESPER_EVTX_SAMPLES"); dir != "" {
			n := collectEVTX(filepath.Join(runDirAbs, "evidence"), dir)
			in.audit.Append("judge.evtx_collected", map[string]any{"files": n, "dir": dir})
		}
	}
	engine.CorrelateOutcomes(context.Background(), judgeIfConfigured(in.cfg), in.cfg.Judge.CorrelationWindowS, outcomes, in.audit)
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
	if egressStopped {
		return exitOperational // design §6: egress policy stop exits 1
	}
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

// collectEVTX copies *.evtx files from the run's evidence tree into dst.
func collectEVTX(evidenceDir, dst string) int {
	_ = os.MkdirAll(dst, 0o755)
	n := 0
	_ = filepath.Walk(evidenceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.EqualFold(filepath.Ext(path), ".evtx") {
			return nil
		}
		out := filepath.Join(dst, fmt.Sprintf("run_%d_%s", time.Now().UnixNano(), filepath.Base(path)))
		if b, rerr := os.ReadFile(path); rerr == nil && os.WriteFile(out, b, 0o644) == nil {
			n++
		}
		return nil
	})
	return n
}

// judgeIfConfigured builds the detection judge from the environment (the
// live-run wiring; formal run.config fields follow when the contract
// stabilizes). Requires HESPER_CHAINSAW + HESPER_SIGMA_RULES +
// HESPER_EVTX_SAMPLES (+ optional HESPER_SIGMA_MAPPING, HESPER_SIGMA_INDEX).
// Returns nil (unjudged findings, §6) when the offline env is absent and no
// Velociraptor endpoint is configured.
func judgeIfConfigured(cfg *config.RunConfig) detection.Judge {
	ch, rules, samples := os.Getenv("HESPER_CHAINSAW"), os.Getenv("HESPER_SIGMA_RULES"), os.Getenv("HESPER_EVTX_SAMPLES")
	var offline *detection.OfflineJudge
	if ch != "" && rules != "" && samples != "" {
		offline = &detection.OfflineJudge{ChainsawPath: ch, RulesDir: rules, SamplesDir: samples}
		if m := os.Getenv("HESPER_SIGMA_MAPPING"); m != "" {
			offline.MappingPath = m
		}
		if idx := os.Getenv("HESPER_SIGMA_INDEX"); idx != "" {
			ri, err := detection.LoadRuleIndex(idx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "sigma index: %v (hits will fail attribution — DRL fail-closed)\n", err)
			} else {
				offline.Index = ri
			}
		}
	}
	vURL := ""
	if cfg != nil && cfg.Judge.Velociraptor != nil {
		vURL = cfg.Judge.Velociraptor.URL
	}
	switch {
	case vURL != "" && offline != nil:
		return nil // online judge wiring lands with the agent check-in task
	case offline != nil:
		return offline
	default:
		return nil
	}
}

// vmAdapterIfConfigured wires the vm adapter when HESPER_LITEVMS_DIR points
// at a lite-vms Vagrantfile project. Transport selected by HESPER_VM_TRANSPORT:
//   psremoting (default on devbox) — PowerShell remoting from the host,
//     creds via HESPER_VM_CRED_XML (CliXml file), guest IP via HESPER_VM_IP;
//   vagrant (legacy) — vagrant.exe winrm CLI via interop.
// Without HESPER_LITEVMS_DIR, runs behave exactly as before (proc-only).
func vmAdapterIfConfigured(actionsRoot string) (adapters.Adapter, bool) {
	dir := os.Getenv("HESPER_LITEVMS_DIR")
	if dir == "" {
		return nil, false
	}
	switch os.Getenv("HESPER_VM_TRANSPORT") {
	case "psremoting", "":
		ip := os.Getenv("HESPER_VM_IP")
		cred := os.Getenv("HESPER_VM_CRED_XML")
		if ip == "" || cred == "" {
			return nil, false
		}
		p := &vm.PSRemoting{CredXMLPath: cred, HostIP: ip, ActionsRoot: actionsRoot}
		fmt.Printf("vm: psremoting transport on %s (machine dc)\n", ip)
		return vm.New(p, actionsRoot), true
	default:
		w := &vm.VagrantWinRM{
			ProjectDir: dir,
			Machine:    os.Getenv("HESPER_VM_MACHINE"),
			Binary:     os.Getenv("HESPER_VAGRANT_BIN"),
		}
		fmt.Printf("vm: vagrant-winrm transport on %s (machine %q)\n", dir, w.Machine)
		return vm.New(w, actionsRoot), true
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
