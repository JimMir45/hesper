// Command hesper is the headless engine entrypoint (design §0/§6).
//
// Exit codes follow the error taxonomy (design §6): scope/config errors
// exit 2; kill path reserves 130; operational failures exit 1.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/JimMir45/hesper/internal/config"
	"github.com/JimMir45/hesper/internal/kernel"
)

const version = "0.0.1-dev"

const exitOK = 0
const exitOperational = 1 // lab unhealthy, environment failures (M1+)
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
	case "validate":
		return cmdRun(kernel.ModeValidate, args[1:])
	case "pentest":
		return cmdRun(kernel.ModePentest, args[1:])
	case "lab", "report", "evidence", "mcp":
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
  hesper scope check <scope.json>     validate a scope manifest
  hesper validate --scope <file>      start a validation run (engine: M2+)
  hesper pentest  --scope <file>      start a pentest run (engine: M5)
  hesper lab <up|down|status>         manage the bundled lab (M1)
  hesper report <show|render>         inspect run output (M2+)
  hesper evidence verify <run-dir>    verify the evidence hash chain (M2+)
  hesper mcp                          serve MCP tools (M5)
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

func cmdRun(mode kernel.Mode, args []string) int {
	fs := flag.NewFlagSet(string(mode), flag.ContinueOnError)
	scopePath := fs.String("scope", "", "path to scope manifest (required)")
	configPath := fs.String("config", "", "path to run.config (optional; defaults apply)")
	runDir := fs.String("run-dir", "", "run directory (default: runs/<UTC timestamp>)")
	if err := fs.Parse(args); err != nil {
		return exitUsageOrContract
	}
	if *scopePath == "" {
		fmt.Fprintln(os.Stderr, fmt.Sprintf("%s: --scope is required", mode))
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
	runID := filepath.Base(*runDir)
	if err := initRunDir(*runDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}

	audit, err := kernel.OpenAudit(filepath.Join(*runDir, "audit.jsonl"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}
	defer audit.Close()

	if err := writeJSON(filepath.Join(*runDir, "scope.snapshot.json"), scope); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}
	if err := writeJSON(filepath.Join(*runDir, "run.config.json"), cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}
	if err := writeJSON(filepath.Join(*runDir, "state", "state.json"), map[string]any{
		"run_id": runID, "state": "INIT", "mode": scope.Mode, "started_utc": time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}
	if err := audit.Append("run.started", map[string]any{
		"mode": scope.Mode, "scope": *scopePath, "config": *configPath, "budget": scope.Budget,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitOperational
	}

	fmt.Printf("run initialized: %s\n  mode=%s  scope=%s  targets=%d  budget=%d actions / %d min\n  judge=%s (window %ds)\n  engine loop lands in M2 — see docs/plan.md\n",
		*runDir, scope.Mode, scope.Name, len(scope.Targets), scope.Budget.MaxActions, scope.Budget.MaxMinutes,
		cfg.Judge.Mode, cfg.Judge.CorrelationWindowS)
	return exitOK
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
