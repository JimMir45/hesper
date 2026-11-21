package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/JimMir45/hesper/internal/lab"
)

// ToolsOptions configures the real tool handlers.
type ToolsOptions struct {
	LabRoot     string // compose root (default "lab")
	HesperBin   string // binary to spawn for run.start (default: os.Executable())
	RunsRoot    string // where run directories are created (default "runs")
}

// RealTools builds the MCP tool set over the real engine surfaces. The tools
// are thin: they orchestrate what the CLI already does — the engine itself
// is untouched (design §11).
func RealTools(opt ToolsOptions) []Tool {
	if opt.LabRoot == "" {
		opt.LabRoot = "lab"
	}
	if opt.RunsRoot == "" {
		opt.RunsRoot = "runs"
	}
	o := lab.New(opt.LabRoot)

	str := func(v string, def string) string {
		if v == "" {
			return def
		}
		return v
	}

	labUp := Tool{
		Name:        "lab_up",
		Description: "Bring up the bundled Hesper lab (docker compose profile).",
		InputSchema: obj(props(prop("profile", "string", "lab profile: lite | zero-vm")), []string{}),
		Fn: func(ctx context.Context, args json.RawMessage) (string, error) {
			a := parseArgs(args)
			cctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
			defer cancel()
			h, err := o.Up(cctx, str(a["profile"], "lite"))
			if err != nil {
				return "", &rpcErr{-32000, err.Error()}
			}
			return mustJSON(h), nil
		},
	}
	labStatus := Tool{
		Name:        "lab_status",
		Description: "Report the health of a lab profile.",
		InputSchema: obj(props(prop("profile", "string", "lab profile")), []string{}),
		Fn: func(ctx context.Context, args json.RawMessage) (string, error) {
			a := parseArgs(args)
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			h, err := o.Status(cctx, str(a["profile"], "lite"))
			if err != nil {
				return "", &rpcErr{-32000, err.Error()}
			}
			return mustJSON(h), nil
		},
	}
	runStart := Tool{
		Name:        "run_start",
		Description: "Start an engine run (validate or pentest) as a detached process; returns its run directory.",
		InputSchema: obj(props(
			prop("scope", "string", "path to the scope manifest (required)"),
			prop("mode", "string", "validate | pentest (default validate)"),
			prop("planner", "string", "stub | model"),
			prop("stub_plan", "string", "plan.json when planner=stub"),
			prop("lab_profile", "string", "require this lab profile healthy at INIT"),
		), []string{"scope"}),
		Fn: func(ctx context.Context, args json.RawMessage) (string, error) {
			a := parseArgs(args)
			if a["scope"] == "" {
				return "", &rpcErr{-32602, "scope is required"}
			}
			mode := str(a["mode"], "validate")
			if mode != "validate" && mode != "pentest" {
				return "", &rpcErr{-32602, "mode must be validate|pentest"}
			}
			bin := opt.HesperBin
			if bin == "" {
				exe, err := os.Executable()
				if err != nil {
					return "", &rpcErr{-32000, err.Error()}
				}
				bin = exe
			}
			runDir := filepath.Join(opt.RunsRoot, time.Now().UTC().Format("20060102T150405Z")+"-mcp")
			argv := []string{mode, "--scope", a["scope"], "--run-dir", runDir}
			if p := a["planner"]; p != "" {
				argv = append(argv, "--planner", p)
			}
			if sp := a["stub_plan"]; sp != "" {
				argv = append(argv, "--stub-plan", sp)
			}
			if lp := a["lab_profile"]; lp != "" {
				argv = append(argv, "--lab-profile", lp)
			}
			cmd := exec.Command(bin, argv...)
			if err := os.MkdirAll(runDir, 0o755); err != nil {
				return "", &rpcErr{-32000, err.Error()}
			}
			logFile, err := os.Create(filepath.Join(runDir, "mcp-stdout.log"))
			if err != nil {
				return "", &rpcErr{-32000, err.Error()}
			}
			cmd.Stdout, cmd.Stderr = logFile, logFile
			if err := cmd.Start(); err != nil {
				logFile.Close()
				return "", &rpcErr{-32000, err.Error()}
			}
			go func() { _ = cmd.Wait(); _ = logFile.Close() }()
			return mustJSON(map[string]any{"run_dir": runDir, "pid": cmd.Process.Pid, "mode": mode}), nil
		},
	}
	runStatus := Tool{
		Name:        "run_status",
		Description: "Report the lifecycle state, budget use, and findings count of a run directory.",
		InputSchema: obj(props(prop("run_dir", "string", "run directory (required)")), []string{"run_dir"}),
		Fn: func(_ context.Context, args json.RawMessage) (string, error) {
			a := parseArgs(args)
			if a["run_dir"] == "" {
				return "", &rpcErr{-32602, "run_dir is required"}
			}
			out, err := runStatus(a["run_dir"])
			if err != nil {
				return "", &rpcErr{-32000, err.Error()}
			}
			return mustJSON(out), nil
		},
	}
	reportShow := Tool{
		Name:        "report_show",
		Description: "Return the rendered markdown report of a run (first 200 lines).",
		InputSchema: obj(props(prop("run_dir", "string", "run directory (required)")), []string{"run_dir"}),
		Fn: func(_ context.Context, args json.RawMessage) (string, error) {
			a := parseArgs(args)
			if a["run_dir"] == "" {
				return "", &rpcErr{-32602, "run_dir is required"}
			}
			b, err := os.ReadFile(filepath.Join(a["run_dir"], "report.md"))
			if err != nil {
				return "", &rpcErr{-32000, err.Error()}
			}
			lines := 0
			for i := range b {
				if b[i] == '\n' {
					lines++
					if lines >= 200 {
						return string(b[:i]) + "\n…(truncated)", nil
					}
				}
			}
			return string(b), nil
		},
	}
	return []Tool{labUp, labStatus, runStart, runStatus, reportShow}
}

// runStatus aggregates the on-disk run state for the run_status tool.
func runStatus(runDir string) (map[string]any, error) {
	out := map[string]any{"run_dir": runDir}
	if b, err := os.ReadFile(filepath.Join(runDir, "state", "state.json")); err == nil {
		var st map[string]any
		if json.Unmarshal(b, &st) == nil {
			out["state"] = st
		}
	} else {
		return nil, fmt.Errorf("no state file: %w", err)
	}
	if b, err := os.ReadFile(filepath.Join(runDir, "findings.json")); err == nil {
		var fs []any
		if json.Unmarshal(b, &fs) == nil {
			out["findings"] = len(fs)
		}
	}
	if _, err := os.Stat(filepath.Join(runDir, "state", "STOP")); err == nil {
		out["stop_requested"] = true
	}
	return out, nil
}

// ---- tiny schema/args helpers ----

func props(kv ...map[string]any) map[string]any {
	m := map[string]any{}
	for _, e := range kv {
		for k, v := range e {
			m[k] = v
		}
	}
	return m
}

func prop(name, typ, desc string) map[string]any {
	return map[string]any{name: map[string]any{"type": typ, "description": desc}}
}

func obj(properties map[string]any, required []string) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{"type": "object", "properties": properties, "required": required}
}

func parseArgs(raw json.RawMessage) map[string]string {
	a := map[string]string{}
	if len(raw) == 0 {
		return a
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return a
	}
	for k, v := range m {
		if s, ok := v.(string); ok {
			a[k] = s
		}
	}
	return a
}

func mustJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}
