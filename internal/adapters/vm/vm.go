// Package vm implements the vm adapter (design §5.3): staged execution on
// Windows targets over WinRM — script upload, fixed-argv invocation,
// artifact pull. Needed for Sysmon-era telemetry and ART techniques.
//
// Injection discipline, mirroring the proc adapter: planner-supplied values
// NEVER appear on the remote command line. Parameters travel in an uploaded
// JSON params file; the PowerShell invocation is a fixed argv with only
// script and params-file paths. Card script paths resolve against the
// adapter's ActionsRoot (Argv[0] is repo-relative, e.g.
// "actions/endpoint/files/ntds_ifm_dump.ps1").
//
// M4-1 connectivity knowledge baked into docs: WinRM over HTTP, artifacts
// fetched over the VBox NAT gateway path (host loopback), dependency source
// on host port 47807. Live wiring is on the M4 live checklist.
package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/JimMir45/hesper/internal/adapters"
	"github.com/JimMir45/hesper/internal/egress"
	"github.com/JimMir45/hesper/internal/evidence"
)

// WinRM is the transport contract. Real implementation lands with the live
// checklist; tests inject a fake. Paths are guest-side Windows paths.
type WinRM interface {
	// Upload writes content to the guest path (parent dirs created).
	Upload(guestPath string, content []byte) error
	// Run executes a fixed argv on the guest and returns stdout and the
	// process exit code. No shell string is ever assembled here.
	Run(ctx context.Context, argv []string) (stdout []byte, exitCode int, err error)
	// Download reads a guest file.
	Download(guestPath string) ([]byte, error)
}

// Adapter is the vm-kind adapter.
type Adapter struct {
	WinRM      WinRM
	ActionsRoot string // repo-relative root resolving card script paths
	// GuestBase is the guest staging directory (default C:\hesper).
	GuestBase string
}

func New(w WinRM, actionsRoot string) *Adapter {
	return &Adapter{WinRM: w, ActionsRoot: actionsRoot, GuestBase: `C:\hesper`}
}

func (a *Adapter) Kind() string { return "vm" }

// remoteInvocation is the FIXED argv — script path and params file only.
// Nothing derived from planner output ever enters it.
func (a *Adapter) remoteInvocation(guestScript, guestParams string) []string {
	return []string{
		"powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
		"-File", guestScript, "-ParamsFile", guestParams,
	}
}

// Execute stages the card script + params JSON, invokes it with a fixed
// argv, pulls declared remote outputs, and emits evidence. Success requires
// exit 0 AND every evidence.must_capture kind captured (design §4.4).
func (a *Adapter) Execute(ctx context.Context, req adapters.ExecRequest, emit adapters.EmitFunc) (adapters.ExecResult, error) {
	if len(req.Card.Executor.Argv) == 0 {
		return adapters.ExecResult{}, fmt.Errorf("vm: card %s has no script binding", req.Card.ID)
	}
	if err := os.MkdirAll(req.WorkDir, 0o755); err != nil {
		return adapters.ExecResult{}, fmt.Errorf("vm: mkdir %s: %w", req.WorkDir, err)
	}

	// Stage 1: script + params upload. Params (planner-controlled values,
	// possibly containing shell metacharacters) live ONLY in the JSON file.
	scriptRel := req.Card.Executor.Argv[0]
	scriptLocal := filepath.Join(a.ActionsRoot, filepath.FromSlash(scriptRel))
	scriptBytes, err := os.ReadFile(scriptLocal)
	if err != nil {
		return adapters.ExecResult{}, fmt.Errorf("vm: read script %s: %w", scriptLocal, err)
	}
	paramsJSON, err := json.MarshalIndent(req.Params, "", "  ")
	if err != nil {
		return adapters.ExecResult{}, fmt.Errorf("vm: marshal params: %w", err)
	}
	// Guest paths are Windows paths: joined with a literal backslash so the
	// construction is host-OS independent (filepath.Join would emit '/' on
	// Linux hosts and produce mixed separators).
	guestScript := strings.TrimRight(a.GuestBase, "\\") + "\\" + req.ActionID + ".ps1"
	guestParams := strings.TrimRight(a.GuestBase, "\\") + "\\" + req.ActionID + ".params.json"
	if err := a.WinRM.Upload(guestScript, scriptBytes); err != nil {
		return adapters.ExecResult{}, fmt.Errorf("vm: upload script: %w", err)
	}
	if err := a.WinRM.Upload(guestParams, paramsJSON); err != nil {
		return adapters.ExecResult{}, fmt.Errorf("vm: upload params: %w", err)
	}

	// Stage 2: fixed-argv invocation. The command travels as ONE string:
	// Run() psQuote-wraps EACH argv element individually (path-safe, but a
	// command line quoted per-token is a PowerShell parse explosion — the
	// live DC run caught this; m4-live 2026-11-22).
	cmdline := strings.Join(a.remoteInvocation(guestScript, guestParams), " ")
	stdout, exitCode, err := a.WinRM.Run(ctx, []string{cmdline})
	if exitCode != 0 {
		if w, ok := a.WinRM.(*VagrantWinRM); ok && w.LastStderr != "" {
			// live-run diagnostic: the transport stderr is the ground truth
			fmt.Fprintf(os.Stderr, "vm: vagrant stderr: %s\n", w.LastStderr)
		}
	}
	stdoutPath := filepath.Join(req.WorkDir, "stdout.txt")
	if werr := os.WriteFile(stdoutPath, stdout, 0o644); werr != nil {
		return adapters.ExecResult{}, fmt.Errorf("vm: write stdout: %w", werr)
	}

	artifacts := []evidence.Artifact{
		{Path: relToWork(req.WorkDir, stdoutPath), Kind: "stdout"},
	}

	// Stage 3: pull declared remote outputs (params["remote_files"],
	// comma-separated guest paths) into the evidence WorkDir.
	detail := fmt.Sprintf("exit=%d", exitCode)
	if w, ok := a.WinRM.(*VagrantWinRM); ok && w.LastStderr != "" {
		// transport/vagrant stderr is evidence on failure (§6): keep the
		// first 300 chars in the step detail, full text stays in artifacts
		detail += "; vagrant-stderr: " + truncRunes(w.LastStderr, 300)
	}
	if outs := strings.TrimSpace(req.Params["remote_files"]); outs != "" {
		for i, guest := range strings.Split(outs, ",") {
			guest = strings.TrimSpace(guest)
			if guest == "" {
				continue
			}
			data, derr := a.WinRM.Download(guest)
			if derr != nil {
				detail += fmt.Sprintf("; download %s failed: %v", guest, derr)
				continue
			}
			local := filepath.Join(req.WorkDir, fmt.Sprintf("pull_%d_%s", i+1, filepath.Base(guest)))
			if werr := os.WriteFile(local, data, 0o644); werr != nil {
				return adapters.ExecResult{}, fmt.Errorf("vm: write pull: %w", werr)
			}
			artifacts = append(artifacts, evidence.Artifact{Path: relToWork(req.WorkDir, local), Kind: "file"})
		}
	}

	success := err == nil && exitCode == 0

	// Evidence semantics: missing must_capture kinds => not happened.
	kinds := map[string]bool{}
	for _, art := range artifacts {
		kinds[art.Kind] = true
	}
	notHappened := false
	for _, k := range req.Card.Evidence.MustCapture {
		if !kinds[k] {
			notHappened = true
			break
		}
	}
	if notHappened {
		success = false
	}

	if emit != nil {
		if err := emit(evidence.Record{
			RunID:     req.RunID,
			ActionID:  req.ActionID,
			Event:     "action.executed",
			Artifacts: artifacts,
			Result: &evidence.Result{
				Success:     success,
				Detail:      detail,
				NotHappened: notHappened,
				ExitCode:    exitCode,
			},
		}); err != nil {
			return adapters.ExecResult{}, fmt.Errorf("vm: emit: %w", err)
		}
	}

	// Egress enforcement on vm actions is declaration + audit (design §7):
	// guest traffic does not traverse the host process stack, so no local
	// proxy can intercept it. Reported honestly — never claimed as
	// interception.
	return adapters.ExecResult{
		Success: success, Detail: detail, NotHappened: notHappened, ExitCode: exitCode,
		EnforcedEgress: egress.LevelDeclared,
	}, nil
}

func relToWork(work, p string) string {
	rel, err := filepath.Rel(work, p)
	if err != nil {
		return filepath.Base(p)
	}
	return rel
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
