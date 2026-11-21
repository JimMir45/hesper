// Package proc implements the proc adapter (design §5.3): external CLIs
// (NetExec, Nuclei engine, curl, chainsaw, ...) driven with strict argv
// templates. Planner-supplied values are passed as argv elements — they
// never pass through a shell, so shell metacharacters are inert data.
package proc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/JimMir45/hesper/internal/adapters"
	"github.com/JimMir45/hesper/internal/egress"
	"github.com/JimMir45/hesper/internal/evidence"
)

// Proc is the proc-kind adapter.
type Proc struct {
	// LookPath is injectable for tests; defaults to exec.LookPath.
	LookPath func(file string) (string, error)
	// CommandContext is injectable for tests; defaults to exec.CommandContext.
	CommandContext func(ctx context.Context, name string, args ...string) *exec.Cmd
	// Guard, when set, is the runtime egress enforcer (design §7 M4+):
	// children run with proxy env pointing at the guard, and any refused
	// destination fails the action and is reported for audit. Nil ⇒
	// LevelNone (type discipline only), reported honestly.
	Guard *egress.Guard
}

// New returns a Proc adapter with the real exec bindings, no runtime egress
// enforcement.
func New() *Proc { return NewWithGuard(nil) }

// NewWithGuard returns a Proc adapter whose children egress through the
// local control proxy (proxy-aware clients intercepted, design §7).
func NewWithGuard(g *egress.Guard) *Proc {
	return &Proc{LookPath: exec.LookPath, CommandContext: exec.CommandContext, Guard: g}
}

func (p *Proc) Kind() string { return "proc" }

var paramsRef = regexp.MustCompile(`\{params\.([A-Za-z0-9_]+)\}`)

// renderArgv substitutes "{params.NAME}" and "{target}" placeholders.
// The out_file parameter is interpreted relative to the action's evidence
// WorkDir, so captured artifacts stay inside the run's evidence package.
// Substitution is plain string replacement into argv ELEMENTS — no shell
// evaluation ever happens.
func (p *Proc) renderArgv(req adapters.ExecRequest) []string {
	out := make([]string, 0, len(req.Card.Executor.Argv))
	for _, a := range req.Card.Executor.Argv {
		a = paramsRef.ReplaceAllStringFunc(a, func(m string) string {
			name := paramsRef.FindStringSubmatch(m)[1]
			if name == "out_file" {
				v := req.Params["out_file"]
				if v == "" {
					v = "body.bin"
				}
				return filepath.Join(req.WorkDir, filepath.FromSlash(v))
			}
			return req.Params[name]
		})
		a = strings.ReplaceAll(a, "{target}", req.Target.Value)
		out = append(out, a)
	}
	return out
}

// Execute runs the card's argv template and captures stdout, stderr, and
// the declared body artifact. Success = exit 0 (+ card's
// success_stdout_contains when set) AND every evidence.must_capture kind
// captured; otherwise the action is recorded as not-happened (design §4.4).
func (p *Proc) Execute(ctx context.Context, req adapters.ExecRequest, emit adapters.EmitFunc) (adapters.ExecResult, error) {
	if len(req.Card.Executor.Argv) == 0 {
		return adapters.ExecResult{}, fmt.Errorf("proc: card %s has no argv binding", req.Card.ID)
	}
	if err := os.MkdirAll(req.WorkDir, 0o755); err != nil {
		return adapters.ExecResult{}, fmt.Errorf("proc: mkdir %s: %w", req.WorkDir, err)
	}
	argv := p.renderArgv(req)
	if _, err := p.lookPath(argv[0]); err != nil {
		res := adapters.ExecResult{Success: false, Detail: fmt.Sprintf("proc: %s: %v", argv[0], err), ExitCode: -1}
		if err := p.emitNotHappened(req, emit, res, nil); err != nil {
			return res, err
		}
		return res, nil
	}

	stdoutPath := filepath.Join(req.WorkDir, "stdout.txt")
	stderrPath := filepath.Join(req.WorkDir, "stderr.txt")

	cmd := p.commandContext(ctx, argv[0], argv[1:]...)
	// Egress discipline (design §5.3/§7): ambient proxy variables are always
	// stripped — an inherited http_proxy silently reroutes or breaks scoped
	// targets (found live in M2: loopback probes died on a corporate proxy
	// with HTTP 502 before this). With a guard, the child's proxy IS the
	// guard: traffic flows through policy enforcement (proxy-aware clients).
	violationsBefore := 0
	enforcedLevel := egress.LevelNone
	if p.Guard != nil {
		violationsBefore = p.Guard.ViolationCount()
		enforcedLevel = egress.LevelProxy
		cmd.Env = append(stripProxyEnv(), egress.EnvFor(p.Guard.Addr())...)
	} else {
		cmd.Env = stripProxyEnv()
	}
	outF, err := os.Create(stdoutPath)
	if err != nil {
		return adapters.ExecResult{}, fmt.Errorf("proc: create %s: %w", stdoutPath, err)
	}
	errF, err := os.Create(stderrPath)
	if err != nil {
		outF.Close()
		return adapters.ExecResult{}, fmt.Errorf("proc: create %s: %w", stderrPath, err)
	}
	cmd.Stdout = outF
	cmd.Stderr = errF
	runErr := cmd.Run()
	outF.Close()
	errF.Close()

	exitCode := 0
	if runErr != nil {
		exitCode = exitCodeOf(cmd, runErr)
	}
	stdout, _ := os.ReadFile(stdoutPath)

	success := runErr == nil
	detail := fmt.Sprintf("exit=%d", exitCode)
	if sub := req.Card.Executor.SuccessStdoutContains; sub != "" {
		if !strings.Contains(string(stdout), sub) {
			success = false
			detail += fmt.Sprintf("; stdout missing %q", sub)
		} else if success {
			detail += fmt.Sprintf("; stdout contains %q", sub)
		}
	}
	if runErr != nil {
		detail += fmt.Sprintf("; run error: %v", runErr)
	}
	res := adapters.ExecResult{Success: success, Detail: detail, ExitCode: exitCode, EnforcedEgress: enforcedLevel}

	// Egress violations during this action fail it outright (design §5.3),
	// even if the child somehow exited 0.
	if p.Guard != nil {
		if viol := p.Guard.ViolationsSince(violationsBefore); len(viol) > 0 {
			res.EgressViolations = viol
			res.Success = false
			res.Detail = fmt.Sprintf("egress violation: refused %v — destination outside scope; %s", viol, detail)
		}
	}

	// Collect artifacts for the declared must_capture kinds (design §5.3:
	// collect is part of execute, driven by must_capture).
	artifacts, missing := p.collect(req, stdoutPath, stderrPath)

	if len(missing) > 0 {
		res.Success = false
		res.NotHappened = true
		res.Detail = fmt.Sprintf("missing must_capture artifacts %v — action did not happen (%s)", missing, detail)
	}
	if err := p.emitOutcome(req, emit, res, artifacts, missing); err != nil {
		return res, err
	}
	return res, nil
}

// collect resolves each must_capture kind to an artifact in WorkDir:
// stdout → stdout.txt, stderr → stderr.txt, body → params.out_file
// (default body.bin). Returns the found artifacts and the missing kinds.
func (p *Proc) collect(req adapters.ExecRequest, stdoutPath, stderrPath string) ([]evidence.Artifact, []string) {
	var artifacts []evidence.Artifact
	var missing []string
	for _, kind := range req.Card.Evidence.MustCapture {
		var path string
		switch kind {
		case "stdout":
			path = stdoutPath
		case "stderr":
			path = stderrPath
		case "body":
			v := req.Params["out_file"]
			if v == "" {
				v = "body.bin"
			}
			path = filepath.Join(req.WorkDir, filepath.FromSlash(v))
		default:
			// Unknown kinds cannot be captured by this adapter.
			missing = append(missing, kind)
			continue
		}
		if fileNonEmpty(path) {
			sum, err := evidence.HashFile(path)
			if err != nil {
				missing = append(missing, kind)
				continue
			}
			rel, rerr := filepath.Rel(req.WorkDir, path)
			if rerr != nil {
				rel = path
			}
			artifacts = append(artifacts, evidence.Artifact{
				Path:   rel,
				SHA256: sum,
				Kind:   kind,
			})
		} else {
			missing = append(missing, kind)
		}
	}
	return artifacts, missing
}

// emitOutcome writes the action.executed record. Artifact paths are emitted
// relative to WorkDir; the driver's emit binding rewrites them to
// run-directory-relative paths before chaining (design §4.3: run-relative,
// portable evidence packages).
func (p *Proc) emitOutcome(req adapters.ExecRequest, emit adapters.EmitFunc, res adapters.ExecResult, artifacts []evidence.Artifact, missing []string) error {
	rec := evidence.Record{
		RunID:    req.RunID,
		ActionID: req.ActionID,
		Event:    "action.executed",
		Artifacts: artifacts,
		Result: &evidence.Result{
			Success:     res.Success,
			Detail:      res.Detail,
			NotHappened: res.NotHappened,
			ExitCode:    res.ExitCode,
		},
	}
	if len(missing) > 0 {
		if rec.Result.Detail == "" {
			rec.Result.Detail = fmt.Sprintf("missing must_capture: %v", missing)
		}
	}
	return emit(rec)
}

func (p *Proc) emitNotHappened(req adapters.ExecRequest, emit adapters.EmitFunc, res adapters.ExecResult, artifacts []evidence.Artifact) error {
	rec := evidence.Record{
		RunID:     req.RunID,
		ActionID:  req.ActionID,
		Event:     "action.executed",
		Artifacts: artifacts,
		Result: &evidence.Result{
			Success:     res.Success,
			Detail:      res.Detail,
			NotHappened: true,
			ExitCode:    res.ExitCode,
		},
	}
	return emit(rec)
}

func (p *Proc) lookPath(file string) (string, error) {
	if p.LookPath != nil {
		return p.LookPath(file)
	}
	return exec.LookPath(file)
}

func (p *Proc) commandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	if p.CommandContext != nil {
		return p.CommandContext(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...)
}

func exitCodeOf(cmd *exec.Cmd, err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func fileNonEmpty(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Size() > 0
}

// stripProxyEnv returns the parent environment without proxy variables.
func stripProxyEnv() []string {
	proxyVars := map[string]bool{
		"http_proxy": true, "https_proxy": true, "all_proxy": true, "no_proxy": true,
	}
	var out []string
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq > 0 && proxyVars[strings.ToLower(kv[:eq])] {
			continue
		}
		out = append(out, kv)
	}
	return out
}
