package vm

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// VagrantWinRM implements the WinRM transport by delegating to
// `vagrant winrm -c <command> [machine]` inside the lite-vms project
// directory — the exact transport the provisioners already use (proven live:
// plaintext WinRM over HTTP through the VBox NAT port-forward). Zero new Go
// dependencies; Velociraptor-class AGPL isolation does not apply (vagrant is
// MIT), but the external-process pattern matches the rest of the stack.
//
// Injection discipline: the ONLY strings interpolated into guest command
// lines are engine-generated paths (charset-validated by safeGuestPath) and
// base64 payloads (validated alphabet). Planner-supplied values never enter
// a command line — they travel inside uploaded files (adapter contract).
type VagrantWinRM struct {
	// ProjectDir is the directory containing the lite-vms Vagrantfile.
	ProjectDir string
	// Machine is the vagrant machine name ("" = default machine).
	Machine string
	// Binary is the vagrant executable name/path. Default "vagrant"; set
	// "vagrant.exe" when the engine runs inside WSL against a Windows-host
	// vagrant (Linux LookPath won't resolve the .exe suffix on its own).
	Binary string
	// CommandContext is injectable for tests; defaults to exec.CommandContext.
	CommandContext func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

// singleShotLimit bounds the base64 payload for one-shot writes; larger
// content falls back to chunked line appends (winrm SOAP bodies are not
// cmd.exe-limited, but stay conservative).
const singleShotLimit = 96 * 1024

var safeGuestPathRe = regexp.MustCompile(`^[A-Za-z0-9 _\-.\\:]+$`)

func safeGuestPath(p string) bool { return safeGuestPathRe.MatchString(p) }

func (v *VagrantWinRM) factory() func(ctx context.Context, name string, arg ...string) *exec.Cmd {
	if v.CommandContext != nil {
		return v.CommandContext
	}
	return exec.CommandContext
}

// runVagrantWinRM executes `vagrant winrm -c <command> [machine]` in
// ProjectDir and returns stdout plus the vagrant exit code (which mirrors
// the guest command's exit code).
func (v *VagrantWinRM) runVagrantWinRM(ctx context.Context, command string) ([]byte, int, error) {
	argv := []string{"winrm", "-c", command}
	if v.Machine != "" {
		argv = append(argv, v.Machine)
	}
	bin := v.Binary
	if bin == "" {
		bin = "vagrant"
	}
	cmd := v.factory()(ctx, bin, argv...)
	cmd.Dir = v.ProjectDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
		err = nil // exit codes are data, not transport errors
	}
	return stdout.Bytes(), code, err
}

// Upload writes content to the guest path. Small payloads go as one
// WriteAllBytes command; larger ones are appended as base64 lines and
// decoded in place at the end.
func (v *VagrantWinRM) Upload(guestPath string, content []byte) error {
	if !safeGuestPath(guestPath) {
		return fmt.Errorf("vagrantwinrm: unsafe guest path %q", guestPath)
	}
	b64 := base64.StdEncoding.EncodeToString(content)
	dir := filepath.ToSlash(filepath.Dir(guestPath)) // POSIX-ish; PS handles both
	if len(b64) <= singleShotLimit {
		cmd := fmt.Sprintf("[IO.File]::WriteAllBytes('%s', [Convert]::FromBase64String('%s'))", guestPath, b64)
		_, code, err := v.runVagrantWinRM(context.Background(), cmd)
		if err != nil {
			return fmt.Errorf("vagrantwinrm: upload: %w", err)
		}
		if code != 0 {
			return fmt.Errorf("vagrantwinrm: upload exit %d", code)
		}
		return nil
	}
	staging := guestPath + ".b64"
	init := fmt.Sprintf("$d='%s'; if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force $d | Out-Null }; if (Test-Path '%s') { Remove-Item '%s' -Force }", dir, staging, staging)
	if _, code, err := v.runVagrantWinRM(context.Background(), init); err != nil || code != 0 {
		return fmt.Errorf("vagrantwinrm: upload init: err=%v code=%d", err, code)
	}
	for i := 0; i < len(b64); i += singleShotLimit {
		end := i + singleShotLimit
		if end > len(b64) {
			end = len(b64)
		}
		chunk := b64[i:end]
		if !safeB64(chunk) {
			return fmt.Errorf("vagrantwinrm: unsafe base64 payload")
		}
		app := fmt.Sprintf("Add-Content -Path '%s' -Value '%s' -Encoding ASCII", staging, chunk)
		if _, code, err := v.runVagrantWinRM(context.Background(), app); err != nil || code != 0 {
			return fmt.Errorf("vagrantwinrm: upload chunk %d: err=%v code=%d", i/singleShotLimit, err, code)
		}
	}
	final := fmt.Sprintf("[IO.File]::WriteAllBytes('%s', [Convert]::FromBase64String((Get-Content '%s') -join '')); Remove-Item '%s' -Force", guestPath, staging, staging)
	if _, code, err := v.runVagrantWinRM(context.Background(), final); err != nil || code != 0 {
		return fmt.Errorf("vagrantwinrm: upload finalize: err=%v code=%d", err, code)
	}
	return nil
}

var b64Re = regexp.MustCompile(`^[A-Za-z0-9+/=]*$`)

func safeB64(s string) bool { return b64Re.MatchString(s) }

// psQuote makes an argv element safe for PowerShell single-quote context.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// Run executes a fixed argv on the guest. The argv here is engine-built
// (adapter contract: powershell/-File/<paths>); elements are quoted
// defensively anyway. Vagrant's exit code mirrors the guest's.
func (v *VagrantWinRM) Run(ctx context.Context, argv []string) ([]byte, int, error) {
	for _, a := range argv {
		if !safeGuestPath(a) {
			return nil, -1, fmt.Errorf("vagrantwinrm: unsafe argv element %q", a)
		}
	}
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = psQuote(a)
	}
	return v.runVagrantWinRM(ctx, strings.Join(quoted, " "))
}

// Download reads a guest file as bytes via base64 transport.
func (v *VagrantWinRM) Download(guestPath string) ([]byte, error) {
	if !safeGuestPath(guestPath) {
		return nil, fmt.Errorf("vagrantwinrm: unsafe guest path %q", guestPath)
	}
	cmd := fmt.Sprintf("[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'))", guestPath)
	out, code, err := v.runVagrantWinRM(context.Background(), cmd)
	if err != nil {
		return nil, fmt.Errorf("vagrantwinrm: download: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("vagrantwinrm: download exit %d", code)
	}
	b64 := strings.TrimSpace(string(out))
	if !safeB64(b64) {
		return nil, fmt.Errorf("vagrantwinrm: download payload not base64 (file missing?)")
	}
	return base64.StdEncoding.DecodeString(b64)
}
