package vm

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// PSRemoting runs guest commands via PowerShell remoting (WinRM WSMan)
// launched from the devbox Windows host through WSL interop. Unlike the
// `vagrant winrm` CLI (which wraps commands in an elevated scheduled task
// whose principal breaks on a promoted DC), Invoke-Command executes
// directly in the guest session — proven live in this deployment
// (domain user creation, dir pulls).
type PSRemoting struct {
	// CredXMLPath is a CliXml credential file (Export-CliXml shape) for the
	// guest account. Never a password on a command line.
	CredXMLPath string
	// HostIP is the guest's IPv4 (Default Switch). Resolved by the caller.
	HostIP string
	// ActionsRoot is the repo actions directory (host files read via /mnt/c).
	ActionsRoot string

	CommandContext func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

func (p *PSRemoting) Kind() string { return "vm" }

func (p *PSRemoting) factory() func(ctx context.Context, name string, arg ...string) *exec.Cmd {
	if p.CommandContext != nil {
		return p.CommandContext
	}
	return exec.CommandContext
}

// powershellHost spawns the Windows PowerShell via WSL interop. The engine
// itself runs inside WSL; interop resolves powershell.exe from PATH.
func (p *PSRemoting) powershellHost(ctx context.Context, encoded string) ([]byte, error) {
	argv := []string{
		"powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", fmt.Sprintf(
			`$cred = Import-CliXml -Path '%s'; `+
				`$s = New-PSSessionOption -OpenTimeout 20000; `+
				`Invoke-Command -ComputerName '%s' -Credential $cred -SessionOption $s -ScriptBlock { `+
				`param($b64) powershell -NoProfile -EncodedCommand $b64 } -ArgumentList '%s'`,
			p.CredXMLPath, p.HostIP, encoded),
	}
	cmd := p.factory()(ctx, argv[0], argv[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.Bytes(), err
}

func (p *PSRemoting) b64(s string) string {
	return base64UTF16(s)
}

func (p *PSRemoting) Run(ctx context.Context, argv []string) ([]byte, int, error) {
	cmdline := strings.Join(argv, " ")
	// Sentinel: the guest reports its own exit so the transport can mirror it
	// (Invoke-Command does not propagate remote $LASTEXITCODE).
	enc := p.b64("$ErrorActionPreference='Continue'\n" + cmdline + "\nWrite-Output ('exit=' + $LASTEXITCODE)\n")
	out, err := p.powershellHost(ctx, enc)
	code, _ := p.parseExit(out)
	return out, code, err
}

func (p *PSRemoting) parseExit(out []byte) (int, string) {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	last := ""
	if len(lines) > 0 {
		last = strings.TrimSpace(lines[len(lines)-1])
	}
	var code int
	if strings.HasPrefix(last, "exit=") {
		fmt.Sscanf(last, "exit=%d", &code)
	}
	return code, last
}

func (p *PSRemoting) Upload(guestPath string, content []byte) error {
	b64content := base64Std(content)
	enc := p.b64(fmt.Sprintf(
		`$ErrorActionPreference='Stop'; `+
			`$dir = Split-Path -Path '%s'; `+
			`New-Item -ItemType Directory -Force -Path $dir | Out-Null; `+
			`[IO.File]::WriteAllBytes('%s', [Convert]::FromBase64String('%s'))`,
		guestPath, guestPath, b64content))
	_, err := p.powershellHost(context.Background(), enc)
	return err
}

func (p *PSRemoting) Download(guestPath string) ([]byte, error) {
	enc := p.b64(fmt.Sprintf(
		`$ErrorActionPreference='Stop'; `+
			`if (-not (Test-Path '%s')) { exit 9 }; `+
			`[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'))`,
		guestPath, guestPath))
	out, err := p.powershellHost(context.Background(), enc)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(out))
	// strip the sentinel echo lines the guest may prepend
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	return decodeBase64Std(s)
}
