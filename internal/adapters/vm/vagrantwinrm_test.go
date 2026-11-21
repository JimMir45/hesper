package vm

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// captureFactory records every vagrant invocation and replies with printf of
// the given fixture (same trick as the detection-package fakes).
func captureFactory(reply string) (func(ctx context.Context, name string, arg ...string) *exec.Cmd, *sync.Mutex, *[][]string) {
	var mu sync.Mutex
	var calls [][]string
	f := func(ctx context.Context, name string, args ...string) *exec.Cmd {
		mu.Lock()
		calls = append(calls, append([]string{name}, args...))
		mu.Unlock()
		return exec.CommandContext(ctx, "printf", "%s", reply)
	}
	return f, &mu, &calls
}

func TestVagrantWinRMUploadSingleShot(t *testing.T) {
	f, mu, calls := captureFactory("")
	w := &VagrantWinRM{ProjectDir: ".", Machine: "dc", CommandContext: f}

	content := []byte("Write-Output 'hi'")
	if err := w.Upload(`C:\hesper\a1.ps1`, content); err != nil {
		t.Fatalf("upload: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*calls) != 1 {
		t.Fatalf("want 1 vagrant call, got %d", len(*calls))
	}
	got := strings.Join((*calls)[0], " ")
	wantSub := fmt.Sprintf("[IO.File]::WriteAllBytes('C:\\hesper\\a1.ps1', [Convert]::FromBase64String('%s'))",
		base64.StdEncoding.EncodeToString(content))
	if !strings.Contains(got, wantSub) {
		t.Fatalf("command shape wrong:\n got %s\nwant-sub %s", got, wantSub)
	}
	if !strings.HasPrefix(got, "vagrant winrm -c ") || !strings.HasSuffix(got, " dc") {
		t.Fatalf("argv must be 'vagrant winrm -c <cmd> dc': %q", got)
	}
}

func TestVagrantWinRMRunQuotesArgv(t *testing.T) {
	f, mu, calls := captureFactory("ok\n")
	w := &VagrantWinRM{ProjectDir: ".", CommandContext: f}
	out, code, err := w.Run(context.Background(), []string{"powershell", "-NoProfile", "-File", `C:\hesper\a1.ps1`})
	if err != nil || code != 0 {
		t.Fatalf("run: code=%d err=%v", code, err)
	}
	if strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("stdout not captured: %q", out)
	}
	mu.Lock()
	defer mu.Unlock()
	got := strings.Join((*calls)[0], " ")
	if !strings.Contains(got, `'powershell' '-NoProfile' '-File' 'C:\hesper\a1.ps1'`) {
		t.Fatalf("argv must be element-quoted: %q", got)
	}
}

func TestVagrantWinRMRunRejectsUnsafeArgv(t *testing.T) {
	w := &VagrantWinRM{ProjectDir: "."}
	for _, bad := range []string{"a'; rm -rf /", "x $(boom)", "one two `t"} {
		if _, _, err := w.Run(context.Background(), []string{"powershell", bad}); err == nil {
			t.Fatalf("unsafe argv element %q must be rejected", bad)
		}
	}
}

func TestVagrantWinRMDownloadDecodes(t *testing.T) {
	content := []byte("ntds dump bytes")
	f, _, _ := captureFactory(base64.StdEncoding.EncodeToString(content))
	w := &VagrantWinRM{ProjectDir: ".", CommandContext: f}
	got, err := w.Download(`C:\hesper\out\dump.txt`)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

func TestVagrantWinRMUploadRejectsUnsafePath(t *testing.T) {
	w := &VagrantWinRM{ProjectDir: "."}
	if err := w.Upload(`C:\x'; calc.exe`, []byte("z")); err == nil {
		t.Fatal("unsafe guest path must be rejected")
	}
}
