package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/JimMir45/hesper/internal/adapters/vm"
)

func main() {
	variant := "full"
	if len(os.Args) > 1 {
		variant = os.Args[1]
	}

	if variant == "full" || variant == "no-wslenv" {
		os.Setenv("WSLENV", "HESPER_WINRM_USER/u:HESPER_NO_PRIVATE_NET/u:HESPER_DC_BOX_VERSION/u")
	}
	if variant == "full" || variant == "no-privnet" || variant == "no-wslenv" {
		os.Setenv("HESPER_NO_PRIVATE_NET", "1")
	}

	w := &vm.VagrantWinRM{
		ProjectDir: "/mnt/c/hesper-lab/lite-vms",
		Machine:    "dc",
		Binary:     "vagrant.exe",
	}
	cmd := []string{
		"powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
		"-File", `C:\hesper\m4-ntdsutil-susp.ps1`, "-ParamsFile", `C:\hesper\m4-ntdsutil-susp.params.json`,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	stdout, code, err := w.Run(ctx, cmd)
	fmt.Printf("[%s] EXIT=%d ERR=%v STDOUT=%d bytes LASTSTDERR=%d bytes\n", variant, code, err, len(stdout), len(w.LastStderr))
	if code != 0 || len(stdout) == 0 {
		fmt.Printf("[%s] STDOUT: %s\n", variant, string(stdout))
		fmt.Printf("[%s] STDERR: %s\n", variant, w.LastStderr)
	}
}
