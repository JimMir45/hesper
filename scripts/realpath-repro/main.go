package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/JimMir45/hesper/internal/adapters/vm"
)

func main() {
	// Engine-like env: WSLENV forwards these into the Windows vagrant.exe.
	os.Setenv("WSLENV", "HESPER_WINRM_USER/u:HESPER_NO_PRIVATE_NET/u:HESPER_DC_BOX_VERSION/u")
	os.Setenv("HESPER_NO_PRIVATE_NET", "1")

	w := &vm.VagrantWinRM{
		ProjectDir: "/mnt/c/hesper-lab/lite-vms",
		Machine:    "dc",
		Binary:     "vagrant.exe",
	}
	cmd := `powershell -NoProfile -ExecutionPolicy Bypass -File C:\hesper\m4-ntdsutil-susp.ps1 -ParamsFile C:\hesper\m4-ntdsutil-susp.params.json`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	stdout, code, err := w.Run(ctx, cmd)
	fmt.Printf("EXIT=%d ERR=%v\n--- STDOUT (%d bytes) ---\n%s\n", code, err, len(stdout), string(stdout))
	if w.LastStderr != "" {
		fmt.Printf("--- LASTSTDERR ---\n%s\n", w.LastStderr)
	}
}
