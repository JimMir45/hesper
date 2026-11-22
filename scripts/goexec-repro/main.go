package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func main() {
	dir := `/mnt/c/hesper-lab/lite-vms`
	bin := `/mnt/c/Program Files/Vagrant/bin/vagrant.exe`
	argv := []string{
		"winrm", "dc", "-c",
		`powershell -NoProfile -ExecutionPolicy Bypass -File C:\hesper\m4-ntdsutil-susp.ps1 -ParamsFile C:\hesper\m4-ntdsutil-susp.params.json`,
	}
	if len(os.Args) > 1 && os.Args[1] == "timeout" {
		ctx := contextWithTimeout(30 * time.Second)
		cmd := exec.CommandContext(ctx, bin, argv...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		fmt.Printf("EXIT-ERR=%v\nOUTPUT:\n%s", err, string(out))
		return
	}
	cmd := exec.Command(bin, argv...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	fmt.Printf("EXIT-ERR=%v\nOUTPUT:\n%s", err, string(out))
}
