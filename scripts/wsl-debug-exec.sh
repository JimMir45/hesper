#!/usr/bin/env bash
# Engine-style exec WITH vagrant debug logging, output to files (no console loss).
cd /mnt/c/hesper-lab/lite-vms || exit 1
unset VAGRANT_HOME
export VAGRANT_LOG="debug"
VAGRANT="/mnt/c/Program Files/Vagrant/bin/vagrant.exe"
CMD='powershell -NoProfile -ExecutionPolicy Bypass -File C:\hesper\m4-ntdsutil-susp.ps1 -ParamsFile C:\hesper\m4-ntdsutil-susp.params.json'
"$VAGRANT" winrm dc -c "$CMD" > /mnt/c/hesper-lab/wsl-exec-out.txt 2> /mnt/c/hesper-lab/wsl-exec-err.txt
echo "EXIT=$?"
echo "== stdout tail =="
tail -6 /mnt/c/hesper-lab/wsl-exec-out.txt
echo "== stderr grep (auth/winrm/error) =="
grep -iE "error|auth|winrm|failed|denied" /mnt/c/hesper-lab/wsl-exec-err.txt | tail -8
