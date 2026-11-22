#!/usr/bin/env bash
# Replicate the engine's EXACT guest command via vagrant winrm.
cd /mnt/c/hesper-lab/lite-vms || exit 1
export VAGRANT_HOME="C:\hesper-lab\vagrant-home"
VAGRANT="/mnt/c/Program Files/Vagrant/bin/vagrant.exe"
CMD='powershell -NoProfile -ExecutionPolicy Bypass -File C:\hesper\m4-ntdsutil-susp.ps1 -ParamsFile C:\hesper\m4-ntdsutil-susp.params.json'
echo "== exec =="
"$VAGRANT" winrm dc -c "$CMD" 2>&1 | tail -8
echo "EXIT=$?"
