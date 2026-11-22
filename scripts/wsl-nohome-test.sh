#!/usr/bin/env bash
# Same exec WITHOUT VAGRANT_HOME (mimics the engine's env).
cd /mnt/c/hesper-lab/lite-vms || exit 1
unset VAGRANT_HOME
VAGRANT="/mnt/c/Program Files/Vagrant/bin/vagrant.exe"
CMD='powershell -NoProfile -ExecutionPolicy Bypass -File C:\hesper\m4-ntdsutil-susp.ps1 -ParamsFile C:\hesper\m4-ntdsutil-susp.params.json'
echo "== exec without VAGRANT_HOME =="
"$VAGRANT" winrm dc -c "$CMD" 2>&1 | tail -5
echo "EXIT=$?"
