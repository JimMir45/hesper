#!/usr/bin/env bash
cd /mnt/c/hesper-lab/lite-vms || exit 1
unset VAGRANT_HOME
VAGRANT="/mnt/c/Program Files/Vagrant/bin/vagrant.exe"
CMD='powershell -NoProfile -ExecutionPolicy Bypass -File C:\hesper\m4-ntdsutil-susp.ps1 -ParamsFile C:\hesper\m4-ntdsutil-susp.params.json'
echo "== stdin=/dev/null =="
"$VAGRANT" winrm dc -c "$CMD" < /dev/null > /mnt/c/hesper-lab/stdin-test-out.txt 2>&1
echo "EXIT=$?"
tail -4 /mnt/c/hesper-lab/stdin-test-out.txt
