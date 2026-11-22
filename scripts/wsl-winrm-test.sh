#!/usr/bin/env bash
# Replicate the engine's WSL-interop vagrant winrm invocation.
cd /mnt/c/hesper-lab/lite-vms || exit 1
export VAGRANT_HOME="C:\hesper-lab\vagrant-home"
VAGRANT="/mnt/c/Program Files/Vagrant/bin/vagrant.exe"
echo "== whoami =="
"$VAGRANT" winrm dc -c "whoami" 2>&1 | tail -4
echo "EXIT=$?"
