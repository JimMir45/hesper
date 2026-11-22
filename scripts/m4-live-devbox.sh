#!/usr/bin/env bash
# M4 live run orchestrator (devbox WSL). One-shot: builds the engine, reads
# the DC's IP, renders the live scope/plan, runs the scripted driver with the
# vm adapter + offline judge, and dumps the findings. Run over a held ssh:
#   ssh devbox "wsl -e bash /mnt/c/hesper-lab/m4-live-devbox.sh"
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== pull + build =="
git pull -q
go build -o /tmp/hesper-live ./cmd/hesper

echo "== vm target =="
VM_IP=$(powershell.exe -NoProfile -Command '(Get-VM hesper-litevms-dc01 | Get-VMNetworkAdapter).IPAddresses | Select-Object -First 1' | tr -d '\r\n ')
if [ -z "$VM_IP" ]; then echo "FATAL: DC01 has no IP"; exit 1; fi
echo "DC01_IP=$VM_IP"

GATEWAY=$(powershell.exe -NoProfile -Command '(Get-VM hesper-litevms-dc01 | Get-VMNetworkAdapter | Select-Object -First 1).SwitchName' | tr -d '\r\n ')
echo "switch=$GATEWAY"

echo "== render scope/plan =="
RUN=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p /tmp/m4-live
sed "s/__VM_TARGET__/$VM_IP/" plans/m4-live-endpoint.plan.json > /tmp/m4-live/plan.json
cat > /tmp/m4-live/scope.json <<EOF
{
  "version": "0.1",
  "mode": "validate",
  "name": "m4-live-devbox",
  "targets": [{ "kind": "host", "value": "$VM_IP", "comment": "lab DC on devbox Default Switch" }],
  "allow": { "technique_ids": ["T1003.003", "T1490"], "adapters": ["vm"] },
  "budget": { "max_actions": 6, "max_minutes": 30 }
}
EOF
cat > /tmp/m4-live/run.config.json <<'EOF'
{ "version": "0.1", "judge": { "mode": "offline", "correlation_window_s": 900 } }
EOF

export HESPER_LITEVMS_DIR=/mnt/c/hesper-lab/lite-vms
export HESPER_VM_MACHINE=dc
export HESPER_VAGRANT_BIN=vagrant.exe
export HESPER_EVTX_COLLECT=1
export HESPER_EVTX_SAMPLES="$HOME/hesper/lab/state/evtx-samples"
export HESPER_CHAINSAW="$HOME/hesper/lab/state/bin/chainsaw"
export HESPER_SIGMA_RULES="$HOME/hesper/lab/state/sigma/rules"
export HESPER_SIGMA_INDEX="$HOME/hesper/lab/state/sigma/index.json"
# HESPER_SIGMA_MAPPING left unset: chainsaw uses its built-in sigma mappings
# (same as compose.zero-vm; fetch script's mapping dir is empty on devbox).
mkdir -p "$HESPER_EVTX_SAMPLES"

echo "== run =="
/tmp/hesper-live validate \
  --scope /tmp/m4-live/scope.json \
  --config /tmp/m4-live/run.config.json \
  --run-dir "runs/$RUN-m4live" \
  --scripted /tmp/m4-live/plan.json || echo "driver exit=$?"

echo "== findings =="
cat "runs/$RUN-m4live/findings.json" 2>/dev/null || echo "(no findings.json)"
echo "== evidence verify =="
/tmp/hesper-live evidence verify "runs/$RUN-m4live" || true
echo "== report head =="
head -40 "runs/$RUN-m4live/report.md" 2>/dev/null || true
echo "M4-LIVE-RUN-DONE runid=$RUN-m4live"
