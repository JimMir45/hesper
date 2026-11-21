# Bundled Lab

The practice range ships in three profiles (composition rationale:
[docs/research/lab-defense-stack-selection-20261120.md](../docs/research/lab-defense-stack-selection-20261120.md),
live networking validation: [docs/research/tv-networking.md](../docs/research/tv-networking.md)).

## Quick start (lite)

```bash
go build -o hesper ./cmd/hesper
./hesper lab up --profile lite --lab-root lab     # images pulled on first run
./hesper lab status --profile lite
# DVWA        http://127.0.0.1:4280  (login.php)
# VAmPI       http://127.0.0.1:5002  (insecure instance)
# Velociraptor GUI  https://127.0.0.1:8889  (admin / hesper-lab)
./hesper lab down --profile lite
```

State persists under `lab/state/` (git-ignored): velociraptor config + datastore,
dvwa database. Relocate heavy state off drvfs with `HESPER_LAB_STATE=/some/ext4/path`.

## zero-vm (offline detection-rule validation, CI-friendly)

```bash
bash scripts/fetch-zero-vm-data.sh     # one-time: chainsaw binary, Sigma rules, EVTX samples
docker compose -f lab/compose.zero-vm.yaml up --abort-on-container-exit
# results: lab/state/chainsaw-out/findings.json (NDJSON, ATT&CK-tagged)
```

No attack execution, no Windows, no network — pure log parsing over public sample EVTX.

## preflight (VM readiness gate, M4-0)

`hesper lab preflight [--json]` observes — never installs — whether this machine
can run the Windows-VM layer:

- **CPU**: vendor + virtualization flag + `/dev/kvm`. Intel with KVM ⇒ `wsl2-kvm`
  path; AMD (or no KVM) ⇒ `windows-host` Vagrant/VirtualBox path (design §9).
- **Tools**: Vagrant/VirtualBox presence on both the WSL side and the Windows
  host (via powershell interop + default install paths).
- **Resources**: WSL + host RAM and `lab/state` disk against profile budgets
  (lite-vms ≈10 GB RAM / 60 GB disk; full ≈24 GB / 120 GB, from the
  [lab composition research](../docs/research/lab-defense-stack-selection-20261120.md)).

Exit 0 = ready (no gaps); exit 1 = gaps listed. Run it before any M4 spend.

## lite-vms (Windows VM layer, M4-1)

1×DC (Windows Server 2019 eval) + 1×workstation (Windows 10 eval): forest `hesper.lab`,
vulnerable-AD misconfig injection, Sysmon (sysmon-modular config), domain-joined workstation.
VM↔VM on host-only `192.168.56.0/24`; VM→detection plane via VBox NAT `10.0.2.2:18000`
(host loopback → WSL mirrored → Velociraptor frontend; see tv-networking.md §3).

```bash
# one-time host deps (Windows host; Sysmon fetched live per its EULA, nothing binary in-repo):
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/fetch-litevms-deps.ps1

cd lab/vagrant/lite-vms
vagrant up      # first run pulls ~10GB of eval boxes (180-day expiry)
vagrant halt / vagrant destroy -f
```

Boxes: `StefanScherer/windows_2019` (pinned `2021.05.15`, same as GOAD-Light) +
`StefanScherer/windows_10`. Provisioners are the plain `shell` provisioner — vagrant
2.4.9 runs `.ps1` via PowerShell automatically on WinRM guests (no separate
"powershell" provisioner exists in that version).

## full (AD lateral chain) — later

GOAD-Light VM layer + wizard for the manual Windows-eval-ISO step (license forbids
redistribution). Preflight (`hesper lab preflight`) gates M4; see
[docs/research/tv-networking.md](../docs/research/tv-networking.md) §6 for the honest gaps.

## Hard constraints (honest limits)

- Containers bootstrap automatically; the VM layer uses eval boxes from Vagrant Cloud
  (no manual ISO step for lite-vms/full — a manual Windows-ISO download only applies
  if self-building custom images later).
- On hosts crowded with other compose projects: lite pins subnet `172.16.0.0/16`
  (the usual 172.17+ pools are taken); zero-vm runs with `network_mode: none`.
