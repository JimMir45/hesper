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

## full (AD lateral chain) — lands with M4

GOAD-Light VM layer + wizard for the manual Windows-eval-ISO step (license forbids
redistribution). Preflight (`hesper lab preflight`) gates M4; see
[docs/research/tv-networking.md](../docs/research/tv-networking.md) §6 for the honest gaps.

## Hard constraints (honest limits)

- Containers bootstrap automatically; the **AD VM layer needs Vagrant/VirtualBox and a
  manual Windows-ISO download** — the installer is a wizard, not a one-shot script.
- On hosts crowded with other compose projects: lite pins subnet `172.16.0.0/16`
  (the usual 172.17+ pools are taken); zero-vm runs with `network_mode: none`.
