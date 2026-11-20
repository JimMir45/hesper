# Bundled Lab

The practice range ships in three profiles (resource budgets from
[the composition research](../docs/research/lab-defense-stack-selection-20261120.md)):

| Profile | Contents | RAM (approx.) | Purpose |
|---|---|---|---|
| **lite** (default) | VAmPI + DVWA (web/API), Metasploitable 2 (Linux), mini AD (single DC + vulnerable-AD injection), offline detection chain (Sysmon → EVTX → chainsaw/hayabusa) | ~8–10 GB | First-run demo; 16 GB machines |
| **full** | lite + juice-shop + GOAD-Light (3 VMs) + Velociraptor server for online Sigma judgment | ~24–27 GB | Full lateral chain; 32 GB machines |
| **zero-vm** | EVTX-ATTACK-SAMPLES replay against detection rules | ~0 | CI and offline regression of detection rules |

## Hard constraints (honest limits)

- Containers (web/API/detection) bootstrap fully automatically with `docker compose`.
- The AD range must live at the VM layer (Vagrant + VirtualBox/VMware, or Proxmox + Ludus).
- Windows evaluation ISOs must be downloaded manually by the user — Microsoft's license does
  not permit redistribution. The installer therefore ships as a **wizard**, not a one-shot
  script, and the README will say so.

## Status

Not yet implemented. Composition decisions live in the research doc; compose/Vagrant drafts
land here next.
