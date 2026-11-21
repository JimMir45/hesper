# M4 live-checklist 鈥?items requiring the live Windows VM range

> Owner: M4 live-verification pass (runs when the shared host has an idle
> window). Code-first work (this branch of M4-3/M4-4) is complete and
> stub/fake-tested; everything below needs the real machines.

## Prerequisites

1. Idle host window: `hesper lab preflight` 鈫?all green (vagrant + VBox
   present since M4-1; nested-virt starvation was the last blocker).
2. `vagrant up --provision dc` (scripts are idempotent; wkst follows).

## Live verification items

- [~] **WinRM transport real wiring** 鈥?IMPLEMENTED + unit-tested (vagrant-backed: charset-validated engine paths, chunked base64 upload, injection tests) (3d13f9b); LIVE validation blocked: see BLOCKER below: `internal/adapters/vm` ships the
      `WinRM` interface + fake only. Implement the real client (WinRM over
      HTTP; M4-1 facts: VBox NAT gateway path, dependency source on host
      port 47807) and re-run the vm-adapter tests against it.
- [ ] **Velociraptor agent check-in** 鈥?BLOCKED (topology, see BLOCKER below): DC boots, agent reaches the WSL
      Velociraptor server through the TV-1 topology (VBox NAT 鈫?host
      loopback 鈫?WSL mirrored), appears in the server's client list.
- [ ] **Real ART card execution** 鈥?BLOCKED (topology, see BLOCKER below): run `endpoint-ntdsutil-susp-usage`
      (lightest card) end-to-end through the vm adapter on the live DC;
      then `endpoint-ntds-ifm-dump` and `endpoint-shadowcopy-wmi-delete`.
- [x] **chainsaw NDJSON shape** 鈥?DONE (live 2026-11-22): v2.18 emits ONE JSON array, parser fixed for array+NDJSON, ns-timestamps verified (3d13f9b): run OfflineJudge against a real chainsaw
      output (zero-vm profile) and confirm the parsed fields (name/level/
      tags/timestamp) match; adjust the struct if v2.18 differs.
- [x] **Velociraptor wire contract** 鈥?DONE (live 2026-11-22): HTTP API is gorilla-CSRF-gated even with client certs (403s recorded); supported path = official CLI + server-minted api config (verified live); client rewritten as CLI subprocess (3d13f9b): the /api/v1/query row schema in
      `velociraptor.go` is stub-pinned; verify against the real API (VQL
      notebook over curated Sigma) and reconcile.
- [ ] **Real detection_gap** 鈥?BLOCKED (topology, see BLOCKER below): one technique where every expected Sigma rule
      stays silent 鈫?`detection_gap` finding with evidence bundle.
- [ ] **Real hit** 鈥?BLOCKED (topology, see BLOCKER below): one technique where at least one expected rule fires 鈫?      hits attached to the proven finding with SigmaHQ author attribution.
- [x] **Sigma index build** 鈥?DONE (live 2026-11-22): builder header-bug fixed (status:/description: precede author: in every SigmaHQ rule), 3164/3164 rules with authors; the three card rules resolve (Patzke/Roth/Rauch) (3d13f9b): `python3 scripts/build-sigma-index.py
      <sigma-checkout> -o lab/state/sigma/index.json`; confirm the three
      card-referenced rule titles resolve with authors.

## Notes

- Cards reference Sigma rules by TITLE (the identifier chainsaw and
  Velociraptor both report): the three used today are listed in the cards'
  `detection.expected_sigma` arrays.
- `judge.mode=auto` picks Velociraptor when healthy, else offline chainsaw;
  both paths must produce at least one live hit during verification.

## BLOCKER (live-verified 2026-11-22): VBox host path cannot boot Windows usably

VBoxManage list hostinfo: nested HW virtualization: **no** - VBox runs in NEM
software-emulated mode under Hyper-V. A FRESH clean box clone (verified healthy
Windows boot splash via guest screenshot) still exceeds boot_timeout=1800s; a
prior VM corrupted (0xc0000001) after hard poweroffs and burned CPU-hours in
retry loops. Windows guests are impractical on this path.

Options for the owner: (a) wsl2-kvm path (preflight's original recommendation -
/dev/kvm live, true KVM acceleration; needs vagrant-libvirt stack + VM disk on
D:); (b) a machine/window with Hyper-V off (breaks WSL2+docker - not viable
here); (c) keep host-VBox for linux-only targets (works: bionic64 smoke).
Dep server: WSL python on 127.0.0.1:48999 (18080=company SPA; 47807 ghost-bind).
Velo api config minted+persisted: D:/hesper-lab/state/velo-api-client.yaml
(admin role, cert+key extracted and CLI-verified).