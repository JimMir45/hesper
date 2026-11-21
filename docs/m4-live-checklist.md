# M4 live-checklist — items requiring the live Windows VM range

> Owner: M4 live-verification pass (runs when the shared host has an idle
> window). Code-first work (this branch of M4-3/M4-4) is complete and
> stub/fake-tested; everything below needs the real machines.

## Prerequisites

1. Idle host window: `hesper lab preflight` → all green (vagrant + VBox
   present since M4-1; nested-virt starvation was the last blocker).
2. `vagrant up --provision dc` (scripts are idempotent; wkst follows).

## Live verification items

- [ ] **WinRM transport real wiring**: `internal/adapters/vm` ships the
      `WinRM` interface + fake only. Implement the real client (WinRM over
      HTTP; M4-1 facts: VBox NAT gateway path, dependency source on host
      port 47807) and re-run the vm-adapter tests against it.
- [ ] **Velociraptor agent check-in**: DC boots, agent reaches the WSL
      Velociraptor server through the TV-1 topology (VBox NAT → host
      loopback → WSL mirrored), appears in the server's client list.
- [ ] **Real ART card execution**: run `endpoint-ntdsutil-susp-usage`
      (lightest card) end-to-end through the vm adapter on the live DC;
      then `endpoint-ntds-ifm-dump` and `endpoint-shadowcopy-wmi-delete`.
- [ ] **chainsaw NDJSON shape**: run OfflineJudge against a real chainsaw
      output (zero-vm profile) and confirm the parsed fields (name/level/
      tags/timestamp) match; adjust the struct if v2.18 differs.
- [ ] **Velociraptor wire contract**: the /api/v1/query row schema in
      `velociraptor.go` is stub-pinned; verify against the real API (VQL
      notebook over curated Sigma) and reconcile.
- [ ] **Real detection_gap**: one technique where every expected Sigma rule
      stays silent → `detection_gap` finding with evidence bundle.
- [ ] **Real hit**: one technique where at least one expected rule fires →
      hits attached to the proven finding with SigmaHQ author attribution.
- [ ] **Sigma index build**: `python3 scripts/build-sigma-index.py
      <sigma-checkout> -o lab/state/sigma/index.json`; confirm the three
      card-referenced rule titles resolve with authors.

## Notes

- Cards reference Sigma rules by TITLE (the identifier chainsaw and
  Velociraptor both report): the three used today are listed in the cards'
  `detection.expected_sigma` arrays.
- `judge.mode=auto` picks Velociraptor when healthy, else offline chainsaw;
  both paths must produce at least one live hit during verification.
