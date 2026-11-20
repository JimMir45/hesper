# Hesper — Plan & Task Graph v1.0

> Status: **authoritative task plan** · 2026-11-20 · supersedes v0.1 · companion to [design.md](design.md) v1.0
> Author: Hesper planning working group (AI-assisted)
> Working agreements (binding): **done = implemented + verified runnable on this machine**; reports happen at milestone boundaries only; silence between milestones is progress, not absence.

## 0. How to read this plan

- Every task has: **ID · depends · deliverables · DoD (verifiable) · verify command**.
- Base verify command (all engine tasks): `wsl -e bash /mnt/c/Users/jiang/orca/projects/hesper/scripts/dev.sh` → must print `BUILD-OK VET-OK TEST-OK`.
- **Staged results** (owner-facing): each milestone ends with exactly one user-visible deliverable, listed per milestone below. Reports are delivered at the boundary; nothing in between.
- Task IDs are stable references; commits use the milestone prefix (`M0:`, `M1:`, `TV:`).

## 1. Milestone skeleton and staged results

| Milestone | Name | Staged result shown to owner |
|---|---|---|
| M0 | Engine baseline & contracts | `hesper scope check` live demo output + green CI badge/link |
| M1 | Lab lite & zero-vm | `hesper lab up --profile lite` status output + live endpoint probes on this machine |
| M2 | Deterministic end-to-end finding | real `findings.json` + rendered `report.md` from a scripted run against the live lab |
| M3 | Planner loop (validate mode) | unattended full-run transcript + report; kill-switch demo mid-run |
| M4 | Windows VM layer & detection correlation | one Windows technique yielding **hit or gap, with evidence bundle** |
| M5 | Pentest mode & surfaces | 30-second demo video (fresh `lab up` → final report) + `hesper claims verify` output |

## 2. M0 — Engine baseline & contracts (current milestone)

| ID | Task | Depends | Deliverables | DoD / verify |
|---|---|---|---|---|
| M0-1 | `internal/kernel/budget.go`: `Budgeter` per design §5.1 — atomic `SpendAction`, deadline check, `Exhausted` + unit tests (deadline, exhaustion, zero-negative budgets) | — | budget.go, budget_test.go | table-driven tests green in `go test ./internal/kernel -run Budget` |
| M0-2 | `internal/kernel/audit.go`: `OpenAudit`/`Append` — JSONL, ts field, single-writer mutex + test (lines parse as JSON, monotonic order) | — | audit.go, audit_test.go | tests green; line shape matches design §4.3 event envelope |
| M0-3 | run.config contract (design §4.5, *new in v1.0*): `internal/config` package — load/validate (model by env-var name only, judge mode, correlation window default 120s, planner budgets) + tests (invalid provider, missing env name ⇒ error) | — | internal/config/runconfig.go, runconfig_test.go | tests green |
| M0-4 | `schemas/v0/`: scope.manifest.example.json, run.config.example.json — golden fixtures reused by tests and `scope check` demo | M0-3 | schemas/v0/*.json | `hesper scope check schemas/v0/scope.manifest.example.json` prints OK |
| M0-5 | `cmd/hesper/main.go`: subcommands `version`, `scope check`, `validate`/`pentest` run-init (run dir, scope.snapshot, run.config snapshot, audit `run.started`), stubs `lab/report/mcp`; **exit codes per design §6** (scope/config errors ⇒ 2; lab unhealthy ⇒ 1; kill path reserves 130) | M0-1…M0-4 | cmd/hesper/main.go | manual: bad manifest exits 2 with structured error; run-init writes all four files |
| M0-6 | First full engine verify | M0-1…M0-5 | — | `scripts/dev.sh` → `BUILD-OK VET-OK TEST-OK` |
| M0-7 | Commit + push; CI green | M0-6 | GitHub Actions run | `gh run watch` → success on ubuntu-latest (go 1.23) |
| M0-8 | **Milestone report #1** to owner: scope-check demo output + CI link | M0-7 | report (chat) | delivered at boundary |

M0 exit criteria: all of the above; M0-8 delivered.

## 3. M1 — Lab lite & zero-vm

| ID | Task | Depends | Deliverables | DoD / verify |
|---|---|---|---|---|
| M1-1 | `lab/compose.lite.yaml`: VAmPI + DVWA + Velociraptor server, healthchecks, dedicated `lab-net`, volumes under `lab/state/` | — | compose file | `docker compose -f lab/compose.lite.yaml up -d` then all healthchecks pass |
| M1-2 | `internal/lab` orchestrator: `Up/Down/Status` via compose; `Health` struct; validate/pentest INIT refuses to start without healthy declared profile (design §5.7) + tests | M1-1 | internal/lab/*, tests | `hesper lab up --profile lite` → healthy; `down` leaves `docker ps` clean |
| M1-3 | zero-vm profile: `lab/compose.zero-vm.yaml` (EVTX-ATTACK-SAMPLES + chainsaw runner) + usage doc | — | compose file, lab/README update | offline scan demo command documented and runs |
| TV-1 | **Tech validation (front-loaded risk task)**: container ↔ Windows-VM networking — WSL2 NAT behavior, VM↔`lab-net` reachability, chosen topology written down | — (start parallel with M1) | docs/research/tv-networking.md | documented reachable/unreachable paths + selected topology + fallback; this unblocks M4-2 |
| M1-4 | Verify on this machine + **Milestone report #2** | M1-1…M1-3 | report | live endpoint probes (DVWA :4280, VAmPI :5002) shown |

## 4. M2 — Deterministic end-to-end finding

| ID | Task | Depends | Deliverables | DoD / verify |
|---|---|---|---|---|
| M2-1 | Action registry `internal/actions`: `LoadRegistry/Get/Candidates` + lint (provenance triple mandatory; `reuse=external` ⇒ proc/vm only; blocklist per design §5.2) + **CI gate: bad card ⇒ red** | M0 | internal/actions/*, 2 bad-card fixtures, ci.yml update | red-CI proof screenshot/log in milestone report |
| M2-2 | First action cards (provenance-carrying): one proc-adapter web probe against VAmPI, one nuclei-template card | M2-1 | actions/*.card.json | `hesper scope check`-style card lint verb passes; fixtures lint-fail correctly |
| M2-3 | Evidence store `internal/evidence`: hash chain (design §4.3/§5.4) `Append/Verify/Tail` + `hesper evidence verify <run-dir>` verb + tamper tests (flip a byte ⇒ verify fails) | M0-2 | internal/evidence/*, tests | verify passes on fresh run; fails on mutated fixture |
| M2-4 | proc adapter (design §5.3 `Execute`+emit) — **risk task, blocking**: argv-strict templates (planner params as argv elements, never shell) **with injection tests** (metacharacters in params must arrive as literal argv); **evidence semantics tests**: any missing `must_capture` kind ⇒ action recorded as not-happened and no finding may reference it | M2-1, M2-3 | internal/adapters/proc/*, injection_test.go, evidence_semantics_test.go | both test files green; explicitly named in report |
| M2-5 | findings module: gap rule exactly per design §4.4 (formal conditions) + markdown report renderer | M2-3 | internal/findings/*, internal/report/* | golden finding test; gap fires only when all four conditions hold |
| M2-6 | Deterministic driver: `hesper validate --scripted plan.json` (fixed proposal list, no LLM) end-to-end on lite lab | M2-2, M2-4, M2-5 | driver + example plan.json | scripted run on live lab → findings.json + report.md; `hesper evidence verify` passes |
| M2-7 | **Milestone report #3**: findings.json + report.md from the real run | M2-6 | report | delivered at boundary |

## 5. M3 — Planner loop (validate mode)

| ID | Task | Depends | Deliverables | DoD / verify |
|---|---|---|---|---|
| M3-1 | Planner interface + hallucination containment (unknown `card_id` / `params_schema` fail ⇒ `proposal.rejected` audited, returned as feedback) + tests | M2-1 | internal/planner/* | rejection tests green; audited events visible |
| M3-2 | Model client: openai_compatible + anthropic, key **by env var name only**, fallback chain, call budgets (design §4.5) | M0-3, M3-1 | internal/planner/client/* | contract test against a stub server; no key ever in files |
| M3-3 | StateView + prompt composition (scope digest, registry digest, `Tail()`-bounded evidence context) | M2-3, M3-1 | stateview.go, prompt.go | golden prompt test; context bounded by Tail |
| M3-4 | ENGAGE run loop per design §3 iteration contract (observe→propose→resolve→gate→spend→execute→update; deny/budget = feedback, not crash) | M3-2, M3-3, M2-6 | run loop in cmd/internal | unattended validate run on lite lab completes within budget |
| M3-5 | Kill switch: SIGINT + `hesper stop --run <dir>`; STOPPING drain; state persist/resume; forced second signal ⇒ ABORTED (exit 130) | M3-4 | signal handling, stop verb | mid-run kill demo in milestone report |
| M3-6 | Adapter quarantine (3 consecutive failures on same card ⇒ quarantined for run) | M3-4 | loop rule + test | forced-failure fixture test green |
| M3-7 | Benchmark baseline (design §8.6): fixed lite-profile run recorded; **Milestone report #4** (transcript + report + kill demo) | M3-4…M3-6 | runs/ artifacts, report | delivered at boundary |

## 6. M4 — Windows VM layer & detection correlation

| ID | Task | Depends | Deliverables | DoD / verify |
|---|---|---|---|---|
| M4-0 | **Preflight gate (risk task, runs FIRST)**: `hesper lab preflight` — CPU nested-virtualization detection (WSL2 KVM: Intel-only; AMD ⇒ advise Windows-host Vagrant path), Vagrant/VirtualBox presence check, disk/RAM budget check | M1 (TV-1 conclusion) | preflight command + docs | preflight runs and correctly identifies this machine's capability |
| M4-1 | VM range provisioning: MINILAB or single-DC + vulnerable-AD injection via Vagrant; **Windows eval-ISO wizard** (manual download step, checksum tracking, 180-day expiry rebuild note) | M4-0, TV-1 | lab/vagrant/*, wizard | `hesper lab up --profile lite-vms` brings up DC + workstation |
| M4-2 | VM↔container networking per TV-1 topology: Windows VM joins detection path | M4-1, TV-1 | network config | VM reaches Velociraptor server; proven by agent check-in |
| M4-3 | Telemetry + judges: Sysmon + sysmon-modular provisioning in VM; Velociraptor agent; `VelociraptorJudge` (online) + `OfflineJudge` (EVTX→chainsaw/hayabusa) behind one `Judge` interface; `judge.mode: auto` | M4-2 | internal/detection/* | a known ART technique produces hits via both paths |
| M4-4 | ART technique cards via vm adapter; correlation join on ATT&CK ID; `detection_gap` emission per §4.4; SigmaHQ author attribution into `sigma_hits[].author` | M4-3, M2-5 | vm adapter + cards | one Windows technique yields **hit or gap with evidence** on this machine |
| M4-5 | Egress hardening spike (design §7 M4+): control-proxy/netns wrapper around proc/vm; acceptance = deliberate egress-violation card blocked + `kernel.egress_violation` audited | M4-4 | enforcement wrapper + test card | violation card blocked and audited |
| M4-6 | **Milestone report #5**: hit-or-gap finding + evidence bundle | M4-4 | report | delivered at boundary |

## 7. M5 — Pentest mode & surfaces

| ID | Task | Depends | Deliverables | DoD / verify |
|---|---|---|---|---|
| M5-1 | Pentest mode: open-ended objective, termination = budget/kill only, opportunistic findings (design §3) | M3, M4 | mode wiring + tests | pentest run on lite+VM lab produces ≥1 valid finding |
| M5-2 | MCP server (`hesper mcp`) + npx wrapper (npm scope decision recorded: default `@jimmir45/hesper`, revisit at M5 start) | M5-1 | internal/mcp/*, wrapper | coding-agent round-trip: start/status/report via MCP |
| M5-3 | `claims.json` + `hesper claims verify`; README numbers traced to it (design §8.5) | M5-1 | claims harness | README claims all verify green |
| M5-4 | Release workflow (static binary, CGO off) + 30-second demo video: fresh `lab up` → unattended run → final report | M5-3 | release action, video | video recorded from clean state; release artifact attached |
| M5-5 | **Milestone report #6** (final staged result of v0 line) | M5-4 | report | delivered at boundary |

## 8. Risk register → task mapping (design-flagged risks are tasks, not prose)

| Risk (from design) | Task | Status |
|---|---|---|
| ① Container↔VM networking (WSL2 NAT + domain segment) | **TV-1**, front-loaded into M1, blocks M4-2 | planned |
| ② argv injection + "evidence missing = did not happen" semantics | **M2-4**, blocking tests, gate to M3 | planned |
| ③ Windows ISO manual step + WSL2 nested-virtualization Intel-only | **M4-0 preflight + M4-1 wizard**, M4 starts with the gate | planned |
| (added) Windows eval ISO 180-day expiry vs long-lived labs | M4-1 rebuild note + wizard checksum tracking | planned |

## 9. Scheduling assumptions and adjustments vs v0.1

1. **run.config contract pulled into M0** — design v1.0 added it (§4.5); contracts ship complete at M0 or the CLI surface lies.
2. **TV-1 front-loaded to M1** (was implicit in M4) — design lead flagged networking as the most underestimated risk; a spike before any VM spend.
3. **M2-4 security tests are blocking** — injection surface and evidence semantics must be proven before the planner (M3) amplifies them.
4. **M4 opens with M4-0 preflight** — no VM effort until the CPU/virtualization path is confirmed on this machine.
5. Assumption: WSL host is Intel; preflight verifies before M4 spend. Assumption: Velociraptor/chainsaw stay unlinked external containers (AGPL/GPL isolation), consistent with the license-layer model.
6. Estimates are deliberately omitted; DoD verification is the unit of progress.

## 10. Working agreements (restated, binding)

1. One report per milestone, with run logs/evidence attached; mid-milestone silence is protocol.
2. Commits prefixed by milestone (`M0:`, `TV:`, `fix:`); attribution line per repo convention.
3. Design changes = design.md version bump + changelog; plan changes = this file's version bump.
4. Environment: engine in WSL (Go 1.23, Docker 29); VM tooling arrives with M4-0/M4-1 only.
