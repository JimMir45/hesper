# Hesper — Detailed Design v1.0

> Status: **authoritative working design** · 2026-11-20 · supersedes v0.1 (changelog in §10)
> Author: Hesper design working group (AI-assisted)
> Inputs: [architecture.md](architecture.md) · research reports in [research/](research/) · current code baseline (internal/kernel/scope.go, decision.go; budget/audit/tests, schemas/, cmd/ land with M0 completion)
> Contract: this document is the build contract. Changes arrive as commits with a version bump and a §10 changelog entry, never as silent edits.

## 0. TL;DR

Hesper is a **headless engine** (single static Go binary) in which an LLM-driven agent autonomously executes real attack chains — web/API entry, credential access, lateral movement, endpoint — inside a **bundled lab**, and emits **evidence-grounded findings**: proof an exposure is exploitable, proof it is not, and — the wedge — **detection-gap findings** (action succeeded, no detection fired). Governing principle, enforced by construction: **the model proposes, the kernel permits, the artifacts prove.**

## 1. Goals and non-goals

**Goals**

1. Dual-mode runs from day one: `validate` (per-target assertions proven/disproven, with detection correlation) and `pentest` (open-ended exploration under scope).
2. Evidence as a first-class data type: hash-chained, replayable; a run is a self-contained evidence package.
3. Fail-closed governance kernel: scope gates, budgets, kill switch, append-only audit.
4. Model-agnostic planner: API-only (OpenAI-compatible + Anthropic), no agent-framework dependency.
5. Composition of mature OSS: audited action vocabulary and lab ranges with per-card provenance.
6. Distribution: one static binary; MCP/npx/CI surfaces.

**Non-goals (explicit)**

- No web dashboard in the core; shells (CLI/IM/MCP/CI) sit above the headless core.
- No exploit development; Hesper orchestrates known techniques.
- No SIEM; findings are downstream-consumable, detections stay external.
- No multi-tenant cloud service before 1.0.

## 2. Architecture overview

```
                      ┌─────────────────────────────┐
 scope.json ─────────▶│  KERNEL (fail-closed)       │────▶ audit.jsonl (append-only)
 run.config.json ────▶│  target·adapter·tech gates  │
                      │  budget · kill switch       │
                      └──────┬──────────────────────┘
                             │ allowed?
 ┌───────────────┐           ▼
 │ PLANNER (LLM) │──Proposal──▶ ACTION REGISTRY ───▶ ADAPTERS ───▶ LAB TARGETS
 │ model-agnostic│  (unknown card   (cards: ATT&CK,      │ lib       (docker containers
 └───────▲───────┘   ⇒ rejected)   provenance,          │ proc       + Windows VMs)
         │ state                   preconditions)       │ vm
         │                                              │
         └───────── EVIDENCE STORE ◀── artifacts ───────┘
                        │  (hash-chained records)
                        ▼
                 DETECTION JUDGE ◀── Sigma hits (Velociraptor online / chainsaw offline)
                        │
                        ▼
                  FINDINGS ──▶ REPORT (canonical JSON + rendered markdown)
```

| Component | Responsibility | Explicitly not responsible for |
|---|---|---|
| Kernel | authorization, budget, kill switch, audit | planning, execution |
| Planner | proposing actions with rationale | executing; output is advisory until kernel permits |
| Action Registry | card loading, provenance lint, precondition matching | running actions |
| Adapters | executing one action, capturing artifacts | choosing actions |
| Evidence Store | immutable hash-chained records, artifact integrity | interpretation |
| Detection Judge | Sigma correlation, gap findings | generating detections |
| Lab Orchestrator | range up/down/status per profile | run-scoped decisions |

## 3. Run model and lifecycle

**Run directory layout** (one engagement = one directory):

```
runs/<UTC-timestamp>/
  audit.jsonl            # append-only kernel + action events (single writer)
  scope.snapshot.json    # exact manifest in force
  run.config.json        # resolved run configuration snapshot
  state/                 # planner state snapshots (persisted for resume/audit)
  evidence/
    <action_id>/         # per-action artifact bundle
    chain.jsonl          # hash-chained EvidenceRecords
  findings.json
  report.md
```

**State machine** (run level; phases inside ENGAGE are planner decisions, kernel-gated):

| State | Meaning | Exits |
|---|---|---|
| `INIT` | scope + config loaded, lab health checked, audit opened | → RECON; → ABORTED (scope/lab failure) |
| `RECON` | inventory within scope | → ENGAGE; → CORRELATE (validate mode may skip if no assertions reachable) |
| `ENGAGE` | agent loop: observe → propose → gate → execute → capture → update | → CORRELATE (objective/budget) ; → STOPPING (kill) |
| `CORRELATE` | detection judge over recorded actions | → REPORT |
| `REPORT` | findings.json + report.md rendered | → DONE |
| `STOPPING` | kill switch drain: no new proposals, in-flight action finishes, state persisted | → STOPPED |
| `STOPPED` / `ABORTED` | terminal | — |

**Mode termination semantics**

- `validate`: terminal success = every target assertion reaches `proven` or `disproven`; early exit allowed when assertions exhaust. Unreachable assertions at budget exhaustion ⇒ reported as `disproven` **only** with attempted-evidence, else `inconclusive` recorded in run summary (never silently dropped).
- `pentest`: runs to budget or kill; no per-assertion closure. Findings accumulate opportunistically.

**Loop iteration contract**: one iteration = Observe (StateView) → Propose (≤N Proposals) → Resolve (registry) → Gate (kernel) → Spend (budget) → Execute (adapter + evidence emit) → Update (state + planner feedback). A denied/budget-failed step returns structured feedback to the planner; it is an observation, not a crash.

## 4. Contracts (v0)

**Policy: JSON-first.** All v0 contracts are JSON, parsed with stdlib `encoding/json` — zero external dependencies at M0. A YAML facade (`yaml.v3`) becomes the authoring format once the registry stabilizes; JSON stays canonical.

**Versioning**: every document carries `version` = `major.minor`. Readers refuse unknown **major** versions (fail-closed). Breaking change ⇒ major bump + §10 entry. Minor = additive optional fields.

### 4.1 scope.manifest (authorization)

| Field | Type | Req | Semantics |
|---|---|---|---|
| `version` | string | ✓ | contract version |
| `mode` | `validate`\|`pentest` | ✓ | must match the command |
| `name` | string | — | human label |
| `targets[]` | `{kind: host\|cidr\|domain, value, comment}` | ✓ ≥1 | authorization boundary; adapters receive kernel-validated TargetRefs only |
| `allow.technique_ids[]` | ATT&CK IDs | — | empty (with classes empty) ⇒ deny all techniques |
| `allow.classes[]` | `web\|creds\|lateral\|endpoint` | — | — |
| `allow.adapters[]` | `lib\|proc\|vm` | ✓ non-empty | — |
| `deny[]` | technique IDs or classes | — | overrides allow |
| `budget` | `{max_actions, max_minutes}` | ✓ positive | hard limits |
| `stop_conditions[]` | string | — | planner hints (advisory) |

### 4.2 action.card (action vocabulary)

| Field | Req | Semantics |
|---|---|---|
| `id` | ✓ | stable registry key |
| `title` | ✓ | human summary |
| `attack.technique_id`, `attack.tactic` | ✓ | ATT&CK mapping — the join key |
| `provenance` | ✓ | `{source_repo, commit, license}` — CI blocks cards missing any field |
| `reuse` | ✓ | `embedded\|external\|data_borrow` — the three license layers from the selection research |
| `preconditions` | — | `{phase, os, ports[], creds[], notes}` matched against StateView |
| `params_schema` | — | JSON Schema for `params` |
| `executor` | ✓ | `{adapter: lib\|proc\|vm, binding}` — binding format is adapter-specific (§5.3) |
| `evidence.must_capture[]` | ✓ | artifact kinds without which the action **did not happen** (§4.4 gap rule) |
| `detection.expected_sigma[]` | — | Sigma rule IDs that should fire if telemetry exists |
| `risks` | — | blast-radius note for approval UX |

Shape follows TTPForge YAML (MIT, Meta) as reference format; JSON encoding is ours. Blocklist (RTA, PEASS-ng, SharpView, Exploit-DB) is a registry-lint rule, not prose.

### 4.3 evidence.record (immutable trail)

```json
{
  "seq": 7, "ts": "RFC3339", "run_id": "...", "action_id": "...",
  "event": "action.executed | artifact.captured | gate.decision | ...",
  "artifacts": [{"path": "...", "sha256": "...", "kind": "stdout|file|pcap|evtx|..."}],
  "result": {"success": true, "detail": "..."},
  "prev_hash": "sha256 of previous chain record",
  "hash": "sha256(canonical(record without hash))"
}
```

Rules: append-only; single writer (the run loop goroutine); `Verify()` recomputes the chain and artifact hashes — `hesper evidence verify <run-dir>` is a CLI verb. A finding referencing evidence that fails verification is invalid by construction.

### 4.4 finding

| Field | Req | Semantics |
|---|---|---|
| `id`, `run_id`, `assertion` | ✓ | — |
| `attack_id` | ✓ | join key |
| `status` | ✓ | `proven \| disproven \| detection_gap` |
| `evidence[]` | ✓ for proven/gap | resolvable, chain-verified artifact refs |
| `repro[]` | ✓ for proven | deterministic replay steps |
| `sigma_hits[]` | on hit | `{rule_id, author, level, matches}` — `author` **required** when rules originate from SigmaHQ (DRL-1.1 attribution, implemented as schema) |
| `model_confidence` | — | advisory metadata; never the basis of a finding |

**detection_gap rule (formal)**:

```
gap ⟺ action.result.success == true
    ∧ every artifact kind in card.evidence.must_capture is present
    ∧ card.detection.expected_sigma is non-empty
    ∧ ∀ rule ∈ expected_sigma: hits(rule, window) = ∅
```

Partial hits ⇒ no gap; hits are attached to the `proven` finding instead.

### 4.5 run.config (operational, v0) — *new in v1.0*

Authorization (scope) and operation (config) are separated: scope says what is allowed; config says how we run.

| Field | Semantics |
|---|---|
| `model` | `{provider: openai_compatible\|anthropic, endpoint, model, api_key_env, fallback[]}` — API key **by env var name only**, never stored in files |
| `planner` | `{max_proposals_per_turn, temperature (default 0), max_context_tokens}` |
| `judge` | `{mode: auto\|velociraptor\|offline, correlation_window_s (default 120), velociraptor: {url, api_key_env}}` |
| `budgets` | planner-call token budget separate from action budget |

## 5. Component specifications

### 5.1 Kernel (`internal/kernel`) — baseline in repo

Existing: `ScopeManifest` load/validate (`scope.go`), deny-by-default gates (`decision.go`). To land in M0:

```go
type Budgeter struct{ /* mu, maxActions, deadline, used */ }
func NewBudgeter(b Budget, now time.Time) *Budgeter
func (b *Budgeter) SpendAction() (ok bool, reason string) // atomic; deadline checked
func (b *Budgeter) Exhausted() (bool, string)

type AuditLog struct{ /* file + mutex, single writer */ }
func OpenAudit(path string) (*AuditLog, error)
func (a *AuditLog) Append(event string, data map[string]any) error // JSONL + ts
```

Gate order (fixed): **target → adapter → deny-list → technique/class**; deny reasons are planner-readable strings. Kill switch: SIGINT or `hesper stop --run <dir>` ⇒ state `STOPPING`, no new proposals accepted, in-flight action drains (context cancellation respected by adapters), state persisted, terminal `STOPPED`; forced second signal ⇒ `ABORTED`.

### 5.2 Action Registry (`internal/actions`)

```go
type Registry struct{ /* index by id, lint results */ }
func LoadRegistry(root string) (*Registry, error) // loads actions/**/*.card.json, lints
func (r *Registry) Get(id string) (Card, bool)    // unknown id ⇒ caller treats as hallucination
func (r *Registry) Candidates(f Filter) []Card    // phase + target-trait prefilter for the planner
```

Load-time lint (also a CI gate): provenance triple mandatory; `reuse=external` cards must bind to proc/vm executors only; blocklist enforced.

### 5.3 Adapters (`internal/adapters/{lib,proc,vm}`)

Unified interface — one method plus an evidence emitter; collect is part of execute (driven by `must_capture`), not a separate phase:

```go
type ExecRequest struct {
    RunID, ActionID string
    Card    actions.Card
    Params  json.RawMessage   // pre-validated against card.params_schema
    Target  kernel.Target     // kernel-validated reference only — adapters never take raw hosts
    WorkDir string            // evidence/<action_id>/
}
type Adapter interface {
    Kind() string // lib | proc | vm
    Execute(ctx context.Context, req ExecRequest, emit func(evidence.Record) error) (ExecResult, error)
}
```

- **lib**: in-process Go libraries; Python libraries (Impacket, Certipy) via a pinned-venv child managed like a proc. Venv provisioned by the installer/`hesper lab`, never at run time.
- **proc**: external CLIs (NetExec, Nuclei engine, chainsaw/hayabusa) with strict argv templates — planner-supplied values pass as argv elements, **never** through a shell; stdout/stderr/exit code captured as artifacts.
- **vm**: staged executor on Windows targets (PurpleSharp-derived agent): file-drop channel, execute, pull artifacts. Needed for Sysmon-era telemetry and ART techniques.

All adapters: network egress only toward in-scope targets; violations emit `kernel.egress_violation` and abort the action (enforcement staging in §7).

### 5.4 Evidence Store (`internal/evidence`)

```go
type Store interface {
    Append(rec Record) (hash string, err error) // links rec.PrevHash to chain tail
    Verify(runDir string) error                 // recomputes chain + artifact SHA256s
    Tail(runDir string, n int) ([]Record, error) // planner context policy input
}
```

### 5.5 Detection Judge (`internal/detection`)

```go
type Judge interface {
    Correlate(ctx context.Context, w Window, actions []ActionRef) ([]Hit, error)
}
```

Two implementations behind one interface: **VelociraptorJudge** (VQL over the Velociraptor API; `Server.Import.CuratedSigma` + `Windows.Sigma.EventLogs`) and **OfflineJudge** (EVTX export → chainsaw/hayabusa → JSON hits). `judge.mode: auto` picks online when a Velociraptor endpoint is healthy, else offline. Correlation window from run.config (default 120s), joined on ATT&CK technique ID.

### 5.6 Planner (`internal/planner`)

```go
type Proposal struct {
    CardID    string          `json:"card_id"`
    Params    json.RawMessage `json:"params"`
    Target    string          `json:"target"`
    Rationale string          `json:"rationale"`
}
type Planner interface {
    Next(ctx context.Context, s StateView) ([]Proposal, error) // ≤ max_proposals_per_turn
}
```

- **Hallucination containment**: unknown `card_id` ⇒ `proposal.rejected{reason:"unknown_card"}` audited and returned to the planner as feedback; params failing `params_schema` ⇒ same path. Rejection is an observation, never fatal.
- Client: OpenAI-compatible + Anthropic, key by env var name, fallback chain; no framework.
- Prompt composition: role + scope digest (never raw manifest) + StateView (hosts, creds held, evidence tail) + registry digest (ids + preconditions only). Context bounded by `Tail()`, not full transcripts.
- Judgment: planner may draft finding narratives; the run loop binds them to chain-verified evidence. **A finding without resolvable verified evidence is invalid by construction.**

### 5.7 Lab Orchestrator (`internal/lab`)

```go
type Orchestrator interface {
    Up(ctx context.Context, profile string) (Health, error)
    Down(ctx context.Context, profile string) error
    Status(ctx context.Context, profile string) (Health, error)
}
```

Profiles: **lite** (~8–10 GB: VAmPI + DVWA + Velociraptor server; VM subset later), **full** (~24–27 GB: + juice-shop + GOAD-Light), **zero-vm** (EVTX-ATTACK-SAMPLES + chainsaw, CI). Containers via `docker compose`; AD VM layer via Vagrant/VirtualBox with a manual Windows-ISO wizard step (stated publicly, not hidden). State under `lab/state/` (git-ignored). Runs in `validate/pentest` modes require a healthy matching profile at INIT (config-declared), else refuse to start.

## 6. Error taxonomy and failure semantics

| Class | Trigger | Path | Exit code |
|---|---|---|---|
| `ScopeMissing/Parse/Invalid` | startup | refuse to start; no run dir mutated (fail-closed); error printed | 2 |
| `ConfigInvalid` | startup | refuse to start | 2 |
| `LabUnhealthy` | INIT health check | refuse to start (mode requires lab) | 1 |
| `GateDeny` | kernel gate | audit `gate.decision{allowed:false}`; planner feedback; run continues | — |
| `UnknownCard / SchemaInvalid params` | registry/schema | `proposal.rejected` audited; planner feedback | — |
| `BudgetExhausted` | actions/time | no new proposals; drain; CORRELATE→REPORT→DONE | 0 |
| `KillSwitch` | SIGINT / stop cmd | STOPPING→STOPPED | 130 |
| `AdapterError` (transient) | timeout, target unreachable | action failed, evidence of attempt recorded; planner may choose differently; same card failing N=3 consecutively ⇒ quarantined for the run | — |
| `AdapterEgressViolation` | egress outside scope | action aborted + audited; count ≥3 ⇒ STOPPED (policy) | 1 |
| `EvidenceViolation` | artifact missing/chain broken | finding invalid by construction; audited; run continues but finding not emitted | — |
| `JudgeError` | both judge paths fail | findings emitted without sigma attachment are marked `unjudged`; never silently presented as gap-free | 0 (warn) |

## 7. Governance enforcement staging (honesty clause)

- **M0–M3**: enforcement = kernel target gate + by-construction adapter contract (adapters accept kernel-validated `Target` refs only; proc templates are argv-strict). This is code review + type discipline, not network enforcement.
- **M4+ hardening (shipped, M4-5)**: runtime egress enforcement via a **local control proxy** (`internal/egress`): proc children run with proxy env pointing at the guard, which refuses any destination outside the scope manifest (403 + `kernel.egress_violation` audit + action failed). Violations count against a run-wide monitor: **≥3 ⇒ policy STOPPED, exit 1** (§6 — distinct from the kill switch's 130).
- **Enforcement reality matrix** (what each adapter actually gets, audited per action as `egress.enforcement{level}` so reports can never claim more than was enforced):

| Adapter | Level | Reach |
|---|---|---|
| proc (guard on, default) | `proxy` | proxy-AWARE clients (curl, wget, most scanners) are intercepted and refused out-of-scope. Proxy-unaware raw sockets bypass the proxy — full coverage would need netns/LD_PRELOAD, which is not portable across the WSL/Windows-host matrix. |
| proc (guard off, `egress.mode: off`) | `none` | kernel target gate + argv-strict type discipline only. |
| vm | `declared+audit` | the scope policy is declared and audited per action, but guest traffic does not traverse the host process stack — no local proxy can intercept it. Honest declaration, not interception. |

- Acceptance (design §7): the deliberate violation fixture `internal/adapters/proc/testdata/egress-violation.card.json` (TEST-NET-3 destination no legitimate scope contains) is blocked, fails its action, and trips the policy stop at three strikes — proven by `TestGuardedViolationFailsAction`, `TestEgressThreeStrikesStopsRunWithExit1`, and the guard-level tests.
- The README and design stay honest about this staging; ARTEX's lesson is that trust claims must match enforcement reality.

## 8. Testing and verification strategy

1. **Unit**: kernel gates table-driven with explicit fail-closed cases (missing scope, empty allowlists, deny override, CIDR/domain matching, budget exhaustion, kill-switch path); registry lint (provenance absent ⇒ error; external+lib ⇒ error; blocklist).
2. **Contract goldens**: every v0 document has golden examples round-tripped through the Go types; schema-invalid documents are test fixtures.
3. **Integration = the lab**: each milestone's DoD runs against the real bundled range on this machine; no mocked-only milestones.
4. **Provenance & blocklist CI gates**: bad card ⇒ red CI.
5. **verify-claims**: machine-checkable `claims.json` (e.g., "lite lab up < X s", "gap finding produced on demo target") verified by `hesper claims verify`; README numbers must trace to it.
6. **Benchmark**: fixed lite-profile validation run recorded per release; agent capability deltas measurable across models and versions.

## 9. Build and environment adaptation

- Engine builds/tests run in **WSL**: Go 1.23.12, Docker 29.1.3; entry `scripts/dev.sh` (build + vet + test; prints `BUILD-OK VET-OK TEST-OK`).
- Static binary: `CGO_ENABLED=0`; releases via GitHub Actions from M1.
- VM tooling (Vagrant/VirtualBox) **not installed** — lands with M4, including an installer wizard and a CPU-nested-virtualization preflight check (WSL2 KVM works on Intel only; AMD hosts must use Windows-host Vagrant — preflight must detect and advise).
- Windows evaluation ISOs: manual download by the user (license forbids redistribution); wizard tracks checksums and next steps.

## 10. Changelog vs v0.1

1. **Added run.config contract (§4.5)** — operational settings (model, judge, planner budgets) separated from authorization. v0.1 left the correlation window as prose inside scope; scope must stay purely about authorization.
2. **Added error taxonomy (§6)** with exit codes and per-class paths — v0.1 had fail-closed prose only; the CLI and planner need deterministic failure semantics (e.g., budget exhaustion terminates gracefully toward DONE, not an error).
3. **Adapter interface reduced to `Execute` + evidence emitter (§5.3)** — folding Prepare/Collect into one method driven by `must_capture` is harder to misuse than a three-method lifecycle; evidence is emitted at the point of capture.
4. **Egress enforcement staged honestly (§7)** — v0.1 implied kernel-time network enforcement; reality until M3 is type-level discipline, and the doc now says so.
5. **Evidence hash chain formalized (§4.3, §5.4)** with a verify verb — v0.1 mentioned hashing without chain semantics.
6. **Attribution corrected**: v0.1 credited an AI persona ("清水") that was a transcription artifact; replaced by neutral working-group attribution.
7. **Card `reuse` lint + project blocklist made a CI rule (§5.2)** — was prose in v0.1.
8. **Windows-VM CPU preflight added (§9)** — WSL2 nested virtualization is Intel-only; M4 planning must not assume otherwise.

## 11. Open questions (non-blocking)

1. npm scope for the npx wrapper (`@jimmir45/hesper` vs unscoped).
2. Finding schema external review before 1.0 (detection-engineering communities).
3. ATT&CK Navigator coverage-layer generation tooling (research lists as 待核实).
4. Whether `pentest` mode needs per-cred exposure rules in scope v1 (currently creds held are a StateView fact only).
