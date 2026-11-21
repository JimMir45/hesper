# Hesper

> Headless AI-native agent for adversarial exposure validation.
> It breaks in like a real attacker — and proves it.

**Status: pre-alpha, under active design.** The engine, bundled lab, and evidence chain are being built — see [docs/architecture.md](docs/architecture.md) for the current blueprint and [docs/research/](docs/research/) for the groundwork behind it.

Hesper autonomously executes full attack chains — web/API entry, credential access, lateral movement, endpoint — inside a bundled, deliberately vulnerable lab, then answers the question security teams actually care about: **which defenses caught it, and which missed it.** Every finding ships with replayable evidence: the exact actions taken, artifacts on disk, raw requests/responses, and detection-rule hits (or the absence of them).

## Why Hesper

- **Autonomous validation, not scripted replay.** An agent loop plans, executes, observes, and re-tests. A scenario library with a scheduler is the old form of this category.
- **Detection-gap findings.** Join key = MITRE ATT&CK technique ID: action ↔ Sigma rule ↔ hit. "Action succeeded + zero hits = gap" is a first-class finding, not a footnote.
- **Headless by design.** CLI / MCP / CI. Machine-consumable in and out; the engine has no dashboard, the report is structured evidence.
- **Governance is a feature.** A scope manifest gates every planning decision: authorized targets only, fail-closed, hard stop, full audit log.
- **Evidence over claims.** Model output is a hypothesis; artifacts are proof. The bundled lab doubles as a regression benchmark — every iteration is measurable.

## Roadmap

- [ ] Bundled lab, lite profile (~10 GB, one machine): vulnerable web/API targets + mini AD range + offline detection chain
- [ ] Full-chain slice, validation mode: web entry → lateral movement → endpoint, with detection correlation
- [ ] Pentest mode: open-ended autonomous engagement under a scope manifest
- [ ] MCP / npx / CI integrations
- [ ] Full lab profile with a GOAD-Light AD range (~24 GB machines)

## Research

Every major decision is grounded in documented, license-audited research:

- [Competitive landscape](docs/research/prior-art-landscape-20261120.md) — 2024–2026 agentic offensive-security OSS, and why "autonomous full-chain validation + evidence chain" is unoccupied
- [Action-library selection](docs/research/action-library-selection-20261120.md) — 30 candidate projects, license-audited, three-layer reuse model
- [Bundled-lab composition](docs/research/lab-defense-stack-selection-20261120.md) — lab ranges and the detection stack, resource-budgeted for desktop machines

## Machine-checkable claims

Every capability claim in this README is backed by a claim in
[claims.json](claims.json) and re-verified by CI (`hesper claims verify`):

- planner parameters reach argv as literals — never a shell (C1)
- missing evidence ⇒ the action did not happen; no finding may cite it (C2)
- three egress violations stop the run with exit 1 (C3)
- Sigma rules without an author are a hard error — DRL-1.1 attribution (C4)
- the detection_gap verdict requires all four formal conditions (C5)
- tampering with any chained record or artifact breaks `evidence verify` (C6)

Live-lab claims (L1/L2) run with `hesper claims verify --with-live` when the
bundled lab is up. Numbers in prose that cannot be traced to a green claim
do not belong here.

## Responsible use

Hesper runs **only against explicitly authorized targets**, and ships with a legitimate practice range so there is no reason to point it at anything else. The scope manifest is not advisory: out-of-scope actions are refused before execution, and every action is written to the audit log.

How far that refusal actually reaches — stated exactly, never oversold (see the [design doc's enforcement matrix](docs/design.md#7-governance-enforcement-staging-honesty-clause)):

- **proc actions** run through a local egress guard that intercepts proxy-aware clients and refuses out-of-scope destinations (violation ⇒ action fails + audit; three violations ⇒ the run stops with exit 1). Proxy-unaware raw sockets are not intercepted.
- **vm actions** carry the scope as a declared, audited policy — guest traffic does not traverse the host stack, so this level is declaration, not interception.
- Every action records which level actually applied (`egress.enforcement` in the audit log), so a report can never claim more enforcement than happened.

## License

[Apache-2.0](LICENSE). Third-party attack actions are reused from open-source projects with per-card provenance (source repo, commit, license) — see the [architecture doc](docs/architecture.md).

---

*Name: Hesper (Hesperus), the evening star — the watch that begins at dusk.*
