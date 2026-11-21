# Hesper Demo Script — 30s hero cut (+45s full cut)

> Status: v1.0 · product-owned · blocked on: M4-1 live window (lab real runs) + real-model smoke (`HESPER_MODEL_API_KEY`).
> The demo IS the distribution engine (research: every fast-growing project in this category had one).
> Principle: all terminal, no dashboard — the headless engine is the product; the report is structured evidence.

## Hero cut (30s) — "it breaks in, and proves it"

| # | Time | Terminal | On-screen caption | Note |
|---|---|---|---|---|
| 1 | 0–3s | `$ hesper lab up --profile lite` → 4 containers → healthy | "a real attack range, one command" | speed-ramp the pull; end on green health |
| 2 | 3–6s | `$ hesper validate --scope lab.scope.json` → run starts | "an agent plans, the kernel permits" | show scope digest line |
| 3 | 6–14s | loop scrolls: 2–3 actions (`T1190 web probe ✓ evidence`, one denied by kernel → planner adapts) | "model proposes · kernel permits · artifacts prove" | the deny-then-adapt beat is the governance story |
| 4 | 14–21s | one action + Sigma HIT (rule + author flash); one action succeeds, ZERO hits → **DETECTION GAP** finding highlighted | "the finding nobody else ships: what you own that never fired" | THE wedge moment — biggest visual weight here |
| 5 | 21–26s | `$ hesper evidence verify` → `chain OK`; report.md findings table | "every finding: hash-chained, replayable" | |
| 6 | 26–30s | end card | **"Hesper breaks in like a real attacker — and proves it."** repo URL · Apache-2.0 · `claims verify: 11/11 ✓` | claims badge must be real output |

## Full cut (+15s governance tail)

7. mid-run `Ctrl+C` → `STOPPED, exit 130` → `--resume` → `DONE` ("kill it. resume it. budget survives.")
8. out-of-scope card → egress guard 403 → 3rd strike → run stops exit 1 ("three strikes: policy, not promises")

## Recording checklist

- Fresh state: `lab down && vagrant destroy` before recording; real model (not stub) — autonomy is the product.
- Terminal: 16–18pt mono, dark theme, no prompt noise (no proxy vars leaking etc.).
- Real terminal output only — every flashed number must trace to a green claim (`claims verify` before export).
- End card claims line is a screenshot of actual `hesper claims verify` output, not typography.

## Dependencies (do not record until)

1. M4-1 live checklist green (lab real runs incl. detection correlation) — pending idle window.
2. Real-model smoke passed (`HESPER_MODEL_API_KEY` + openai-compatible endpoint configured) — pending owner.
3. v0.1.0-alpha tagged & released (video links the release, not main) — pending owner sign-off.
