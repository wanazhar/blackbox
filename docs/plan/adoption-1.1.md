# Blackbox 1.1 — Adoption release (“leave it on”)

| Field | Value |
|---|---|
| **Document** | Product + technical design for 1.1 |
| **Date** | 2026-07-12 |
| **Status** | Shipped as **1.1.0** |
| **Baseline** | blackbox-recorder **1.0.0** |
| **Target** | **1.1.0** |
| **North star** | A flight recorder an agent (or agent operator) would leave ambient on forever |

---

## Why 1.1 exists

1.0 shipped the **capability** daily-driver: ambient capture, handoff, MCP, redaction, retention, dashboard.

1.1 ships the **adoption** daily-driver: prove those capabilities are free on good days and priceless on bad days.

1.0 answered: *“Is the product complete enough to market leave-on?”*  
1.1 answers: *“Would I actually leave it on?”*

---

## Problem

After 1.0, an honest adopter still churns for non-feature reasons:

| Friction | Why it kills ambient use |
|---|---|
| Shell / ambient unreliability | One double-wrap, nest surprise, or TUI breakage → `BLACKBOX_OFF=1` forever |
| Resume packs that don’t beat harness history | Agents ignore `handoff`; humans paste transcripts instead |
| Redaction trust is “seems fixed” | Structural scar history (SHAs, blob refs) makes secrets-first posture feel brittle |
| Unknown capture/store cost | Long sessions without budgets feel like background tax |

Post-1.0 backlog (deeper adapters, sandbox restore, cost table, Windows, CI polish) extends **surface area**. Adoption fails on **trust and boredom**, not missing subcommands.

---

## Goals

1. **Ambient is boring** — shell contract is tested; install/uninstall/nest/OFF are hard guarantees.
2. **Handoff is useful** — resume packs are actionable, bounded, and better than “read the transcript” for failed runs.
3. **Redaction is a permanent gate** — structural IDs never scar; secrets still die; regression suite is CI-blocking.
4. **Cost is visible and bounded** — doctor/stats report store growth; retention defaults stay self-managing; capture path has measurable overhead bounds where testable.
5. **Marketing honesty** — 1.1 may claim “leave it on” only after A1–A4 exit criteria pass.

## Non-goals (1.1)

- Hosted SaaS / multi-tenant ACLs
- Replacing harness session UIs
- Windows parity as a release blocker
- Perfect machine-readable events from every interactive TUI
- Large new CLI surface beyond CI/eval flags and pack fields

## Included former post-1.1 backlog (same release train)

Folded into 1.1 so “leave it on” is not immediately followed by another feature train:

| Item | 1.1 delivery |
|---|---|
| Deeper harness adapters | First-class `aider` / `gemini` / `cursor` / `opencode` / `grok` adapters + parsers |
| Capture overhead (A6) | `tests/overhead_smoke.rs` soft budget |
| Sandbox git restore | `git archive <sha>` into sandbox when checkpoint has `git_commit` |
| CI/eval polish | `run --ci` / `--artifact-dir`; `postmortem --fail-on-failure` |
| Pricing table | `src/pricing.rs` — **off by default** (`BLACKBOX_ESTIMATE_COST=1`) |

---

## Adoption bar (A1–A5)

Leave blackbox ambient-on when **all** hold:

| # | Criterion | Measurable target |
|---|---|---|
| **A1** | **Ambient shell contract** | Integration tests cover: install markers idempotent; uninstall removes markers; `BLACKBOX_OFF` never opens store; nest (`BLACKBOX_ACTIVE_RUN`) passthrough; wrap miss passthrough; enabled wrap records; missing `blackbox` binary falls through to bare command in generated snippets |
| **A2** | **Redaction regression gate** | Dedicated suite: pure hex SHA-40, SHA-256 blob keys, UUIDs, sequences, enum discriminators survive export + capture redaction paths; known secrets still redacted in free-form; portable export round-trip keeps structural keys |
| **A3** | **Resume-pack quality** | Pack schema includes explicit **attention signal**, **next action**, **failure headline**, ordered failed tools with truncated detail; hard token budget honored; tests assert: failed run pack is non-empty on failures, under budget, contains failure tools/errors when present, omits useless full transcript when over budget |
| **A4** | **Cost visibility** | `doctor` / `stats` report DB size, blob dir size, run count, event count, retention policy; warn thresholds documented; retention auto_apply remains default |
| **A5** | **Docs match reality** | README 1.1 quickstart leads with ambient + handoff; ROADMAP quality bar includes adoption criteria; CHANGELOG lists A1–A4 as 1.1 themes |

Optional stretch (not 1.1 blockers):

| # | Criterion | Notes |
|---|---|---|
| A6 | Capture overhead smoke | Micro-bench or timed `blackbox run -- true` / short script vs bare; document p95 budget or “no worse than X ms fixed overhead” if measurable in CI |
| A7 | Deeper adapters | Cursor/Aider/Gemini first-class parsers — post-1.1 |

---

## Design

### A1 — Ambient shell contract

**Existing pieces:** `maybe_run::decide`, `shell_install`, unit tests for decide/install.

**Gaps:**

- No end-to-end ambient path: enable project → maybe-run records a fake harness → nest does not double-record
- Snippet “blackbox missing → bare command” is string-level only; no contract test on generated script semantics
- No soak-style stress (many sequential maybe-run decisions)

**1.1 work:**

1. Integration test module `tests/ambient_contract.rs`:
   - Project enable via config write (or CLI `enable`)
   - `decide()` matrix as integration-level assertions with real temp dirs
   - CLI `blackbox maybe-run -- <helper>` where helper is a small script on PATH that prints and exits; assert one run in store when enabled+wrapped
   - Nested: set `BLACKBOX_ACTIVE_RUN=1` env for child decision → no second run
   - `BLACKBOX_OFF=1` → zero runs
   - Shell install: write to temp HOME; assert markers; re-install idempotent; uninstall clean
2. Document shell contract in `docs/agent-api.md` or a short `docs/ambient-contract.md` referenced from README
3. Harden only if tests find bugs (do not invent shell features)

**Shell contract (normative):**

```
maybe-run decision order:
  1. BLACKBOX_OFF          → passthrough (no store open)
  2. BLACKBOX_ACTIVE_RUN   → passthrough (no store open)
  3. no enabled project    → passthrough (no store open)
  4. basename ∉ wrap       → passthrough (no store open)
  5. else                  → record under discovered project store

Generated wrappers:
  - Prefer `command blackbox maybe-run -- <name> …`
  - If blackbox missing from PATH → invoke bare <name>
  - Install markers are idempotent; uninstall removes only managed block
```

### A2 — Redaction regression gate

**Existing pieces:** `ExportRedactor` allowlist; scanner comment forbidding whole-string base64; unit tests in `export.rs`; thin `tests/security.rs`.

**Gaps:**

- Gate is unit-local, not a named permanent suite agents/CI can point at
- Capture-time path (`SecretScanner` on argv/terminal) vs export path not both covered for structural preservation
- Portable export round-trip not asserted as “structural keys survive redacted export”

**1.1 work:**

1. Expand `tests/security.rs` (or `tests/redaction_gate.rs`) into the permanent gate:
   - Table-driven structural survivors: git SHA-40, sha256 hex, UUID, numeric sequence-as-string
   - Table-driven secrets that must die: AWS AKIA, `sk-…`, `ghp_…`, PEM-ish samples already in scanner tests
   - Capture: `SecretScanner::redact` must not alter pure structural strings
   - Export: `ExportRedactor` allowlist behavior
   - Portable export: if feasible in integration, push a mini-run through export redaction and assert blob map keys + run id intact
2. Wire gate into existing `cargo test` (no separate feature flag — always on)
3. Add a one-line pointer in `docs/ROADMAP.md` quality bar: “structural redaction gate green”

### A3 — Resume-pack quality

**Existing pieces:** `context::build_context_pack`, `status`/`handoff` attach pack on attention, auto-resume inject.

**Current weaknesses:**

- Pack is summary + failed tools + last tools + fs writes + transcript tail — no explicit **headline** or **recommended next action**
- Failed tool detail prefers raw `input` JSON, not error message
- Token budget shrinks transcript then FS then failed tools, but can still leave a large summary
- No tests on pack quality invariants

**1.1 work:**

1. Extend `ContextPackView` (additive JSON fields; keep existing fields):

```text
headline: string              // one-line failure/success status for agents
next_action: string           // what the next agent should do first
attention_reason: string      // why handoff fired (failed | abandoned | …)
errors_top: [...]             // top structured errors (cap small)
failed_tools: richer detail   // prefer error/output preview over input dump
```

2. Build order for usefulness over raw transcript:
   - Always include: run status, exit, headline, next_action, failed_tools (capped), errors_top (capped)
   - Then: last_tools, filesystem_writes, git from summary
   - Transcript tail last (drop first under budget)

3. Improve failed tool detail: for `tool.call`/`tool.result` errors, prefer `metadata.error`, `metadata.output` preview, else truncated input

4. Tests in `src/context.rs` and/or integration:
   - Synthetic failed run → pack has non-empty headline, next_action mentions handoff/resume intent, failed tool present, approx_tokens ≤ max_tokens
   - Huge transcript → truncated true, budget held, failed_tools retained before transcript

5. Keep MCP/`handoff` schemas in sync (`docs/agent-api.md`)

### A4 — Cost visibility

**Existing pieces:** retention config, `gc`, `stats`, `doctor`.

**1.1 work:**

1. Ensure `doctor --json` and/or `stats --json` include:
   - `db_bytes`, `blobs_bytes`, `blobs_count` (best-effort walk)
   - `runs_total`, `events_total` (or approx)
   - retention policy snapshot (`keep`, `auto_apply`)
2. Human doctor text prints a one-line storage summary + hint if over soft threshold (e.g. > 1 GiB blobs → “run blackbox gc”)
3. No aggressive new defaults that delete user data beyond existing auto_apply policy

### A5 — Docs

- README: 1.1 section “Why leave it on” tied to A1–A4
- ROADMAP: adoption bar; demote sandbox/pricing as non-1.1
- CHANGELOG: `[Unreleased]` / 1.1.0 themes
- This plan is source of truth for implementation order

---

## Key decisions

| Decision | Choice | Rationale |
|---|---|---|
| 1.1 theme | Adoption, not features | 1.0 surface is enough; churn is trust/friction |
| Blockers | A1–A5 only | A6/A7 nice-to-have; don’t slip 1.1 on adapters |
| Schema | Additive JSON fields only | Agents already parsing 1.0 envelopes must not break |
| Shell | Test + harden; no redesign | Contract is sound; proof is missing |
| Redaction | Permanent named gate in `tests/` | Unit tests alone didn’t prevent historical scar class |
| Resume pack | Prefer structured failure signal over transcript | Transcript is what harness already has |
| Cost | Visibility first, not new retention model | auto_apply already exists |
| Adapters/sandbox/cost table | Post-1.1 | Explicit demotion from “must ship soon” |

---

## PR plan

### PR-1 — Ambient shell contract tests (+ fixes if broken)
- **Files:** `tests/ambient_contract.rs`, `src/maybe_run.rs`, `src/shell_install.rs` (only if bugs), `docs/ambient-contract.md`
- **Deps:** none
- **Exit:** A1 tests green

### PR-2 — Redaction structural gate
- **Files:** `tests/redaction_gate.rs` (or expand `tests/security.rs`), possibly `src/redaction/*` if gaps
- **Deps:** none (parallel with PR-1)
- **Exit:** A2 green in `cargo test`

### PR-3 — Resume-pack quality
- **Files:** `src/context.rs`, `src/status.rs`, `src/resume_inject.rs`, `docs/agent-api.md`, tests
- **Deps:** none strictly; land after or parallel with PR-1/2
- **Exit:** A3 green

### PR-4 — Cost visibility in doctor/stats
- **Files:** `src/cli.rs` (doctor/stats), views if needed, tests
- **Deps:** none
- **Exit:** A4 green

### PR-5 — Deeper adapters + pricing + sandbox restore + CI/eval + overhead
- **Files:** `src/adapters/{agents,detect}.rs`, `src/pricing.rs`, `src/replay/sandbox.rs`, `src/cli.rs`, `tests/{overhead_smoke,ci_eval}.rs`
- **Deps:** none strictly
- **Exit:** former post-1.1 backlog items green in-tree

### PR-6 — Docs + version bump to 1.1.0
- **Files:** `Cargo.toml`, `README.md`, `CHANGELOG.md`, `docs/ROADMAP.md`, `AGENTS.md` if needed
- **Deps:** PR-1…PR-5
- **Exit:** A5; version 1.1.0

---

## Exit criteria (ship 1.1.0)

- [x] A1 Ambient contract tests + docs green
- [x] A2 Redaction gate green
- [x] A3 Resume-pack quality (fields + tests + inject) green
- [x] A4 Cost visibility in doctor/stats green
- [x] A5 Docs point at adoption bar (README/ROADMAP/CHANGELOG/agent-api)
- [x] Deeper adapters (aider/gemini/cursor/opencode/grok)
- [x] Optional pricing (`BLACKBOX_ESTIMATE_COST`)
- [x] Sandbox git archive restore from checkpoint SHA
- [x] CI/eval: `--ci`, `--artifact-dir`, `--fail-on-failure`
- [x] Overhead smoke budget test
- [x] Real-shell soak (`tests/shell_soak.rs`)
- [x] Richer native log pollers (per-harness)
- [x] Sandbox `git_diff_blob` apply
- [x] Pricing config file (`BLACKBOX_PRICING` / `.blackbox/pricing.toml`)
- [x] Windows signal helpers + PowerShell install
- [x] `cargo test` / `cargo clippy --all-targets -- -D warnings` clean
- [x] Version bump to **1.1.0** + release cut

---

## Open questions

None blocking. Defaults chosen above. Revisit only if:

- Ambient integration tests cannot invoke `maybe-run` without full PTY (then test `decide` + a thin `run` of `true` with wrap basename via PATH shim)
- Pack schema change needs versioning beyond additive fields (prefer additive)

---

## Relationship to older docs

| Doc | Role after 1.1 plan |
|---|---|
| `docs/plan/daily-driver-0.2.md` | Historical design for 0.2–0.4 capability train; archival value only |
| `docs/ROADMAP.md` | Living quality bar; must incorporate A1–A5 and demote non-adoption backlog |
| `docs/history/*` | Unchanged archival |
