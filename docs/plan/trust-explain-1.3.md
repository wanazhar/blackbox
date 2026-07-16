# Blackbox 1.3 — Trust, explain, and agent-native depth

| Field | Value |
|---|---|
| **Document** | Product + technical plan for 1.3 |
| **Date** | 2026-07-16 |
| **Status** | **In progress** — Phase 1 (T1 fail + T2 setup) implementing; **do not cut release yet** |
| **Baseline** | 1.2.0 + large unreleased master train (trust, debug, docs) |
| **Target tag** | **1.3.0** (when exit criteria below pass) |
| **North star** | Leave ambient on safely; when something fails, get a **story and a jump target** in one breath; agents can load that story without shell-scraping |

---

## Why 1.3 exists

| Version | Question answered |
|---|---|
| **1.0** | Is the capability daily-driver complete enough? |
| **1.1** | Would I leave ambient on? (contract, redaction, cost) |
| **1.2** | Do supervised launches deliver project memory? |
| **1.3** | When it fails (or I return tomorrow), do I **trust the store** and **get to the answer fast** — as a human *and* as an agent? |

1.2 made memory real. Post-1.2 master already added trust (redact/encrypt/vault), explain (postmortem/anomalies/TUI jump), eval (`--eval`), and human docs. Those are **1.3 cargo**, not a silent forever-unreleased pile.

1.3 also **adds** the missing product spine: collapse debug/onboarding to sharp commands, deepen MCP, package eval for CI, surface adapter health, and only **then** release.

---

## Problem (honest)

An adopter who found blackbox still hits:

| Friction | Why it blocks 1.3 “done” |
|---|---|
| **Too many entry commands** | Failure → `status` + `postmortem` + `timeline` + TUI keys; should be one move |
| **Ambient success is silent** | Leave-on works but feels dead; users never build the habit of `show latest` |
| **Agents under-use the store** | MCP lacks timeline/anomalies; skill exists but plugins don’t |
| **Eval is a flag, not a product** | `--eval` + artifacts need a stable score schema + GH Action shape |
| **Trust is configurable but not packaged** | encrypt_blobs + key file + backup is three knobs; users want “hardened project” |
| **Adapter silence** | Claude run with 0 `tool.call` looks “healthy” in coverage but is useless for debug |
| **Unreleased bulk** | 40+ commits ahead of origin; outside world still on 1.2.0 |

---

## Goals

1. **Explain in one move** — after a bad run, one command (or MCP tool) yields headline, next action, anomalies, and a path to the bad seq.
2. **Onboard in one move** — enable + shell + sample run + doctor readiness without reading five guides.
3. **Trust is a mode** — project can opt into a documented hardened profile without SQLCipher.
4. **Agents are first-class clients** — MCP covers the debug spine; session start is mechanical.
5. **Eval is shareable** — stable machine schema + CI recipe; still observe-only.
6. **Honesty** — doctor/adapters tell you when capture is lying (no tools, lag, low quality).
7. **Ship when green** — version, crates.io, Pages only after exit criteria (not before).

## Non-goals (1.3)

- Live SQLCipher for SQLite (keep sealed backup + blob encrypt)
- Hosted multi-tenant SaaS
- Perfect Windows interactive TUI parity as a gate
- Deterministic full LLM re-execution
- Auto-mining TODO/FIXME into open_items as default (optional later)
- Replacing harness UIs

---

## Already in the train (count as 1.3, do not re-build)

Treat as **done for plan purposes** unless regression appears:

| Theme | What’s in tree |
|---|---|
| Privacy / vault | owner modes, env allowlist, blob encrypt, sealed export, sticky seal, backup/restore, external key |
| Serve | Bearer-only, non-loopback token required |
| Explain | postmortem headline/evidence, anomalies, trajectory explain, TUI Enter/g, dashboard anomaly API/badges |
| Eval foothold | `--eval`, artifacts `anomalies.json` / `summary.txt` |
| Capture quality | coverage event, quality score, doctor daily-driver score |
| Claims | path-scoped + project |
| Docs | human track, recipes, cheatsheet, adapters, doctor guide, examples, MkDocs + docs.yml goldens |

**Work remaining = sections T1–T8 below.**

---

## 1.3 bar (exit criteria)

Leave the **1.3.0** tag only when **all** hold:

| # | Criterion | Measurable target |
|---|---|---|
| **T1** | **One-shot failure path** | ✅ `blackbox fail` — postmortem + anomalies + next; JSON; `tests/setup_fail.rs` |
| **T2** | **One-shot setup path** | ✅ `blackbox setup` — enable/shell/memory/harden/sample/doctor; `tests/setup_fail.rs` |
| **T3** | **MCP debug spine** | Tools for postmortem (exists), **timeline**, **anomalies** (and preferably **diff**); skill updated; unit list test |
| **T4** | **Eval score schema** | `blackbox.score/v1` (or artifact `score.json`) with exit, status, anomaly counts by severity/kind, coverage quality, optional tokens; `--eval` writes it; golden test |
| **T5** | **Hardened project profile** | Documented + implemented `setup --harden` or `enable --harden`: encrypt_blobs, external key hint, retention, native_log_scope=project, doctor notes clean |
| **T6** | **Adapter honesty** | Doctor (or postmortem) flags “structured-tool drought” for known harness adapters when tool.call count is 0 on a long run; test with synthetic events |
| **T7** | **Ambient acknowledgment** | Optional quiet-default **one-line** ambient complete notice (config off for power users); contract test that notice does not break passthrough/OFF |
| **T8** | **Release gate** | `cargo test` + clippy + doc links + docs site build green; CHANGELOG 1.3.0 section; version bump; **only then** tag/publish/Pages |

A1–A7 and M1–M7 remain permanent.

---

## Workstreams (what to add)

### T1 — `blackbox fail` (debugger spine)

**Intent:** Collapse `status` + `postmortem latest` + hints into the command people run when angry.

| Item | Detail |
|---|---|
| CLI | `blackbox fail [run]` default `latest` failed/attention run; human text + `--json` |
| Behavior | Resolve focus: attention.run_id → last_failure → latest non-success → latest |
| Output | headline, next_action, top anomalies, evidence with seq, suggested `timeline`/`show --tui` |
| MCP | Ensure `blackbox_postmortem` + new tools are enough; optional `blackbox_fail` alias |
| Tests | Failed synthetic run → fail command fields; no-runs error code |
| Docs | cheatsheet, recipes §3, debug-a-failure lead with `fail` |

**Not:** open browser automatically (optional later `--web`).

---

### T2 — `blackbox setup` (onboarding spine)

**Intent:** First 5 minutes without reading the world.

| Item | Detail |
|---|---|
| CLI | `blackbox setup [--memory-bus] [--install-shell] [--harden] [--no-sample]` |
| Steps | discover/create project → enable flags → optional shell → optional sample `true`/`echo` → doctor summary |
| Exit | non-zero if doctor not ready **and** `--require-ready` (default soft warn) |
| Tests | temp dir setup creates config + db after sample |
| Docs | getting-started points to setup first |

---

### T3 — MCP + agent packaging

| Item | Detail |
|---|---|
| MCP tools | `blackbox_timeline` (run_id, semantic, kind?, limit?), `blackbox_anomalies` (run_id), optional `blackbox_diff` |
| Skill | Update for new tools; fail/setup commands |
| Plugin packaging | Minimal Claude Code / Cursor install snippets (repo `plugins/` or docs only if marketplaces lag) |
| Continuity honesty | Optional stronger preamble marker + docs; explore `require_memory_read` only if low-cost (may slip to 1.4) |

---

### T4 — Eval productization

| Item | Detail |
|---|---|
| Schema | `blackbox.score/v1`: `run_id`, `exit_code`, `status`, `anomalies` summary, `capture_quality`, `duration_ms`, `tags`, `adapter` |
| Write path | `--eval` / `--artifact-dir` always write `score.json` |
| Compare | `blackbox eval-report <dir>` **or** document jq recipe in 1.3 if CLI slips |
| GH Action | Composite action in-repo: install blackbox, run `--eval --artifact-dir`, upload artifacts |
| Tests | score.json shape golden |

---

### T5 — Hardened trust profile

| Item | Detail |
|---|---|
| Config | `setup --harden` / `enable --harden` sets encrypt_blobs, observe-friendly defaults, native_log_scope=project, retention auto_apply |
| Key | Prefer external key path creation under `~/.config/blackbox/` with 0600 + doctor tip |
| Backup | Print one-liner for passphrase backup; do not force |
| Docs | security “hardened project” section |

---

### T6 — Adapter / capture honesty

| Item | Detail |
|---|---|
| Signal | For adapter ∈ {claude,codex,…}, if duration or event count above threshold and `tool.call` == 0 → warning note |
| Surfaces | `capture.warning` or coverage notes + doctor last-run note |
| Dashboard | Optional badge “no structured tools” |
| Tests | Synthetic claude-tagged run without tool.call |

---

### T7 — Ambient presence (subtle)

| Item | Detail |
|---|---|
| Config | `capture.ambient_notice = true` default **false** or true with one-line only — pick in implementation with A1 green |
| Content | `blackbox: recorded <short_id> (exit=N)` on stderr of wrapper path only when recording |
| Never | notice on passthrough/OFF/missing binary |

---

### T8 — Release engineering (end of train only)

| Item | Detail |
|---|---|
| Version | bump to 1.3.0 in Cargo.toml |
| CHANGELOG | dated 1.3.0 section (collapse Unreleased) |
| Publish | crates.io + tag; enable Pages if not already |
| Smoke | install.sh / cargo install path on clean machine checklist in PUBLISH.md |

**Do not start T8 until T1–T7 criteria are green** (T7 can be config-default debate; T5–T6 are in).

---

## Stretch (nice for 1.3, not blocking)

| Item | Note |
|---|---|
| `blackbox open --web latest` | Dashboard deep-link with seq |
| Serve SSE notify (less polling) | Perf |
| `fail --tui` | Jump straight to failure story mode |
| Devcontainer snippet | Agent-in-container |
| Homebrew formula draft | Distribution |
| Trajectory “vs previous same name” | Diff UX |

---

## Implementation order (recommended)

```text
Phase 0  Freeze scope; keep merging only 1.3 train items
    │
Phase 1  T1 fail + T2 setup          ← user-visible spine
    │
Phase 2  T3 MCP timeline/anomalies   ← agent spine
    │
Phase 3  T4 score.json + GH Action   ← eval spine
    │
Phase 4  T5 harden + T6 adapter drought + T7 ambient notice
    │
Phase 5  Docs pass (cheatsheet/recipes/skill) + goldens
    │
Phase 6  T8 release                  ← only when bar green
```

Parallelism: T3 and T4 can proceed beside T1/T2 after Phase 1 API shapes stabilize.

---

## Module touch map (expected)

| Area | Likely paths |
|---|---|
| CLI | `src/cli.rs` — Setup/Fail subcommands |
| Status/summary | `src/status.rs`, `src/summary.rs`, `src/analysis/anomalies.rs` |
| MCP | `src/mcp.rs` |
| Config | `src/config.rs` — harden, ambient_notice |
| Run / ambient | `src/maybe_run.rs`, `src/shell_install.rs` |
| Doctor | `src/cli.rs` doctor builder |
| Eval artifacts | `write_ci_artifacts` path |
| Action | `.github/actions/blackbox-eval/` or `actions/eval` |
| Tests | `tests/docs_*`, new `tests/fail_setup.rs`, MCP list tests |
| Docs | guides + skill + ROADMAP + CHANGELOG |

---

## Testing plan

| Gate | Suite / check |
|---|---|
| Existing permanent | A1 ambient, A2 redaction, M2a memory, overhead_smoke, docs links, docs_first_run, docs_cli_envelope |
| New | fail/setup integration; score.json golden; MCP tools/list contains timeline+anomalies; adapter drought unit; harden config snapshot |
| Manual | Fresh machine: setup → ambient claude (or fake) → fail → export sealed |

---

## Docs plan (when implementing)

| Doc | Change |
|---|---|
| getting-started | Lead with `setup` |
| debug-a-failure / recipes | Lead with `fail` |
| cheatsheet | setup / fail / harden / score.json |
| mcp.md | new tools when-to-use |
| security | hardened profile |
| ROADMAP | 1.3 bar T1–T8; move stretch |
| skill | session + fail + MCP tools |

---

## Risks

| Risk | Mitigation |
|---|---|
| Scope creep to 1.4 agent-marketplace | Plugin = snippets + skill; no marketplace dependency |
| Ambient notice annoys | Default off or single stderr line; A1 must stay green |
| Harden breaks existing projects | Opt-in flag only |
| Eval schema churn | Version field `blackbox.score/v1`; additive fields later |
| Release pressure | T8 blocked on bar; no soft-ship |

---

## Success snapshot (for CHANGELOG 1.3.0)

> **1.3.0 — Trust & explain**  
> Setup and fail as one-shot human paths; MCP timeline/anomalies for agents; eval `score.json` + CI action; hardened project profile; adapter drought honesty; ambient optional notice. Vault/encrypt/anomalies/postmortem/TUI jump from the pre-1.3 train included.

---

## Open decisions (resolve during Phase 1)

1. **Command names:** `fail` vs `why` vs `last-failure`; `setup` vs `init`  
2. **Ambient notice default:** on vs off  
3. **`eval-report` CLI** in 1.3 vs jq-only  
4. **`blackbox_fail` MCP** vs composing existing tools  

Recommend: **`fail` / `setup`**, ambient notice **default off**, **score.json required**, eval-report **jq/docs unless cheap**, MCP **timeline+anomalies required**, `blackbox_fail` optional alias.

---

## Related

- Quality bar: [../ROADMAP.md](../ROADMAP.md)  
- Shipped design: [adoption-1.1.md](adoption-1.1.md), [agent-memory-bus-1.2.md](agent-memory-bus-1.2.md)  
- Operator today: [../guide/README.md](../guide/README.md)  
