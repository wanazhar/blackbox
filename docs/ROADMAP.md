# Blackbox quality bar & roadmap

## Quality bar (what “best” means)

This tool is worth running on a machine that holds secrets when **all** of the following hold:

1. **Secrets never at rest by default** — argv, env, terminal, and tool payloads are redacted before SQLite/blob write. Raw capture requires an explicit `--insecure-raw` flag.
2. **Timeline is true** — one sequencer owns sequence numbers; order matches capture order.
3. **Payloads as blobs** — large terminal/tool content lives in content-addressed blobs; metadata holds keys + small previews only.
4. **Checkpoints are honest** — end-of-run git/fs state is the *after* state, not a copy of *before*.
5. **Crashes recover** — opening the store marks abandoned `Running` runs as `Failed`.
6. **Store is project-local** — `.blackbox/blackbox.db` + `.blackbox/blobs/`, overridable via `BLACKBOX_DB`.
7. **Semantic signal is first-class** — harness adapters parse tool calls; analysis is wired into the CLI.
8. **Export / sync are safe by default** — redacted unless `--no-redact` is passed.
9. **Docs match the binary** — README + AGENTS.md describe real behavior.
10. **Agent-native inspect** — global `--json` envelope; resume packs; MCP; handoff.

### Adoption bar (1.1 — leave it on)

Capability is not enough. Ambient capture stays enabled only when:

| # | Criterion | Target |
|---|---|---|
| **A1** | Ambient shell contract | Install/uninstall/OFF/nest/wrap tested; wrappers never hard-fail if binary missing |
| **A2** | Redaction regression gate | Structural IDs (SHA, blob keys, UUIDs) never scar; secrets still die; CI-blocking suite |
| **A3** | Resume-pack quality | Actionable headline + next action; budget held; failures beat raw transcript for agents |
| **A4** | Cost visibility | doctor/stats report DB + blob sizes + retention; soft warnings |
| **A5** | Docs match adoption reality | README/ROADMAP/CHANGELOG describe 1.1 bar honestly |
| **A6** | Capture overhead smoke | Soft wall-time budget for supervising `true` |
| **A7** | Broader adapters | First-class aider/gemini/cursor/opencode/grok (not only wrap+generic) |

Design source of truth: [`docs/plan/adoption-1.1.md`](plan/adoption-1.1.md).

## Current product

| Version | Story |
|---|---|
| **1.0.0** | Capability daily-driver: enable → capture → fail → handoff / MCP / auto-resume |
| **1.1.0** | Adoption bar **plus** former post-1.0 backlog (adapters, CI/eval, pricing opt-in, sandbox restore, shell soak, Windows soft kill) |

### 1.0 shipped (capability)

| Area | Status |
|---|---|
| PTY capture, redact-before-write, blobs, monotonic seq, checkpoints | **shipped** |
| Claude/Codex adapters + native logs; generic + stream protocol v1 | **shipped** |
| Expanded wrap list (aider/cursor/gemini/opencode/grok + claude/codex) | **shipped** |
| Analysis, search (FTS5), tags, stats, scrub/gc, export/import, sync, serve | **shipped** |
| Project enable / maybe-run / install-shell / uninstall-shell | **shipped** |
| status / handoff / sticky state / AGENT.md | **shipped** |
| Auto-resume on next launch | **shipped** |
| MCP stdio tools | **shipped** |
| Dashboard `/status` `/handoff` + API | **shipped** |
| Binary install script + release workflow | **shipped** |
| Retention auto_apply + opportunistic GC | **shipped** |
| Replay sandbox / fork | **mostly shipped** |

### 1.1 work (adoption + former backlog)

| Theme | Status |
|---|---|
| A1 Ambient shell contract | **done** |
| A2 Redaction structural gate | **done** |
| A3 Resume-pack quality | **done** |
| A4 Cost visibility (doctor/stats) | **done** |
| A5 Docs for adoption bar | **done** |
| A6 Overhead smoke | **done** (`tests/overhead_smoke.rs`) |
| A7 Deeper adapters | **done** (`src/adapters/agents.rs`, `detect.rs`) |
| Pricing table + config file | **done** — opt-in; `BLACKBOX_PRICING` / `.blackbox/pricing.toml` |
| Sandbox git restore + diff | **done** — `git archive` + apply `git_diff_blob` |
| CI/eval polish | **done** — `run --ci --artifact-dir`, `postmortem --fail-on-failure` |
| Real-shell soak | **done** — `tests/shell_soak.rs` (bash install → wrap → record) |
| Richer native log pollers | **done** — per-harness roots/filters + plaintext for aider |
| Windows signal / PowerShell install | **done** — taskkill soft/hard; `powershell` shell kind |
| 1.1.0 version bump + publish | **this release** |

## Backlog (post-1.1)

Residual polish only (core items folded into 1.1):

| Priority | Theme | Notes |
|---|---|---|
| Low | Sandbox: 3-way merge / conflict UX when `git apply` fails | Best-effort apply already shipped |
| Low | Full Windows interactive TUI parity | Soft/hard kill + PowerShell install shipped; PTY edge cases remain |
| Low | Per-harness session file format docs | Poller heuristics shipped; document vendor layouts as they stabilize |

## Non-goals

- Full multi-tenant hosted SaaS / remote multi-user ACLs
- Replacing the harness’s own session UI
- Perfect Windows parity as a release blocker
- Guaranteeing every interactive TUI agent emits machine-readable tool events
- Inventing `estimated_cost_usd` when cost estimation is off or model unknown

## Design decisions (locked)

| Decision | Choice | Why |
|---|---|---|
| Secret policy | Redact-before-write default | A flight recorder that hoards API keys is unusable |
| Event ingress | Single writer task + monotonic seq | Concurrent seq assignment corrupted timelines |
| Terminal storage | Blob refs + short preview | JSON metadata cannot scale or redact cleanly |
| DB location | Project `.blackbox/` | Multi-project isolation; gitignore-friendly |
| Export / sync default | Redacted | Sharing traces is the common case for agents |
| Package name | `blackbox-recorder` on crates.io | `blackbox` is taken; binary/lib stay `blackbox` |
| Ambient capture | Project-scoped enable + maybe-run | No silent global recording |
| Versioning | One product release at a time | Intermediate version trains confuse ship truth |
| 1.1 theme | Adoption + folded backlog | Avoid a hollow “leave it on” then immediate feature chase |
| Cost estimates | Opt-in only | Never invent prices |
| JSON compatibility | Additive fields only in 1.1 | Existing agent parsers must keep working |
