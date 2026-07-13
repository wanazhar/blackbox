# Blackbox quality bar & roadmap

## Quality bar (what "best" means)

This tool is worth running on a machine that holds secrets when **all** of the following hold:

1. **Secrets never at rest by default** -- argv, env, terminal, and tool payloads are redacted before SQLite/blob write. Raw capture requires an explicit `--insecure-raw` flag.
2. **Timeline is true** -- one sequencer owns sequence numbers; order matches capture order.
3. **Payloads as blobs** -- large terminal/tool content lives in content-addressed blobs; metadata holds keys + small previews only.
4. **Checkpoints are honest** -- end-of-run git/fs state is the *after* state, not a copy of *before*.
5. **Crashes recover** -- opening the store marks abandoned `Running` runs as `Failed`.
6. **Store is project-local** -- `.blackbox/blackbox.db` + `.blackbox/blobs/`, overridable via `BLACKBOX_DB`.
7. **Semantic signal is first-class** -- harness adapters parse tool calls; analysis is wired into the CLI.
8. **Export / sync are safe by default** -- redacted unless `--no-redact` is passed.
9. **Docs match the binary** -- README + AGENTS.md describe real behavior.
10. **Agent-native inspect** -- global `--json` envelope; resume packs; MCP; handoff.

## Current product

| Version | Story |
|---|---|
| **1.0.0** | Capability daily-driver: enable -> capture -> fail -> handoff / MCP / auto-resume |
| **1.1.0** | Adoption bar + folded post-1.0 backlog (adapters, CI/eval, pricing, sandbox restore, shell soak, Windows) |
| **1.2.0** | **Agent Memory Bus / Continuity plane** -- default launch delivers project memory; sticky v2 + claims + M6 attention |

### Adoption bar (1.1 -- leave it on)

| # | Criterion | Target |
|---|---|---|
| **A1** | Ambient shell contract | Install/uninstall/OFF/nest/wrap tested; wrappers never hard-fail if binary missing |
| **A2** | Redaction regression gate | Structural IDs (SHA, blob keys, UUIDs) never scar; secrets still die; CI-blocking suite |
| **A3** | Resume-pack quality | Actionable headline + next action; budget held; failures beat raw transcript |
| **A4** | Cost visibility | doctor/stats report DB + blob sizes + retention; soft warnings |
| **A5** | Docs match adoption reality | README/ROADMAP/CHANGELOG describe 1.1 bar honestly |
| **A6** | Capture overhead smoke | Soft wall-time budget for supervising `true` |
| **A7** | Broader adapters | First-class aider/gemini/cursor/opencode/grok (not only wrap+generic) |

Design: [`docs/plan/adoption-1.1.md`](plan/adoption-1.1.md).

### Memory bus bar (1.2 -- M1-M7)

| # | Criterion | Target |
|---|---|---|
| **M1** | Materialize + inject on launch paths | `continuity=always` injects; `attention` clean skips launch inject; end-of-run always refreshes MEMORY when != off |
| **M2a** | Pack structural quality | CI suite `tests/memory_pack_quality.rs` |
| **M3** | Side effects surface | `side_effects_top`, `destructive_paths`, `secret_redaction_events` |
| **M4** | Multi-agent claim MVP | One project claim under `state.lock`; exclusive acquire |
| **M5** | Sessions disposable | Pack from store+sticky; degraded sticky-only if store fails |
| **M6** | Silent failure discipline | `apply_run_outcome`; unrelated success does not clear failure |
| **M7** | Trust settled | Redaction on MEMORY paths; doctor memory plane fields |

Design: [`docs/plan/agent-memory-bus-1.2.md`](plan/agent-memory-bus-1.2.md). **A1-A7 remain permanent.**

## Backlog (post-1.2)

| Priority | Theme | Notes |
|---|---|---|
| Low | Path-scoped claims | Extend project-wide claim to subdirectory scope |
| Low | Auto TODO/FIXME open_items | Scan for TODO/FIXME markers to auto-populate open_items |
| Low | Sandbox 3-way merge / conflict UX | Best-effort git apply already shipped; improve UX on conflict |
| Low | Full Windows interactive TUI parity | Soft/hard kill + PowerShell install shipped; PTY edge cases remain |
| Low | Per-harness session file format docs | Poller heuristics shipped; document vendor layouts as they stabilize |

## Non-goals

- Full multi-tenant hosted SaaS / remote multi-user ACLs
- Replacing the harness's own session UI
- Perfect Windows parity as a release blocker
- Guaranteeing every interactive TUI agent emits machine-readable tool events
- Inventing `estimated_cost_usd` when cost estimation is off or model unknown
