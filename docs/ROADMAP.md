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

## Current product (1.0.0)

Leave it on for Linux/macOS agent work:

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
| Replay sandbox / fork | **mostly shipped** (restore still best-effort) |

## Backlog (post-1.0)

| Theme | Notes |
|---|---|
| Deeper harness adapters | First-class Cursor/Aider/Gemini parsers beyond wrap + generic |
| Sandbox workspace restore | git checkout of checkpoint; not full FS guarantee |
| Windows PTY/signal parity | Non-blocking |
| Pricing table for `estimated_cost_usd` | Off by default (never invent prices) |
| CI/eval mode polish | exit codes + artifact export conventions |

## Non-goals

- Full multi-tenant hosted SaaS / remote multi-user ACLs
- Replacing the harness’s own session UI
- Perfect Windows parity as a release blocker
- Guaranteeing every interactive TUI agent emits machine-readable tool events

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
