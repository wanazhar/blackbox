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
10. **Agent-native inspect** — global `--json` envelope for the inspect loop; resume packs for retry.

Design notes (optional deep dive): [`docs/plan/daily-driver-0.2.md`](plan/daily-driver-0.2.md), [`docs/agent-api.md`](agent-api.md).

## Current product (0.3.0)

One ship unit — capture through agent feedback — not a ladder of half-versions:

| Area | Status |
|---|---|
| PTY capture, redact-before-write, blobs, monotonic seq, checkpoints | **shipped** |
| Claude/Codex adapters + native logs; generic + stream protocol v1 | **shipped** |
| Analysis, search (FTS5), tags, stats, scrub/gc, export/import, sync, serve | **shipped** |
| Safe export (structure preserved; secrets redacted) | **shipped** |
| Project `enable` / `maybe-run`, ancestor store discovery, config.toml | **shipped** |
| `--json` inspect, postmortem/summary, retention `gc` | **shipped** |
| Schema v6 metrics, trajectory diff, `context --for-resume` | **shipped** |
| Replay sandbox / fork | **mostly shipped** (restore still best-effort) |

## Backlog (no version theater)

Ship when it hurts not to have it — fold into the next release when ready:

| Theme | Notes |
|---|---|
| Binary releases / install scripts | GitHub Actions assets; `cargo install` stays primary |
| Broader harness coverage | Cursor / other adapters; more Claude/Codex layouts |
| Sandbox workspace restore | Spike: git checkout of checkpoint; not full FS guarantee |
| Dashboard polish | Summary/context routes after CLI is the source of truth |
| Optional MCP | Thin wrapper over Views — only if demand |
| Windows PTY/signal parity | Non-blocking; Linux/macOS first |
| Pricing table for `estimated_cost_usd` | Off by default (never invent prices) |

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
| Versioning | One product release at a time | Intermediate “0.2 floor / 0.3 loop” trains confuse ship truth |

When the quality-bar invariants hold, backlog items are trustworthy additive work instead of theater.
