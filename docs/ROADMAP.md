# Blackbox quality bar & roadmap

## Quality bar (what “best” means)

This tool is worth running on a machine that holds secrets when **all** of the following hold:

1. **Secrets never at rest by default** — argv, env, terminal, and tool payloads are redacted before SQLite/blob write. Raw capture requires an explicit `--insecure-raw` flag.
2. **Timeline is true** — one sequencer owns sequence numbers; order matches capture order.
3. **Payloads are blobs** — large terminal/tool content lives in content-addressed blobs; metadata holds keys + small previews only.
4. **Checkpoints are honest** — end-of-run git/fs state is the *after* state, not a copy of *before*.
5. **Crashes recover** — opening the store marks abandoned `Running` runs as `Failed`.
6. **Store is project-local** — `.blackbox/blackbox.db` + `.blackbox/blobs/`, overridable via `BLACKBOX_DB`.
7. **Semantic signal is first-class** — harness adapters parse tool calls; analysis is wired into the CLI.
8. **Export / sync are safe by default** — redacted unless `--no-redact` is passed.
9. **Docs match the binary** — README + AGENTS.md describe real behavior.

## Shipped (0.1.0)

| Area | Status |
|---|---|
| **P0 Trust** — store path, secrets-at-rest, sequencer, blobs, checkpoints, orphan recovery | **done** |
| **P1 Usefulness** — analysis CLI, inspect/diff, resume, scrub+gc, CI, search, tags, stats | **done** |
| **P2 Fidelity** — stream-json inject, SIGWINCH, native log poller | **done** (coverage still depends on harness paths) |
| **P3 Replay** — sandbox seed, mock tools, fork → `--launch` | **mostly done** |
| **Share** — portable v2 + blobs, import, dir/HTTP/S3 sync, local serve + SSE | **done** for single-user / team folder / object store |

Historical phase plans (scaffold → integration → limits) are archived under [`docs/history/`](history/).

## Next (post-0.1)

Prioritized candidates — pick based on user pain, not completeness theater:

| Priority | Theme | Notes |
|---|---|---|
| **Ops** | Binary releases / install scripts | Optional GitHub Actions release assets; `cargo install` remains primary |
| **Fidelity** | Broader harness coverage | More Claude/Codex log layouts; optional Cursor/other adapters |
| **Replay** | Stronger sandbox policy | Clearer allow/deny, workspace restore from checkpoints |
| **Serve** | Auth + multi-client polish | Token is shared-secret only; no multi-user ACLs yet |
| **Store** | Migration / vacuum UX | Doctor guidance when legacy `./blackbox.db` is in use |
| **Perf** | Large-run timeline / FTS | Coalesce + index tuning for multi-hour agent sessions |
| **Windows** | Parity | PTY and signal paths are Linux/macOS-first today |

## Non-goals (for now)

- Full multi-tenant hosted SaaS / remote multi-user store with ACLs
- Replacing the harness’s own session UI
- Perfect Windows parity in 0.1
- Guaranteeing every interactive agent UI emits machine-readable tool events (adapters do best-effort)

## Design decisions (locked)

| Decision | Choice | Why |
|---|---|---|
| Secret policy | Redact-before-write default | A flight recorder that hoards API keys is unusable |
| Event ingress | Single writer task + monotonic seq | Concurrent seq assignment corrupted timelines |
| Terminal storage | Blob refs + short preview | JSON metadata cannot scale or redact cleanly |
| DB location | Project `.blackbox/` | Multi-project isolation; gitignore-friendly |
| Export / sync default | Redacted | Sharing traces is the common case for agents |
| Package name | `blackbox-recorder` on crates.io | `blackbox` is taken; binary/lib stay `blackbox` |

When the quality-bar invariants hold, everything else (TUI polish, more adapters, release packaging) is trustworthy additive work instead of theater.
