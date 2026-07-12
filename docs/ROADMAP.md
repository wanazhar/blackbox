# Blackbox quality bar & roadmap

## Quality bar (what “best” means)

I would actually use this tool when **all** of the following are true:

1. **Secrets never at rest by default** — argv, env, terminal, and tool payloads are redacted before SQLite/blob write. Raw capture requires an explicit `--insecure-raw` flag.
2. **Timeline is true** — one sequencer owns sequence numbers; order matches capture order.
3. **Payloads are blobs** — large terminal/tool content lives in content-addressed blobs; metadata holds keys + small previews only.
4. **Checkpoints are honest** — end-of-run git/fs state is the *after* state, not a copy of *before*.
5. **Crashes recover** — opening the store marks abandoned `Running` runs as `Failed`.
6. **Store is project-local** — `.blackbox/blackbox.db` + `.blackbox/blobs/`, overridable via `BLACKBOX_DB`.
7. **Semantic signal is first-class** — harness adapters parse tool calls; analysis runs are wired into the CLI.
8. **Export is safe by default** — `export` redacts unless `--no-redact` is passed.
9. **Docs match the binary** — README + AGENTS.md describe real behavior.

## Attack order

| Phase | Theme | Status |
|---|---|---|
| **P0** | Trust: store path, secrets-at-rest, sequencer, blobs, checkpoints, orphans | **done** |
| **P1** | Usefulness: analysis CLI, inspect/diff, resume, scrub+gc, CI | **done** |
| **P2** | Fidelity: stream-json inject, SIGWINCH, native log poller | **done** (poller attached; coverage depends on harness paths) |
| **P3** | Replay: sandbox seed, mock tools, fork→`--launch` resume | **mostly done** |

## Non-goals (for now)

- Full multi-user server / remote store
- Perfect Windows parity (Linux/macOS first)
- Replacing the harness’s own session UI

## Design decisions (locked)

| Decision | Choice | Why |
|---|---|---|
| Secret policy | Redact-before-write default | A flight recorder that hoards API keys is unusable |
| Event ingress | Single writer task + monotonic seq | Concurrent seq assignment corrupted timelines |
| Terminal storage | Blob refs + short preview | JSON metadata cannot scale or redact cleanly |
| DB location | Project `.blackbox/` | Multi-project isolation; gitignore-friendly |
| Export default | Redacted | Sharing traces is the common case for agents |

When these P0 invariants hold, everything else (TUI polish, replay, analysis) becomes trustworthy additive work instead of theater.
