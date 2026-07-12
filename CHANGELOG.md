# Changelog

All notable changes to **blackbox** are documented here.

## [0.1.0] — 2026-07-12

First solid release candidate: a flight recorder you’d actually run on a machine with secrets.

### Capture & trust
- PTY supervision with stdin/EOF, SIGINT, SIGWINCH resize
- Redact-before-write for argv, env, and terminal (no `metadata.raw` secrets)
- Content-addressed blobs; terminal output coalescing
- Monotonic `EventWriter` sequencing + tool-call dedupe (PTY ∩ native logs)
- Project-local `.blackbox/` store; stale `Running` recovery
- Git before/after diffs, live filesystem watch, env capture, checkpoints

### Harness fidelity
- Claude/Codex adapters: stream-json / `--json` injection when safe
- Native log poller for `.claude` / `.codex` session files
- Structured `tool.call` / `tool.result` / session parsing
- Resume helpers + `fork --launch`

### Inspect & ops
- CLI: show/timeline/inspect/diff/analyze/export/replay/fork/rm/purge
- Search (SQLite **FTS5**), watch, tags, stats, doctor, scrub --gc
- Transcript rebuild (`show --transcript` / `--tools`)
- HTML export with tools, filters, dark mode
- Shell completions (bash/zsh/fish)

### Web dashboard
- `blackbox serve` local UI + JSON API
- Live SSE stream: `/api/runs/{id}/events/stream`
- Live run list SSE: `/api/runs/stream` (index auto-updates)
- Live run page + `/watch` shortcut
- Optional shared-secret auth (`--token` / `BLACKBOX_SERVE_TOKEN`)

### Share / sync
- Portable **v2** JSON export with **embedded blobs** (offline-complete)
- `blackbox import` accepts v1/v2 (new ids by default, tag `imported`)
- `blackbox sync push|pull`:
  - `--dir` shared folder
  - `--remote http://host:7788` (talks to `blackbox serve` sync API)
  - `--s3 s3://bucket/prefix` (AWS env credentials)
- Serve endpoints: `/api/sync/manifest`, `/api/sync/runs/{id}`

### Packaging
- crates.io package name: **`blackbox-recorder`** (binary/lib still `blackbox`)
- Dual license files: `LICENSE-MIT`, `LICENSE-APACHE`
- Publish checklist: `docs/PUBLISH.md`
- Runtime artifacts (`.blackbox/`, `*.db*`) gitignored and excluded from the crate package

### Docs
- Release-oriented README (install-first, workflows, accurate 0.1.0 status)
- Contributor map in `AGENTS.md`; quality bar + next work in `docs/ROADMAP.md`
- Historical Phase 1–3 plan archived under `docs/history/`

### Quality
- Integration tests (fake Claude, secrets, export, tags, portable, sync)
- CI: `cargo test` + `clippy -D warnings`
- `cargo publish --dry-run` validates packaging
