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

### Share / import
- Portable JSON export + `blackbox import` (new ids by default, tag `imported`)

### Quality
- Integration tests (fake Claude, secrets, export, tags, portable round-trip)
- CI: `cargo test` + `clippy -D warnings`
- `cargo publish --dry-run` packages cleanly (crate name may need rename for crates.io)
