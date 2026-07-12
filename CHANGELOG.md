# Changelog

All notable changes to **blackbox** are documented here.

## [Unreleased]

## [1.0.0] — 2026-07-12

First major release: leave-on daily driver for Linux/macOS agent workflows.

### Agent surface
- **MCP stdio server**: `blackbox mcp` — tools for status, handoff, postmortem, context, runs, search, doctor
- **Auto-resume** (default on): inject prior failure context into the next harness launch (`BLACKBOX_RESUME_*`, `.blackbox/RESUME.md`); `--no-auto-resume` / `BLACKBOX_AUTO_RESUME=0` to disable
- Expanded default wrap list: claude, codex, aider, cursor, cursor-agent, gemini, opencode, grok

### Dashboard
- `GET /status`, `/handoff` HTML pages
- `GET /api/status`, `/api/handoff` JSON (same Views as CLI)

### Install
- `install.sh` one-liner for GitHub Release binaries
- `.github/workflows/release.yml` multi-target builds (linux/mac, x86_64/aarch64)

### Docs
- 1.0 quickstart in README
- Agent skill snippet: `docs/skills/blackbox.md`

## [0.4.0] — 2026-07-12

Close the daily-driver loop: install once, fail once, next agent resumes without human paste.

### Agent handoff
- `blackbox status` / `blackbox handoff` with `--json` (attention + next commands)
- Sticky `.blackbox/state.json` after every run (last run / last failure / attention)
- Failed runs print a handoff hint; `handoff` embeds `context --for-resume` pack
- `.blackbox/AGENT.md` written on `enable` so coding agents know the contract

### Zero-friction ops
- Real `enable --install-shell` / `--uninstall-shell` (managed markers in bash/zsh rc or fish conf.d)
- Retention `auto_apply = true` by default; opportunistic GC after runs
- Shell integration status scans all shells (not just `$SHELL`)

## [0.3.0] — 2026-07-12

Single product release: daily-driver capture **and** agent feedback loop (one version, one story).

### Trust
- Fix export redaction destroying git SHAs and content-addressed blob keys
- Path-aware structural allowlist in `ExportRedactor`; secrets in free-form still redacted

### Zero-friction capture
- Ancestor-aware project/store discovery (monorepo subdirs share one store)
- `.blackbox/config.toml` (`enabled`, wrap list, retention)
- `blackbox enable` / `disable` + fish/bash shell wrapper snippets
- `blackbox maybe-run` with nest guard (`BLACKBOX_ACTIVE_RUN`) and `BLACKBOX_OFF`

### Agent-native inspect
- Global `--json` envelope (`blackbox.cli/v1`) for runs, show, timeline, inspect, analyze, search, stats, doctor, postmortem, enable/disable, gc, diff, context
- Shared view types in `src/views.rs`
- `blackbox postmortem` / `summary` with SQL-limited event scan
- `blackbox gc` retention dry-run/apply; `purge --policy-from-config`

### Agent feedback
- Schema v6 run metrics: `duration_ms`, `adapter`, `session_id`, token fields, `model`
- Parse `harness.usage` + blackbox stream protocol v1 (`tool_call`, `usage`, `session`, `message`)
- `blackbox diff --trajectory` / `--json` ordered alignment (greedy LCP)
- `blackbox context <run> --for-resume --json` bounded resume packs
- `docs/agent-api.md`

## [0.2.0] — 2026-07-12

Intermediate tag (daily-driver floor only). Prefer **0.3.0** for the full product surface.

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
