# Repository Guidelines

## Project Overview

**blackbox** is a Rust flight recorder and debugger for AI-agent runs. It launches agent commands (Claude, Codex, or generic), captures terminal output and structured events via PTY supervision, stores traces in SQLite + content-addressed blobs, and provides CLI, TUI, and a local web dashboard for inspection.

**Quality bar:** secrets never at rest by default; monotonic event sequencing; payloads as blobs; project-local `.blackbox/` store; safe export/sync defaults. See `docs/ROADMAP.md` and `README.md`.

**Package naming:** crates.io package is `blackbox-recorder`; the binary and library crate path remain `blackbox`.

## Architecture & Data Flow

```
CLI (clap) → RunSupervisor → CaptureLayers (Git, FS, Process) + PTY I/O
                    │              │
                    │         mpsc merge → EventWriter (seq + persist)
                    │              │
              PTY path ──→ normalize → redact → blob → adapter parse
                    │                         → EventWriter
                    │
              TraceStore (SQLite + .blackbox/blobs/ + FTS5)
                    │
         ┌──────────┼──────────────┬────────────┐
    AnalysisPass  Export/Import  Serve/SSE   UI / CLI
                  Sync (dir/HTTP/S3)
```

**Core data model:**
- `TraceEvent` — universal trace substrate. Large payloads in `output_blob` keys; metadata holds previews only.
- `Run` — one recorded session (command redacted at rest, cwd, status, exit, parent fork, tags).
- `Checkpoint` — start/end snapshots (env blob, git commit/diff, harness session).
- `BlobReference` — SHA-256 content-addressed storage.

**Capture:** layers emit events; `EventWriter` is the single sequencer. Terminal I/O is handled in `RunSupervisor` (normalize → redact → blob → adapter parse). Native log pollers attach for Claude/Codex session files when present.

**Storage:** `SqliteStore` with on-disk blobs and FTS5. Opening the store recovers abandoned `Running` runs → `Failed`.

## Key Directories

| Path | Purpose |
|---|---|
| `src/core/` | TraceEvent, Run, Checkpoint, BlobReference |
| `src/config.rs` | Store path resolution + capture policy |
| `src/pipeline/` | EventWriter (monotonic sequence) |
| `src/capture/` | CaptureLayer trait + PTY/Git/FS/Process |
| `src/storage/` | TraceStore + SqliteStore (+ FTS) |
| `src/terminal/` | RawRecorder, AnsiNormalizer, coalescing |
| `src/analysis/` | ErrorDetector, SideEffectClassifier, EventCorrelator |
| `src/adapters/` | Claude, Codex, Generic; native log poller; parse |
| `src/replay/` | Fork, Sandbox, Mock, Timeline |
| `src/redaction/` | SecretScanner, EnvironmentRedactor, ExportRedactor |
| `src/export/` | JSONL, HTML, Portable (v1/v2) |
| `src/ui/` | ratatui TUI |
| `src/cli.rs` | Clap CLI (all subcommands) |
| `src/run.rs` | RunSupervisor |
| `src/serve.rs` | Local axum dashboard + SSE + sync API |
| `src/sync.rs` | Directory / HTTP / S3 push-pull |
| `src/search.rs` | FTS-backed search |
| `src/scrub.rs` | At-rest re-redaction + blob GC |
| `src/resume.rs` | Fork/resume helpers |
| `src/transcript.rs` | Transcript rebuild for CLI |
| `tests/` | Integration tests |
| `docs/` | ROADMAP, PUBLISH; `docs/history/` is archival only |

## Development Commands

```bash
cargo build
cargo build --release
cargo run -- <subcommand>
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
cargo check
cargo publish --dry-run   # packaging check; see docs/PUBLISH.md
```

No Makefile or justfile — use cargo directly. Stable Rust, edition 2021.

## Conventions

- **`anyhow::Result`** for fallible ops at the CLI/integration boundary
- **tokio** full features; manual Runtime in `main.rs` (not `#[tokio::main]`)
- **`#[async_trait]`** for trait objects (`CaptureLayer`, `TraceStore`, `AnalysisPass`, `ReplayEngine`, `HarnessAdapter`)
- **Redact-before-write** default; `--insecure-raw` / `--no-redact` are opt-in danger flags
- Export and sync **redact by default**; `--no-redact` to disable
- Prefer project-local `.blackbox/` over root `blackbox.db` (legacy only if the file already exists)

## Store paths

1. `--store` / `BLACKBOX_DB`
2. Legacy `./blackbox.db` if present
3. Default: `.blackbox/blackbox.db` + `.blackbox/blobs/`

Runtime artifacts (`.blackbox/`, `*.db`, `*.db-wal`, `*.db-shm`) are gitignored. Do not commit them.

## Testing

- Unit tests: `#[cfg(test)]` modules next to the code they cover
- Integration tests: `tests/integration_run.rs` (fake harness, secrets, export, tags, portable, sync)
- `cargo test` runs everything; CI also enforces clippy `-D warnings`

Prefer tests for redaction, store invariants, sequencing, adapters, export/import round-trips, and sync paths.

## Docs map

| File | Audience |
|---|---|
| `README.md` | Users — install, quick start, commands |
| `CHANGELOG.md` | Release notes |
| `AGENTS.md` | Contributors / coding agents (this file) |
| `docs/ROADMAP.md` | Quality bar + remaining work |
| `docs/PUBLISH.md` | crates.io publish checklist |
| `docs/history/*` | Archived plans — not current truth |

## Roadmap

P0–P3 product bar is largely met for a first release. Open work and non-goals live in `docs/ROADMAP.md`. Do not use `docs/history/` task lists as a backlog.
