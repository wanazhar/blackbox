# Repository Guidelines

## Project Overview

**blackbox** is a Rust flight recorder and debugger for AI-agent runs. It launches agent commands (Claude, Codex, or generic), captures terminal output and structured events via PTY supervision, stores traces in SQLite + content-addressed blobs, and provides CLI + TUI inspection.

**Quality bar:** secrets never at rest by default; monotonic event sequencing; payloads as blobs; project-local `.blackbox/` store. See `docs/ROADMAP.md` and `README.md`.

## Architecture & Data Flow

```
CLI (clap) → RunSupervisor → CaptureLayers (PTY lifecycle, Git, FS, Process)
                    │              │
                    │         mpsc merge → EventWriter (seq + persist)
                    │              │
              PTY I/O path ──→ redact → blob → EventWriter
                    │
              TraceStore (SQLite + .blackbox/blobs/)
                    │
         ┌──────────┼──────────┐
    AnalysisPass   Export    UI / CLI
```

**Core data model:**
- `TraceEvent` — universal trace substrate. Large payloads in `output_blob` keys; metadata holds previews only.
- `Run` — one recorded session (command redacted at rest, cwd, status, exit, parent fork).
- `Checkpoint` — start/end snapshots (env blob, git commit/diff, harness session).
- `BlobReference` — SHA-256 content-addressed storage.

**Capture:** layers emit events; `EventWriter` is the single sequencer. Terminal I/O is handled in `RunSupervisor` (normalize → redact → blob → adapter parse).

**Storage:** `SqliteStore` with on-disk blobs. Opening the store recovers abandoned `Running` runs → `Failed`.

## Key Directories

| Path | Purpose |
|---|---|
| `src/core/` | TraceEvent, Run, Checkpoint, BlobReference |
| `src/config.rs` | Store path resolution + capture policy |
| `src/pipeline/` | EventWriter (monotonic sequence) |
| `src/capture/` | CaptureLayer trait + PTY/Git/FS/Process |
| `src/storage/` | TraceStore + SqliteStore |
| `src/terminal/` | RawRecorder, AnsiNormalizer |
| `src/analysis/` | ErrorDetector, SideEffectClassifier, EventCorrelator |
| `src/adapters/` | Claude, Codex, Generic harness adapters |
| `src/replay/` | Fork, Sandbox, Mock, Timeline |
| `src/redaction/` | SecretScanner, EnvironmentRedactor, ExportRedactor |
| `src/export/` | JSONL, HTML, Portable |
| `src/ui/` | ratatui TUI |
| `src/cli.rs` | Clap CLI |
| `src/run.rs` | RunSupervisor |

## Development Commands

```bash
cargo build
cargo build --release
cargo run -- <subcommand>
cargo test
cargo clippy
cargo fmt
cargo check
```

## Conventions

- **`anyhow::Result`** for fallible ops
- **tokio** full features; manual Runtime in `main.rs`
- **`#[async_trait]`** for trait objects
- **Redact-before-write** default; `--insecure-raw` / `--no-redact` are opt-in danger flags
- Export **redacts by default**; `--no-redact` to disable

## Store paths

1. `--store` / `BLACKBOX_DB`
2. Legacy `./blackbox.db` if present
3. Default: `.blackbox/blackbox.db` + `.blackbox/blobs/`

## Testing

Unit tests live in `#[cfg(test)]` modules. `cargo test` runs them. Prefer tests for redaction, store, adapters, and sequencing invariants.

## Roadmap

See `docs/ROADMAP.md`. P0 trust work is the current focus; P1 usefulness and P2 harness fidelity follow.
