# Repository Guidelines

## Project Overview

**blackbox** is a Rust flight recorder and debugger for AI-agent runs. It launches agent commands (Claude, Codex, or generic), captures terminal output and structured events via PTY supervision, stores traces in SQLite, and provides a TUI for inspection. The project is in **Phase 1 scaffold** — all types and traits are defined, but most implementations are stubs awaiting real wiring.

## Architecture & Data Flow

```
CLI (clap) → RunSupervisor → CaptureLayers (PTY, Git, FS, Process)
                                    │
                              mpsc::Receiver<TraceEvent>
                                    │
                              TraceStore (SQLite / InMemory)
                                    │
                         ┌──────────┴──────────┐
                    AnalysisPass           UI Panels
              (error detection,        (ratatui TUI)
               classification)
                         │
                    ExportRedactor → JSONL output
```

**Core data model:**
- `TraceEvent` — universal trace substrate (16 fields: source, status, side effects, confidence, timing). Every observable action becomes one.
- `Run` — one recorded session (command, cwd, status, exit code, parent fork, sequence counter).
- `Checkpoint` — observable state snapshot for resume/fork, references blobs by SHA-256 key.
- `BlobReference` — content-addressed storage key (SHA-256 hex digest), builder pattern.

**Capture pipeline:** Each `CaptureLayer` implementation spawns an async task that emits `TraceEvent` values on an `mpsc::channel`. Layers are independent and composable.

**Storage abstraction:** `TraceStore` async trait (11 methods) with `InMemoryStore` (Arc<RwLock<HashMap>>) as current implementation. SQLite backend planned but not built.

**Adapter pattern:** `HarnessAdapter` trait with implementations for Claude, Codex, and a Generic fallback. Each detects its harness and provides launch context.

**Replay engines:** `ReplayEngine` async trait with Fork, Sandbox, Mock, and Timeline implementations. Mock filters Tool events for testing.

## Key Directories

| Path | Purpose |
|---|---|
| `src/core/` | Pure data types — TraceEvent, Run, Checkpoint, BlobReference. Zero internal deps. |
| `src/capture/` | `CaptureLayer` trait + 4 implementations (PTY, Git, FS, Process). Emits events via mpsc. |
| `src/storage/` | `TraceStore` trait + InMemoryStore. SQLite backend TBD. |
| `src/terminal/` | TerminalRecorder trait, RawRecorder, AnsiNormalizer, TranscriptIndexer. Not wired to capture yet. |
| `src/analysis/` | AnalysisPass trait + ErrorDetector, SideEffectClassifier, EventCorrelator. |
| `src/adapters/` | HarnessAdapter trait + Claude, Codex, Generic adapters. LaunchContext/PreparedLaunch types. |
| `src/replay/` | ReplayEngine trait + Fork, Sandbox, Mock, Timeline implementations. |
| `src/redaction/` | SecretScanner (5 regex patterns), EnvironmentRedactor, ExportRedactor (recursive JSON). |
| `src/ui/` | Panel trait + ratatui views (Runs, Timeline, Event, Diff, ProcessTree). No TUI shell yet. |
| `src/cli.rs` | Clap v4 derive CLI, 9 subcommands. All currently `bail!("not yet implemented")`. |

## Development Commands

```bash
# Build (debug)
cargo build

# Build (release — aggressive: opt-level=3, LTO, codegen-units=1)
cargo build --release

# Run
cargo run -- <subcommand>

# Lint (no clippy.toml configured, use defaults)
cargo clippy -- -W clippy::all

# Format (no rustfmt.toml, use defaults)
cargo fmt

# Check (fast compilation check)
cargo check

# Test (no tests exist yet)
cargo test
```

**No CI/CD, no Makefile, no justfile.** All commands are direct cargo invocations.

**Runtime:** Stable Rust, edition 2021. No pinned toolchain file. No `.cargo/config.toml`.

## Code Conventions & Common Patterns

### Error Handling
- **`anyhow::Result`** for all fallible operations — CLI commands, storage, capture layers.
- `thiserror` is a dependency but unused in current code; reserved for future typed errors.
- Pattern: `bail!("not yet implemented")` in stubs.

### Async Patterns
- **tokio full features** — manual Runtime creation in `main.rs` (not `#[tokio::main]`).
- **`#[async_trait]`** for all trait objects (`CaptureLayer`, `TraceStore`, `AnalysisPass`, `ReplayEngine`, `HarnessAdapter`, `TerminalRecorder`).
- **`mpsc::channel`** for event streaming from capture layers to storage.
- **`Arc<RwLock<HashMap>>`** for shared state in InMemoryStore.

### Naming & Structure
- Module `mod.rs` files define traits and re-export submodules.
- Concrete implementations live in separate files named after the implementation (e.g., `pty.rs`, `sqlite.rs`).
- Structs use CamelCase, fields use snake_case. Enum variants use CamelCase.
- `pub mod` in `lib.rs` for all 9 top-level modules — flat public API.

### Builder Patterns
- `BlobReference` uses builder: `.compressed().with_content_type(...)`.

### Dependency Injection
- Constructor injection: views receive data at construction, no global state.
- Trait objects for polymorphism (not enums) in capture, storage, analysis, replay, adapters.

### Configuration
- No config files. All behavior controlled by CLI flags (clap).
- `tracing_subscriber` with `EnvFilter` for log levels via `RUST_LOG` env var.

## Important Files

| File | Role |
|---|---|
| `src/main.rs` | Entry point — manual tokio runtime, tracing init, Cli::parse() → execute() |
| `src/lib.rs` | Crate root — re-exports all 10 modules |
| `src/cli.rs` | CLI definition — 9 subcommands (Run, Runs, Show, Timeline, Inspect, Diff, Export, Replay, Fork) |
| `src/core/event.rs` | TraceEvent struct + EventSource/EventStatus/SideEffect/Confidence enums — the universal data model |
| `src/core/run.rs` | Run struct — session tracking with fork support |
| `src/core/blob.rs` | BlobReference — content-addressed storage with builder pattern |
| `src/storage/mod.rs` | TraceStore async trait — storage backend abstraction |
| `src/storage/store.rs` | InMemoryStore — current storage implementation |
| `src/capture/mod.rs` | CaptureLayer async trait — plugin interface for observation |
| `src/capture/pty.rs` | PtyCapture — PTY supervision (stub, portable-pty unused) |
| `src/adapters/harness.rs` | HarnessAdapter trait — agent integration interface |
| `src/redaction/scanner.rs` | SecretScanner — 5 regex patterns for secret detection |
| `Cargo.toml` | Dependencies, release profile (LTO, opt-level=3) |
| `plan.md` | Phase 1 roadmap — 7 tasks with dependency graph |

## Runtime & Tooling Preferences

- **Language:** Rust 2021 edition, stable toolchain (no pinned version)
- **Async runtime:** tokio (full features), manual creation (not `#[tokio::main]`)
- **CLI:** clap v4 with derive macros
- **TUI:** ratatui 0.28 + crossterm 0.28
- **Storage:** rusqlite 0.31 (bundled SQLite) — not yet wired
- **Compression:** zstd 0.13 (experimental feature)
- **Hashing:** sha2 0.10 + hex 0.4 for content-addressed blobs
- **No CI/CD, no linter config, no formatter config** — use cargo defaults

## Testing & QA

**Current state: Zero tests.** No `#[cfg(test)]` modules, no `tests/` directory, no `benches/`, no `examples/`, no dev-dependencies in Cargo.toml.

**Test approach (when tests are added):**
- Unit tests in `#[cfg(test)]` modules within source files
- Integration tests would go in `tests/` directory
- `cargo test` to run all
- `cargo clippy` for linting (no custom config)
- `cargo fmt --check` for format verification

**What to test (per plan.md):**
- Each task is a "single self-contained commit that leaves the project compiling and testable"
- Capture layers: event emission via mpsc channels
- Storage: CRUD operations, content-addressed blob dedup
- Redaction: pattern matching, recursive JSON scrubbing
- Adapters: harness detection, launch context preparation

## Phase 1 Roadmap

The project follows a 7-task phased implementation (`plan.md`):

```
Task 1 (RunSupervisor) → Task 2 (PTY recording)
                              ↓
                    Task 3 (SQLite store) ←→ Task 4 (Git diff)
                              ↓
                    Task 5 (TUI shell) ←──┘
                    Task 6 (JSONL export) ←──┘
                    Task 7 (Secret redaction) — additive
```

Tasks 3 and 4 are independent (parallelizable). Task 7 is additive and can be done last or interleaved.
