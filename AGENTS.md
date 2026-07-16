# Repository guidelines

This document is for contributors and coding agents who need to understand the blackbox codebase — architecture patterns, module responsibilities, coding conventions, and how to add new features.

---

## Project overview

**blackbox** is a Rust flight recorder, debugger, and project memory bus for AI-agent runs. It launches agent commands (Claude, Codex, or generic), captures terminal output and structured events via PTY supervision, stores traces in SQLite + content-addressed blobs, and provides CLI, TUI, and a local web dashboard for inspection.

**Package naming:** crates.io package is `blackbox-recorder`; the binary and library crate path remain `blackbox`.

---

## Architecture

```
CLI (clap) → RunSupervisor → CaptureLayers (PTY, Git, FS, Process) + mpsc merge
                    │
               EventWriter (sequence + persist + dedup)
                    │
          TraceStore (SQLite + .blackbox/blobs/ + FTS5)
                    │
     ┌──────────────┼────────────────┬──────────────┐
AnalysisPass   Export/Import    Serve/SSE      UI / CLI
                Sync (dir/HTTP/S3)
```

### Core data flow

1. **CLI** parses args with clap, resolves store path, dispatches to subcommand
2. **RunSupervisor** creates a `Run` record, starts capture layers (PTY, Git, FS, Process)
3. Each layer emits `TraceEvent` values into independent `mpsc` channels
4. `merge_layers()` combines channels into one merged stream
5. **EventWriter** owns the monotonic sequence counter, deduplicates tool events, persists to store
6. PTY output pipeline: RawRecorder → AnsiNormalizer → redaction → blob → adapter parse → EventWriter
7. On run end: stop layers, write checkpoint, `apply_run_outcome()` to sticky state, refresh memory files

---

## Module map

| Path | Purpose | Key types |
|---|---|---|
| `src/core/` | Data model | `TraceEvent`, `Run`, `Checkpoint`, `BlobReference` |
| `src/capture/` | CaptureLayer trait + impls | `CaptureLayer`, PTY/Git/FS/Process |
| `src/pipeline/` | Event sequencing + dedup | `EventWriter` |
| `src/storage/` | Storage abstraction + SQLite | `TraceStore` trait, `SqliteStore` |
| `src/terminal/` | PTY I/O handling | `RawRecorder`, `AnsiNormalizer`, coalescing |
| `src/redaction/` | Secret scanning + redaction | `SecretScanner`, `EnvironmentRedactor` |
| `src/adapters/` | Harness detection + parsing | `HarnessAdapter`, claude/codex/generic/aider/gemini/cursor/opencode/grok |
| `src/analysis/` | Event analysis passes | `ErrorDetector`, `SideEffectClassifier`, `EventCorrelator` |
| `src/replay/` | Replay engines | `Fork`, `Sandbox`, `Mock`, `Timeline` |
| `src/export/` | Export formats | JSONL, HTML, Portable (v1/v2) |
| `src/ui/` | TUI | ratatui event/run/timeline views |
| `src/run.rs` | PTY supervision orchestrator | `RunSupervisor` |
| `src/config.rs` | Store path + capture policy | `BlackboxPaths`, `BlackboxConfig`, `ContinuityMode` |
| `src/state.rs` | Sticky project state | `ProjectState`, `apply_run_outcome`, `AttentionLevel`, claims |
| `src/memory.rs` | Project memory pack | `ProjectMemoryPack`, `build_project_memory`, `shrink_pack` |
| `src/resume_inject.rs` | Continuity launch inject | `ResumeInjection`, `ContinuityPrepareOpts` |
| `src/mcp.rs` | MCP stdio server | JSON-RPC 2.0 tools |
| `src/cli.rs` | CLI definition | clap `Parser` + `Subcommand` |
| `src/status.rs` | Status/handoff builder | `build_status` |
| `src/serve.rs` | Web dashboard | Axum routes, SSE, JSON API |
| `src/sync.rs` | Dir/HTTP/S3 sync | Push/pull backends |
| `src/search.rs` | FTS search | Search runner |
| `src/scrub.rs` | Re-redaction + GC | Scrub + blob GC |
| `src/summary.rs` | Run summary builder | `build_summary` |
| `src/transcript.rs` | Transcript rebuild | Transcript from store |
| `src/views.rs` | JSON view types | All `*View` structs for `--json` |
| `src/output.rs` | Output formatting | JSON envelope, human formatting |
| `src/util.rs` | Shared helpers | `short_id`, `truncate` |
| `src/trajectory.rs` | Run comparison | LCP, divergence, diff |

## Key traits

```rust
#[async_trait]
pub trait CaptureLayer: Send + 'static {
    fn name(&self) -> &'static str;
    async fn start(&mut self, run: &Run) -> anyhow::Result<mpsc::Receiver<TraceEvent>>;
    async fn stop(&mut self) -> anyhow::Result<()>;
}

#[async_trait]
pub trait TraceStore: Send + Sync + 'static {
    // Runs: insert/update/get/list/delete
    // Events: insert/get/limited/get/update/count/batch
    // Checkpoints: insert/get
    // Blobs: store/load/move/all_keys/delete_keys
    // Search: fts_event_ids
}

#[async_trait]
pub trait AnalysisPass: Send + 'static {
    fn name(&self) -> &'static str;
    async fn analyze(&self, events: &[TraceEvent]) -> anyhow::Result<Vec<TraceEvent>>;
}

#[async_trait]
pub trait HarnessAdapter: Send + Sync + 'static {
    fn detect(&self, run: &Run, env: &HashMap<String, String>) -> bool;
    fn parse(&self, event: &mut TraceEvent);
    fn launch_command(&self, command: &[String]) -> Option<Vec<String>>;
}
```

## Conventions

- **`anyhow::Result`** for fallible ops at the CLI/integration boundary
- **tokio** full features; manual `Runtime` in `main.rs` (not `#[tokio::main]`)
- **`#[async_trait]`** for trait objects (`CaptureLayer`, `TraceStore`, `AnalysisPass`, `ReplayEngine`, `HarnessAdapter`)
- **Redact-before-write** default; `--insecure-raw`/`--no-redact` are opt-in danger flags
- Export and sync **redact by default**; `--no-redact` to disable
- Prefer project-local `.blackbox/` over root `blackbox.db` (legacy only if the file already exists)

## Store paths

1. `--store` / `BLACKBOX_DB`
2. Legacy `./blackbox.db` if present
3. Default: `.blackbox/blackbox.db` + `.blackbox/blobs/`

Runtime artifacts (`.blackbox/`, `*.db`, `*.db-wal`, `*.db-shm`) are gitignored. Do not commit them.

## Adding a new subcommand

1. Add variant to `Command` enum in `src/cli.rs` with clap args
2. Add handler method (or match arm in `execute()`) with the command logic
3. Return a view struct (for `--json`) or println output
4. Add view struct to `src/views.rs` if JSON output is needed
5. Add unit tests in the module's `#[cfg(test)]` section
6. Add integration test in `tests/` if it touches the store
7. Update the CLI reference in `docs/reference/cli.md`

## Adding a new harness adapter

Operator-facing notes for shipped harnesses: [docs/guide/adapters.md](docs/guide/adapters.md). Update that table + `tests/docs_first_run.rs` (`adapters_md_detection_table`) when detection basenames change.

1. Add detection logic in `src/adapters/detect.rs` (check argv, env, output patterns)
2. Create parser module in `src/adapters/` (e.g., `my_harness.rs`)
3. Add native log poller in `src/adapters/native_logs.rs` if applicable
4. Register in `src/adapters/mod.rs`
5. Add to the wrap list default in `src/config.rs`
6. Test with recorded sessions in `tests/`
7. Document in `docs/guide/adapters.md`

## Testing

| File | What it covers |
|---|---|
| `tests/integration_run.rs` | Full run lifecycle, fake harness, secrets, export, tags, portable, sync |
| `tests/ambient_contract.rs` | A1 gate: OFF/nest/wrap/enable/install-shell/disable |
| `tests/redaction_gate.rs` | A2 gate: structural IDs survive, secrets die |
| `tests/memory_pack_quality.rs` | M2a gate: budget, shrink order, failure fields, success-WIP, redaction |
| `tests/overhead_smoke.rs` | A6 gate: soft wall-time budget for supervising `true` |
| `tests/shell_soak.rs` | Real bash install -> ambient record -> BLACKBOX_OFF |
| `tests/ci_eval.rs` | `--ci` exit code propagation |
| `tests/docs_first_run.rs` | Getting-started happy path + short_id / artifact contract |
| `tests/security.rs` | Security invariants |
| `tests/test_critical.rs` | Critical path smoke tests |

## Docs map

**Writing standard:** [docs/WRITING.md](docs/WRITING.md) — competent technical audience, answer-first, no dumbing down. Prefer [docs/README.md](docs/README.md) as the index.

| File | Audience | Content |
|---|---|---|
| `README.md` | All | Landing: install, first commands, links by question |
| `docs/README.md` | All | Full docs index by track |
| `docs/WRITING.md` | Contributors | Doc style + glossary |
| `docs/guide/README.md` | Operators | Guide map |
| `docs/guide/what-is-blackbox.md` | Operators | Mental model + boundaries |
| `docs/guide/concepts.md` | Operators | Capture / inspect / continuity planes |
| `docs/guide/glossary.md` | Operators | Term definitions |
| `docs/guide/install.md` | Operators | Install + verify |
| `docs/guide/getting-started.md` | Operators | Enable → first run → inspect |
| `docs/guide/recipes.md` | Operators | Copy-paste workflows |
| `docs/guide/cheatsheet.md` | Operators | One-screen commands |
| `docs/guide/adapters.md` | Operators | Harness detection + native logs |
| `docs/guide/everyday-use.md` | Operators | List/show/TUI/serve/search |
| `docs/guide/debug-a-failure.md` | Operators | Postmortem, anomalies, handoff |
| `docs/guide/leave-it-on.md` | Operators | Ambient wrappers + opt-out |
| `docs/guide/configuration.md` | Operators | Flags, env, config.toml |
| `docs/guide/security.md` | Operators | Redaction + at-rest |
| `docs/guide/export-and-sync.md` | Operators | Export/sync/backup |
| `docs/guide/troubleshooting.md` | Operators | Diagnostics + recovery |
| `docs/guide/overhead.md` | Operators | Cost / soft budgets |
| `docs/skills/blackbox.md` | Agents | Session playbook |
| `docs/reference/*` | Automation | CLI, JSON, MCP, schemas |
| `docs/internals/*` | Contributors | Architecture truth |
| `docs/plan/*`, `docs/history/*` | Historical | Design archives — not how-to |
| `docs/ROADMAP.md` | All | Quality bar / version story |
| `CHANGELOG.md` | All | Release notes |
| `AGENTS.md` | Contributors | This file |
| `docs/PUBLISH.md` | Maintainers | crates.io checklist |

When editing operator guides, do not lead with design-doc IDs (A1/M2a). Put depth in reference/internals and link.

## Development commands

```bash
cargo build
cargo build --release
cargo run -- <subcommand>
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
cargo check
cargo publish --dry-run
```

No Makefile or justfile -- use cargo directly. Stable Rust, edition 2021.

## Roadmap

- **1.0** = capability daily-driver
- **1.1** = adoption proof (leave ambient on)
- **1.2** = Agent Memory Bus (project memory on launch)

See `docs/ROADMAP.md` for quality bar and remaining work.
