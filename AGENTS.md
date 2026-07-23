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
| `src/analysis/` | Event analysis passes | `ErrorDetector`, causal fingerprints/edges, `FailureFixCorrelator`, anomalies |
| `src/replay/` | Replay engines | `Fork`, `Sandbox`, `Mock`, `Timeline` |
| `src/export/` | Export formats | JSONL, HTML, Portable (v1/v2) |
| `src/ui/` | TUI | ratatui event/run/timeline views |
| `src/run.rs` | PTY supervision orchestrator | `RunSupervisor` |
| `src/nest.rs` | Nest guard without child-visible env (1.4) | `ActiveSupervisorGuard`, `strip_blackbox_env` |
| `src/maybe_run.rs` | Ambient wrap decision table | `MaybeRunAction`, `decide` |
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
| `src/aggregates.rs` | Incremental run aggregates + analysis scope (1.5) | `RunAggregates`, `AnalysisScope` |
| `src/workspace_manifest.rs` | Workspace checkpoint manifests + restore (1.5) | `WorkspaceManifest`, `RestoreReport` |
| `src/pipeline/batch_ingest.rs` | Bounded batch SQLite writer (1.5) | `BatchIngestor` |
| `src/summary.rs` | Run summary builder | `build_summary` |
| `src/transcript.rs` | Transcript rebuild | Transcript from store |
| `src/boundary/` | Agent boundary contracts (1.7–1.8) | contracts, typed selectors, calibrated findings, containment, detect, provenance, correlate |
| `src/protocol/` | Evidence protocol (1.9) | canonical JSON, schema catalog, stability, validation |
| `src/native/` | Native ingest without PTY (1.9) | `NativeRecorder`, NDJSON, Unix socket |
| `src/security/` | Security decisions (1.9) | decision receipts, action fingerprints, reconciliation |
| `src/commitment/` | Run evidence commitments (1.9) | event hashes, chain, Ed25519 sign/verify |
| `src/otlp/` | OTLP interop (1.9) | export, import, loss ledger |
| `src/conformance/` | Conformance runner (1.9) | Core/Recorder/Boundary/Forensic profiles |
| `src/integrations/` | Native harness refs (1.9) | Claude Code hooks adapter |
| `spec/` | Published protocol schemas (1.9) | JSON Schema + canonical rules |
| `test-vectors/` | Protocol test vectors (1.9) | valid/invalid/canonical/tamper |
| `src/evidence/` | External evidence import (1.7) | `ExternalEvidenceEvent`, NDJSON importer |
| `src/incident/` | Multi-run incidents (1.7–1.8) | `Incident`, graph, typed continuation |
| `src/forensic/` | Forensic packs (1.7) | `ForensicPack` |
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
| `tests/neutrality_contract.rs` | 1.4 N1/N2: recorder neutrality + nest markers |
| `tests/pty_fidelity.rs` | 1.4 Phase D: PTY ANSI/unicode/stream/exit/TTY fixtures |
| `tests/process_spawn_storm.rs` | 1.4 Phase D: short-lived process loss measurement |
| `tests/fault_recovery.rs` | 1.4 Phase D: abandoned Running → Failed honesty |
| `tests/redaction_store_scan.rs` | 1.4 S1: holdback run leaves no secret in SQLite/blobs |
| `tests/redaction_gate.rs` | A2 gate: structural IDs survive, secrets die |
| `tests/redaction_adversarial.rs` | Adversarial corpus + exhaustive split positions |
| `tests/memory_pack_quality.rs` | M2a gate: budget, shrink order, failure fields, success-WIP, redaction |
| `tests/overhead_smoke.rs` | A6 gate: soft wall-time budget for supervising `true` |
| `tests/shell_soak.rs` | Real bash install -> ambient record -> BLACKBOX_OFF |
| `tests/ci_eval.rs` | `--ci` exit code propagation |
| `tests/docs_first_run.rs` | Getting-started happy path + short_id / artifact contract |
| `tests/docs_cli_envelope.rs` | CLI JSON envelope + postmortem text labels + examples.md jq paths |
| `tests/setup_fail.rs` | 1.3 Phase 1: `setup` + `fail` integration |
| `src/score.rs` + `tests/ci_eval.rs` | 1.3 Phase 3: `blackbox.score/v1` score.json |
| `src/boundary/` + `tests/boundary_contract.rs` | 1.7 boundary contracts, containment, detect, provenance |
| `src/evidence/` + `src/incident/` + `src/forensic/` | 1.7 external evidence, incidents, forensic packs |
| `tests/boundary_1_7_full.rs` | 1.7 end-to-end pipeline |
| `tests/boundary_trust_integration.rs` | score trust fail + portable 1.7 round-trip |
| `tests/boundary_detector_quality.rs` | 1.7 permanent FP/FN detector quality gate |
| `tests/incident_pagination.rs` | incident cursor pages + aggregates |
| `tests/auto_provenance.rs` | auto provenance from dataset_case |
| `tests/evidence_adversarial.rs` | 1.7 evidence path-attr rejection + canary honesty |
| `tests/fixtures/docs/` | Static golden samples for docs contracts |
| `.github/workflows/ci.yml` | test + clippy + doc link check (docs stay in-repo; no Pages) |
| `tests/security.rs` | Security invariants |
| `tests/test_critical.rs` | Critical path smoke tests |
| `tests/long_run_integrity.rs` | 1.5 L1/L2: aggregates + analysis_scope beyond load caps |
| `tests/tool_dedup.rs` | 1.5 D1: ID-less retries preserved; cross-source merge |
| `tests/portable_import_atomicity.rs` | 1.5 A1: hash validation, rollback, nested redaction |
| `tests/patch_path_safety.rs` | 1.5 R1: absolute/traversal patch rejection; honest capabilities |
| `tests/storage_batch_faults.rs` | 1.5 S1: batch barriers, flush/shutdown durability, backpressure |
| `tests/workspace_checkpoint.rs` | 1.5 W1: binary/untracked restore + completeness report |
| `tests/event_ordering.rs` | 1.5 O1: source sequences, occurrence vs storage order |
| `tests/filesystem_escape.rs` | 1.5 C1: symlink/out-of-root scope for FS capture |
| `tests/native_log_rotation.rs` | 1.5: native-log identity, rotation, backlog |
| `tests/dashboard_auth.rs` | 1.5 H1: session cookie contract |
| `tests/pagination_scale.rs` | 1.5 P1: cursor pages + blob compression |
| `tests/protocol_vectors.rs` | Published schemas + canonical/adversarial vectors (1.9) |
| `tests/protocol_properties.rs` | Parser, canonicalizer, normalizer, portable-import properties (1.9) |
| `tests/native_ingest.rs` | Restart-safe native ingest without PTY (1.9) |
| `tests/native_reference_qualification.rs` | Claude hooks overhead, loss, isolation, upgrade behavior (1.9) |
| `tests/protocol_architecture.rs` | Protocol dependency boundary + single publishable package (1.9) |

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
| `docs/guide/doctor-and-capture.md` | Operators | Doctor score + coverage quality |
| `docs/guide/examples.md` | Operators | Annotated status/handoff JSON |
| `docs/guide/everyday-use.md` | Operators | List/show/TUI/serve/search |
| `mkdocs.yml` | Maintainers | Optional Material docs site nav |
| `docs/guide/debug-a-failure.md` | Operators | Postmortem, anomalies, handoff |
| `docs/guide/leave-it-on.md` | Operators | Ambient wrappers + opt-out |
| `docs/guide/configuration.md` | Operators | Flags, env, config.toml |
| `docs/guide/security.md` | Operators | Redaction + at-rest |
| `docs/guide/export-and-sync.md` | Operators | Export/sync/backup |
| `docs/guide/fsck-and-integrity.md` | Operators | `fsck`, spool, repair |
| `docs/guide/verification.md` | Operators | Receipts vs execution |
| `docs/guide/experiments.md` | Operators | Experiments, report, gate |
| `docs/guide/capsules-and-cassettes.md` | Operators | Capsules; experimental MCP cassette |
| `docs/guide/budgets-and-adapters.md` | Operators | Budgets, adapter protocol, project index |
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
./scripts/release-qualify-unix.sh    # 1.4+ Unix release gate
```

No Makefile or justfile -- use cargo directly. Stable Rust, edition 2021.

## Roadmap

- **1.0** = capability daily-driver
- **1.1** = adoption proof (leave ambient on)
- **1.2** = Agent Memory Bus (project memory on launch)
- **1.3** = trust & explain (shipped)
- **1.4** = Trust Proof (Unix neutrality, causal proof, security) — **1.4.0**
- **1.5** = Trace integrity & scale — **1.5.0**
- **1.6** = Verified runs & reproducibility — **1.6.0**
- **1.7** = Agent boundary evidence & incident reconstruction — **1.7.0**
- **1.8** = Evidence semantics & forensic rigor — **1.8.0** ([issue #6](https://github.com/wanazhar/blackbox/issues/6))
- **1.9** = Evidence protocol, embeddability, native harness integration — **1.9.0 release candidate** ([issue #7](https://github.com/wanazhar/blackbox/issues/7))

Qualify before tag: `./scripts/release-qualify-unix.sh`. See `docs/ROADMAP.md`.
