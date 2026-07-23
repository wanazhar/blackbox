//! # blackbox
//!
//! Local flight recorder and debugger for supervised processes — especially
//! AI coding agents. The **crates.io package** is [`blackbox-recorder`](https://crates.io/crates/blackbox-recorder);
//! the **library crate and CLI binary** are both named `blackbox`.
//!
//! ## What the library does
//!
//! 1. Supervise a child under a PTY (`run`)
//! 2. Merge capture layers (terminal, git, filesystem, process)
//! 3. Redact secrets before write (default)
//! 4. Persist ordered `TraceEvent`s in SQLite + content-addressed blobs
//! 5. Expose analysis, export, verification receipts, experiments, and MCP
//!
//! Most users run the **`blackbox` CLI**. This crate is the implementation
//! library for that binary and for embedding capture/store logic.
//!
//! ## Operator docs (CLI)
//!
//! Guides and reference live in the repository (not all pages are rendered as
//! rustdoc). Start here:
//!
//! - [README](https://github.com/wanazhar/blackbox/blob/master/README.md) — install and first commands
//! - [docs index](https://github.com/wanazhar/blackbox/blob/master/docs/README.md) — full map
//! - [CLI reference](https://github.com/wanazhar/blackbox/blob/master/docs/reference/cli.md)
//!
//! ## Library map
//!
//! | Module | Role |
//! |--------|------|
//! | [`run`] | PTY supervision (`RunSupervisor`) |
//! | [`storage`] | `TraceStore` + SQLite backend |
//! | [`core`] | `Run`, `TraceEvent`, checkpoints, blobs |
//! | [`capture`] | Capture layers and merge |
//! | [`pipeline`] | `EventWriter`, batch ingest |
//! | [`adapters`] | Harness detection and parse |
//! | [`redaction`] | Secret scanning before write |
//! | [`verification`] | Immutable receipts and outcomes |
//! | [`boundary`] | Boundary contracts, containment, detectors, provenance, trust (1.7) |
//! | [`evidence`] | External evidence NDJSON import + sensor adapters (1.7) |
//! | [`incident`] | Multi-run incident reconstruction + pagination (1.7) |
//! | [`forensic`] | Local forensic analysis packs (1.7) |
//! | [`protocol`] | Evidence protocol canonical form & schemas (1.9) |
//! | [`experiment`] | Experiments, reports, gates |
//! | [`export`] | Portable / JSONL / HTML |
//! | [`integrity`] | `fsck` and repair |
//! | [`budget`] | Wall/process/memory/tool budgets |
//! | [`mcp`] | MCP stdio server |
//! | [`cli`] | clap CLI definition |
//!
//! ## Quick embed sketch
//!
//! ```no_run
//! use std::sync::Arc;
//! use blackbox::cli::RunArgs;
//! use blackbox::run::RunSupervisor;
//! use blackbox::storage::sqlite::SqliteStore;
//! use blackbox::storage::TraceStore;
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let store = Arc::new(SqliteStore::open_memory()?) as Arc<dyn TraceStore>;
//! let run = RunSupervisor::new(store)
//!     .execute(&RunArgs {
//!         command: vec!["echo".into(), "hi".into()],
//!         ..Default::default()
//!     })
//!     .await?;
//! println!("run id {}", run.id);
//! # Ok(())
//! # }
//! ```
//!
//! ## License
//!
//! MIT OR Apache-2.0.

#![warn(missing_docs)]

/// External process adapter protocol (`blackbox.adapter/v1`).
pub mod adapter_protocol;
/// Built-in harness adapters (Claude, Codex, generic, …).
pub mod adapters;
/// Incremental per-run aggregate counters.
pub mod aggregates;
/// Post-hoc analysis passes (errors, anomalies, causal links).
pub mod analysis;
/// Sealed offline store backup / restore.
pub mod backup;
/// Agent boundary contracts, containment receipts, evidence gates (1.7).
pub mod boundary;
/// Execution budget policy and Linux enforcement.
pub mod budget;
/// Reproducibility capsules.
pub mod capsule;
/// Capture layers: PTY, git, filesystem, process.
pub mod capture;
/// Experimental MCP cassette record / replay.
pub mod cassette;
/// Clap CLI definition and command dispatch.
pub mod cli;
/// 1.6 CLI handlers (fsck, verify, experiment, …).
pub mod cli_ext;
/// Store paths, capture policy, continuity mode.
pub mod config;
/// Resume / context packing helpers.
pub mod context;
/// Core data model: runs, events, blobs, checkpoints.
pub mod core;
/// Content hashing and sealed-export crypto.
pub mod crypto;
/// External evidence ingestion (1.7).
pub mod evidence;
/// Experiments, multi-run reports, and CI gates.
pub mod experiment;
/// Export formats: portable JSON, JSONL, HTML.
pub mod export;
/// Local forensic analysis packs (1.7).
pub mod forensic;
/// Multi-run incident reconstruction (1.7).
pub mod incident;
/// Durable ingest spool and crash recovery.
pub mod ingest;
/// Store integrity checks (`fsck`) and repair.
pub mod integrity;
/// Ambient wrap decision table (`maybe-run`).
pub mod maybe_run;
/// MCP stdio server.
pub mod mcp;
/// Project memory pack build and shrink.
pub mod memory;
/// Nest guard without child-visible control env.
pub mod nest;
/// Human and JSON CLI output helpers.
pub mod output;
/// Event writer and batch ingest pipeline.
pub mod pipeline;
/// Token / cost estimation helpers.
pub mod pricing;
/// File permission hardening helpers.
pub mod privacy;
/// Evidence protocol: canonical form, schemas, stability (1.9).
pub mod protocol;
/// Multi-project metadata index.
pub mod projects;
/// Secret scanning and redaction.
pub mod redaction;
/// Replay engines: timeline, mock, sandbox, fork.
pub mod replay;
/// Resume pack construction.
pub mod resume;
/// Continuity launch injection.
pub mod resume_inject;
/// Retention policies.
pub mod retention;
/// PTY supervision orchestrator ([`run::RunSupervisor`]).
pub mod run;
/// Eval score.json builder.
pub mod score;
/// Historical re-redaction and blob GC.
pub mod scrub;
/// FTS search runner.
pub mod search;
/// Local web dashboard (Axum).
pub mod serve;
/// Shell ambient-wrapper install.
pub mod shell_install;
/// Sticky project state.
pub mod state;
/// Status and handoff builders.
pub mod status;
/// Trace store trait and SQLite backend.
pub mod storage;
/// Run summary / postmortem text and JSON.
pub mod summary;
/// Supervisor lifecycle, rollup, shutdown.
pub mod supervisor;
/// Dir / HTTP / S3 sync.
pub mod sync;
/// PTY terminal recording, ANSI, coalescing.
pub mod terminal;
/// Run trajectory comparison (LCP / divergence).
pub mod trajectory;
/// Transcript rebuild from store blobs.
pub mod transcript;
/// Ratatui TUI views.
pub mod ui;
/// Shared string / path helpers.
pub mod util;
/// Verification receipts and outcomes.
pub mod verification;
/// JSON view types for `--json` envelopes.
pub mod views;
/// Workspace checkpoint manifests and restore.
pub mod workspace_manifest;
