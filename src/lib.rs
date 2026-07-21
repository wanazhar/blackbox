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

pub mod adapter_protocol;
pub mod adapters;
pub mod aggregates;
pub mod analysis;
pub mod backup;
pub mod budget;
pub mod capture;
pub mod capsule;
pub mod cassette;
pub mod cli;
pub mod cli_ext;
pub mod config;
pub mod context;
pub mod core;
pub mod crypto;
pub mod experiment;
pub mod export;
pub mod ingest;
pub mod integrity;
pub mod maybe_run;
pub mod mcp;
pub mod memory;
pub mod nest;
pub mod output;
pub mod pipeline;
pub mod pricing;
pub mod privacy;
pub mod projects;
pub mod redaction;
pub mod replay;
pub mod resume;
pub mod resume_inject;
pub mod retention;
pub mod run;
pub mod score;
pub mod scrub;
pub mod search;
pub mod serve;
pub mod shell_install;
pub mod state;
pub mod status;
pub mod storage;
pub mod summary;
pub mod supervisor;
pub mod sync;
pub mod terminal;
pub mod trajectory;
pub mod transcript;
pub mod ui;
pub mod util;
pub mod verification;
pub mod views;
pub mod workspace_manifest;
