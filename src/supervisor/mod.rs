//! Run supervision stages (1.5 U1).
//!
//! `RunSupervisor` in [`crate::run`] remains the orchestrator. This module
//! holds explicit stage types so planning, rollup, and checkpoints are
//! testable without a full PTY session.
//!
//! ## Lifecycle
//!
//! ```text
//! planned → persisted → capture_starting → child_running
//!   → draining → rolling_up → checkpointing → completed|failed|cancelled
//! ```

pub mod checkpoint;
pub mod lifecycle;
pub mod rollup;

pub use checkpoint::{build_end_checkpoint, CheckpointInputs};
pub use lifecycle::{RunStage, ShutdownReason};
pub use rollup::{build_coverage_events, RollupInputs, RollupOutput};
