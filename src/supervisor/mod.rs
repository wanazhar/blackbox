//! Run supervision stages (1.5 U1).
//!
//! `RunSupervisor` in [`crate::run`] remains the orchestrator. This module
//! holds explicit stage types so planning, rollup, checkpoints, and child
//! shutdown are testable without a full PTY session. The PTY reader/adapter
//! pump still lives in `run.rs` (tight coupling to portable_pty handles).
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
pub mod shutdown;

pub use checkpoint::{build_end_checkpoint, CheckpointInputs};
pub use lifecycle::{RunStage, ShutdownReason};
pub use rollup::{build_coverage_events, RollupInputs, RollupOutput};
pub use shutdown::{
    escalate_sigkill, forward_sigint, timeout_kill_and_wait, DrainStep, SIGGRACE,
};
