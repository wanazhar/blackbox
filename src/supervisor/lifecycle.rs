//! Explicit run lifecycle stages and shutdown reasons (1.5 U1).

use serde::{Deserialize, Serialize};

/// Stages of a supervised run. The orchestrator advances through these
/// roughly in order; not every stage is a separate OS process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStage {
    /// Launch plan resolved (adapter, argv, cwd, continuity).
    Planned,
    /// Run row persisted to the store.
    Persisted,
    /// Capture layers starting.
    CaptureStarting,
    /// Child process running under PTY.
    ChildRunning,
    /// Child exited; draining layer/PTY queues.
    Draining,
    /// End-of-run coverage / usage rollup.
    RollingUp,
    /// End checkpoint + workspace manifest.
    Checkpointing,
    Completed,
    Failed,
    Cancelled,
}

impl RunStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Persisted => "persisted",
            Self::CaptureStarting => "capture_starting",
            Self::ChildRunning => "child_running",
            Self::Draining => "draining",
            Self::RollingUp => "rolling_up",
            Self::Checkpointing => "checkpointing",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Why capture shut down (distinct from run status).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownReason {
    ChildExit { code: u32 },
    Signal,
    Timeout,
    WriterFailure { message: String },
    CollectorTimeout,
    Error { message: String },
}

impl ShutdownReason {
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::ChildExit { .. } => "child_exit",
            Self::Signal => "signal",
            Self::Timeout => "timeout",
            Self::WriterFailure { .. } => "writer_failure",
            Self::CollectorTimeout => "collector_timeout",
            Self::Error { .. } => "error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_labels_are_stable() {
        assert_eq!(RunStage::RollingUp.as_str(), "rolling_up");
        assert_eq!(
            ShutdownReason::ChildExit { code: 0 }.as_label(),
            "child_exit"
        );
    }
}
