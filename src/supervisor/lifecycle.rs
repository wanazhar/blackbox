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
    /// `Completed` variant.
    Completed,
    /// `Failed` variant.
    Failed,
    /// `Cancelled` variant.
    Cancelled,
}

impl RunStage {
    /// View as str.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `as_str` — see module docs for full workflow.
    /// ```
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
    /// Supervised child process exited.
    ChildExit {
        /// Child exit code.
        code: u32,
    },
    /// Shutdown was requested by a signal.
    Signal,
    /// Wall-clock or budget timeout ended the run.
    Timeout,
    /// Event writer failed durably.
    WriterFailure {
        /// Failure message.
        message: String,
    },
    /// Capture collectors timed out during drain.
    CollectorTimeout,
    /// Unclassified shutdown error.
    Error {
        /// Error message.
        message: String,
    },
}

impl ShutdownReason {
    /// View as label.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `as_label` — see module docs for full workflow.
    /// ```
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
