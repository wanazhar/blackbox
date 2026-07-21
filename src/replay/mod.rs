/// Fork module.
pub mod fork;
/// Mock module.
pub mod mock;
/// Sandbox module.
pub mod sandbox;
/// Timeline module.
pub mod timeline;

use crate::core::event::TraceEvent;
use crate::core::run::Run;

/// Outcome of a replay operation.
#[derive(Debug, Clone)]
pub enum ReplayOutcome {
    /// Timeline or generic successful completion.
    Completed {
        /// Human-readable completion summary.
        summary: String,
    },
    /// User cancelled mid-replay.
    Cancelled,
    /// Engine failed.
    Errored(String),
    /// Mock tool replay finished.
    Mocked {
        /// Number of tool calls mocked.
        tool_count: usize,
        /// Human-readable summary.
        summary: String,
    },
    /// Sandbox re-execution finished.
    Sandboxed {
        /// Commands executed in the sandbox.
        executed: usize,
        /// Commands skipped.
        skipped: usize,
        /// Workspace path used for the sandbox.
        workspace: String,
        /// Human-readable summary.
        summary: String,
    },
    /// A new forked run was created.
    Forked {
        /// Id of the newly forked run.
        new_run_id: String,
        /// Human-readable summary.
        summary: String,
    },
}

impl std::fmt::Display for ReplayOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplayOutcome::Completed { summary } => write!(f, "completed — {}", summary),
            ReplayOutcome::Cancelled => write!(f, "cancelled"),
            ReplayOutcome::Errored(e) => write!(f, "errored: {}", e),
            ReplayOutcome::Mocked {
                tool_count,
                summary,
            } => write!(f, "mocked {} tools — {}", tool_count, summary),
            ReplayOutcome::Sandboxed {
                executed,
                skipped,
                workspace,
                summary,
            } => write!(
                f,
                "workspace executed={} skipped={} dir={} — {}",
                executed, skipped, workspace, summary
            ),
            ReplayOutcome::Forked {
                new_run_id,
                summary,
            } => write!(
                f,
                "forked run {} — {}",
                &new_run_id[..8.min(new_run_id.len())],
                summary
            ),
        }
    }
}
impl ReplayOutcome {
    /// Returns `true` when the replay completed without error.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `success` — see module docs for full workflow.
    /// ```
    pub fn success(&self) -> bool {
        !matches!(self, ReplayOutcome::Errored(_))
    }
}

/// Replay policy for side effects during replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayPolicy {
    /// Allow read-only operations only
    ReadOnly,
    /// Allow local writes in a sandbox
    Sandbox,
    /// Allow all operations (dangerous)
    Live,
}

/// A replay engine processes recorded events to recreate or
/// simulate a previous run.
#[async_trait::async_trait]
pub trait ReplayEngine: Send + 'static {
    /// Return the name.
    fn name(&self) -> &'static str;

    /// Begin replaying a run from an optional starting event.
    async fn start(
        &mut self,
        run: &Run,
        events: &[TraceEvent],
        from_event_id: Option<&str>,
    ) -> anyhow::Result<ReplayOutcome>;
}

/// Slice events from an optional starting event id.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `events_from` — see module docs for full workflow.
/// ```
pub fn events_from<'a>(events: &'a [TraceEvent], from_event_id: Option<&str>) -> &'a [TraceEvent] {
    let start_idx = from_event_id
        .and_then(|id| {
            events
                .iter()
                .position(|e| e.id == id || e.id.starts_with(id))
        })
        .unwrap_or(0);
    &events[start_idx..]
}
