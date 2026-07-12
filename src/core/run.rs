use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Lifecycle status of a recorded run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RunStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Unknown,
}

/// A recorded agent run.
///
/// Every `blackbox run -- <command>` creates one `Run`. It holds
/// the command-line invocation, temporal metadata, and final outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    /// Unique run identifier
    pub id: String,

    /// Human-readable label (optional)
    pub name: Option<String>,

    /// The command that was executed under observation
    pub command: Vec<String>,

    /// Working directory at launch time
    pub cwd: String,

    /// Project directory (may differ from cwd for --project)
    pub project_dir: String,

    /// Free-form tags for filtering and grouping
    pub tags: Vec<String>,

    /// User-provided notes
    pub notes: Option<String>,

    /// Run status
    pub status: RunStatus,

    /// When the run started
    pub started_at: DateTime<Utc>,

    /// When the run ended
    pub ended_at: Option<DateTime<Utc>>,

    /// Exit code of the supervised process
    pub exit_code: Option<i32>,

    /// Parent run ID, if this run was forked from another trace
    pub parent_run_id: Option<String>,

    /// Event sequence counter — incremented atomically per new event
    pub next_sequence: u64,
}

impl Run {
    /// Create a new run with auto-generated ID.
    pub fn new(command: Vec<String>, cwd: String) -> Self {
        let project_dir = cwd.clone();
        Self {
            id: Uuid::new_v4().to_string(),
            name: None,
            command,
            cwd,
            project_dir,
            tags: Vec::new(),
            notes: None,
            status: RunStatus::Pending,
            started_at: Utc::now(),
            ended_at: None,
            exit_code: None,
            parent_run_id: None,
            next_sequence: 0,
        }
    }

    /// Allocate the next sequence number for an event in this run.
    pub fn allocate_sequence(&mut self) -> u64 {
        let seq = self.next_sequence;
        self.next_sequence += 1;
        seq
    }

    /// Mark the run as finished.
    pub fn finish(&mut self, exit_code: i32) {
        self.ended_at = Some(Utc::now());
        self.exit_code = Some(exit_code);
        self.status = if exit_code == 0 {
            RunStatus::Succeeded
        } else {
            RunStatus::Failed
        };
    }
}

/// A handle to an active supervised run.
///
/// Returned by the run supervisor and used to interact with the
/// running child process (signal, inject input, poll, stop).
pub struct RunHandle {
    pub run_id: String,
    pub child_pid: u32,
}
