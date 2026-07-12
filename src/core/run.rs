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
        self.next_sequence = self.next_sequence.saturating_add(1);
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
#[allow(dead_code)]
pub struct RunHandle {
    pub run_id: String,
    pub child_pid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_defaults() {
        let r = Run::new(vec!["cargo".into(), "test".into()], "/tmp".into());
        assert_eq!(r.command, vec!["cargo", "test"]);
        assert_eq!(r.cwd, "/tmp");
        assert_eq!(r.project_dir, "/tmp");
        assert_eq!(r.status, RunStatus::Pending);
        assert!(r.ended_at.is_none());
        assert!(r.exit_code.is_none());
        assert!(r.parent_run_id.is_none());
        assert!(r.id.parse::<uuid::Uuid>().is_ok());
        assert_eq!(r.next_sequence, 0);
        assert!(r.name.is_none());
        assert!(r.notes.is_none());
        assert!(r.tags.is_empty());
    }

    #[test]
    fn allocate_sequence_increments() {
        let mut r = Run::new(vec!["echo".into()], "/tmp".into());
        assert_eq!(r.allocate_sequence(), 0);
        assert_eq!(r.allocate_sequence(), 1);
        assert_eq!(r.allocate_sequence(), 2);
        assert_eq!(r.next_sequence, 3);
    }

    #[test]
    fn finish_sets_succeeded_on_zero_exit() {
        let mut r = Run::new(vec!["true".into()], "/tmp".into());
        r.finish(0);
        assert_eq!(r.status, RunStatus::Succeeded);
        assert_eq!(r.exit_code, Some(0));
        assert!(r.ended_at.is_some());
    }

    #[test]
    fn finish_sets_failed_on_nonzero_exit() {
        let mut r = Run::new(vec!["false".into()], "/tmp".into());
        r.finish(1);
        assert_eq!(r.status, RunStatus::Failed);
        assert_eq!(r.exit_code, Some(1));
    }

    #[test]
    fn finish_is_idempotent() {
        let mut r = Run::new(vec!["test".into()], "/tmp".into());
        r.finish(0);
        assert_eq!(r.status, RunStatus::Succeeded);
        // Finish again — should not panic
        r.finish(1);
        assert_eq!(r.status, RunStatus::Failed);
        assert_eq!(r.exit_code, Some(1));
    }

    #[test]
    fn serde_round_trip() {
        let mut r = Run::new(vec!["bash".into(), "-c".into(), "ls".into()], "/home".into());
        r.status = RunStatus::Succeeded;
        r.exit_code = Some(0);
        r.tags = vec!["test".into(), "demo".into()];
        r.name = Some("demo-run".into());
        let json = serde_json::to_string(&r).unwrap();
        let de: Run = serde_json::from_str(&json).unwrap();
        assert_eq!(de.id, r.id);
        assert_eq!(de.command, r.command);
        assert_eq!(de.tags, r.tags);
        assert_eq!(de.name, r.name);
        assert_eq!(de.status, r.status);
    }

    #[test]
    fn status_serialization() {
        let cases = [
            (RunStatus::Pending, "\"Pending\""),
            (RunStatus::Running, "\"Running\""),
            (RunStatus::Succeeded, "\"Succeeded\""),
            (RunStatus::Failed, "\"Failed\""),
            (RunStatus::Cancelled, "\"Cancelled\""),
            (RunStatus::Unknown, "\"Unknown\""),
        ];
        for (variant, expected) in &cases {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(&json, expected, "mismatch for {variant:?}");
        }
    }
}
