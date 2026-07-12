use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A checkpoint captures enough observable state to resume or fork work.
///
/// Checkpoints are created at meaningful boundaries:
/// - Before the harness starts
/// - Before an external side effect
/// - After file modification batches
/// - Before and after tests
/// - On user request
/// - At agent completion
/// - Before a fork
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Unique checkpoint identifier
    pub id: String,

    /// Run this checkpoint belongs to
    pub run_id: String,

    /// Event that triggered this checkpoint
    pub event_id: String,

    /// Git commit hash at checkpoint time, if in a repo
    pub git_commit: Option<String>,

    /// Reference to stored git diff blob (uncommitted changes)
    pub git_diff_blob: Option<String>,

    /// Reference to stored filesystem manifest blob
    pub filesystem_manifest_blob: Option<String>,

    /// Working directory at checkpoint time
    pub cwd: String,

    /// Reference to stored environment variable snapshot blob
    pub environment_blob: Option<String>,

    /// Reference to stored conversation/terminal transcript blob
    pub transcript_blob: Option<String>,

    /// Harness session ID, if the adapter provides one
    pub harness_session_id: Option<String>,

    /// When this checkpoint was created
    pub created_at: DateTime<Utc>,
}

impl Checkpoint {
    /// Create a new checkpoint.
    pub fn new(run_id: &str, event_id: &str, cwd: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            run_id: run_id.to_string(),
            event_id: event_id.to_string(),
            git_commit: None,
            git_diff_blob: None,
            filesystem_manifest_blob: None,
            cwd: cwd.to_string(),
            environment_blob: None,
            transcript_blob: None,
            harness_session_id: None,
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_correct_defaults() {
        let cp = Checkpoint::new("run-1", "evt-1", "/tmp");
        assert_eq!(cp.run_id, "run-1");
        assert_eq!(cp.event_id, "evt-1");
        assert_eq!(cp.cwd, "/tmp");
        assert!(cp.git_commit.is_none());
        assert!(cp.git_diff_blob.is_none());
        assert!(cp.filesystem_manifest_blob.is_none());
        assert!(cp.environment_blob.is_none());
        assert!(cp.transcript_blob.is_none());
        assert!(cp.harness_session_id.is_none());
        assert!(cp.id.parse::<uuid::Uuid>().is_ok());
    }

    #[test]
    fn new_generates_unique_ids() {
        let cp1 = Checkpoint::new("run-1", "evt-1", "/tmp");
        let cp2 = Checkpoint::new("run-1", "evt-1", "/tmp");
        assert_ne!(cp1.id, cp2.id);
    }

    #[test]
    fn serde_round_trip() {
        let cp = Checkpoint::new("run-1", "evt-1", "/home/user/project");
        let json = serde_json::to_string(&cp).unwrap();
        let de: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(de.id, cp.id);
        assert_eq!(de.run_id, cp.run_id);
        assert_eq!(de.event_id, cp.event_id);
        assert_eq!(de.cwd, cp.cwd);
    }
}
