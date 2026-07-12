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
