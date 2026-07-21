//! Immutable verification receipt schema.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// `VerificationStatus` classification.
pub enum VerificationStatus {
    /// `Passed` variant.
    Passed,
    /// `Failed` variant.
    Failed,
    /// `PartiallyPassed` variant.
    PartiallyPassed,
    /// `Unverified` variant.
    Unverified,
    /// `Inconclusive` variant.
    Inconclusive,
    /// `NotApplicable` variant.
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// `VerifierType` classification.
pub enum VerifierType {
    /// `CommandExit` variant.
    CommandExit,
    /// `JunitXml` variant.
    JunitXml,
    /// `Tap` variant.
    Tap,
    /// `CargoLibtestJson` variant.
    CargoLibtestJson,
    /// `FileAssertion` variant.
    FileAssertion,
    /// `GitState` variant.
    GitState,
    /// `Custom` variant.
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// `VerificationConfidence` classification.
pub enum VerificationConfidence {
    /// `Confirmed` variant.
    Confirmed,
    /// `StronglyCorrelated` variant.
    StronglyCorrelated,
    /// `WeaklyCorrelated` variant.
    WeaklyCorrelated,
    /// `Unknown` variant.
    Unknown,
}

/// Immutable verification receipt. Later verifications create new receipts
/// rather than rewriting prior evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReceipt {
    /// Schema identifier string.
    pub schema: String,
    /// Unique identifier.
    pub id: String,
    /// Owning run id.
    pub run_id: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Verifier type.
    pub verifier_type: VerifierType,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// Command argv.
    pub command_argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Command fidelity.
    pub command_fidelity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Working directory.
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Contained.
    pub contained: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Start timestamp.
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// End timestamp, if finished.
    pub ended_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Duration in milliseconds.
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Process exit code, if known.
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Stdout blob.
    pub stdout_blob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Stderr blob.
    pub stderr_blob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Tests total.
    pub tests_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Tests passed.
    pub tests_passed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Tests failed.
    pub tests_failed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Tests skipped.
    pub tests_skipped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Verified scope.
    pub verified_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Failure fingerprint.
    pub failure_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Workspace hash.
    pub workspace_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Git commit.
    pub git_commit: Option<String>,
    /// Status value.
    pub status: VerificationStatus,
    /// Confidence.
    pub confidence: VerificationConfidence,
    #[serde(default)]
    /// Limitations.
    pub limitations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Parent receipt id.
    pub parent_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Summary.
    pub summary: Option<String>,
}

impl VerificationReceipt {
    /// Create a new instance.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `new` — see module docs for full workflow.
    /// ```
    pub fn new(run_id: impl Into<String>, verifier_type: VerifierType) -> Self {
        Self {
            schema: "blackbox.verification.receipt/v1".into(),
            id: format!("verify-{}", Uuid::new_v4()),
            run_id: run_id.into(),
            created_at: Utc::now(),
            verifier_type,
            command_argv: Vec::new(),
            command_fidelity: None,
            cwd: None,
            contained: Some(false),
            started_at: None,
            ended_at: None,
            duration_ms: None,
            exit_code: None,
            stdout_blob: None,
            stderr_blob: None,
            tests_total: None,
            tests_passed: None,
            tests_failed: None,
            tests_skipped: None,
            verified_scope: None,
            failure_fingerprint: None,
            workspace_hash: None,
            git_commit: None,
            status: VerificationStatus::Unverified,
            confidence: VerificationConfidence::Unknown,
            limitations: Vec::new(),
            parent_receipt_id: None,
            summary: None,
        }
    }
}
