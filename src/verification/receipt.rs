//! Immutable verification receipt schema.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Passed,
    Failed,
    PartiallyPassed,
    Unverified,
    Inconclusive,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerifierType {
    CommandExit,
    JunitXml,
    Tap,
    CargoLibtestJson,
    FileAssertion,
    GitState,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationConfidence {
    Confirmed,
    StronglyCorrelated,
    WeaklyCorrelated,
    Unknown,
}

/// Immutable verification receipt. Later verifications create new receipts
/// rather than rewriting prior evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReceipt {
    pub schema: String,
    pub id: String,
    pub run_id: String,
    pub created_at: DateTime<Utc>,
    pub verifier_type: VerifierType,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command_argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_fidelity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contained: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_blob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_blob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tests_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tests_passed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tests_failed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tests_skipped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    pub status: VerificationStatus,
    pub confidence: VerificationConfidence,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl VerificationReceipt {
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
