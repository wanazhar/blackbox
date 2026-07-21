//! Combined execution / verification / capture outcome view.

use serde::{Deserialize, Serialize};

use crate::core::run::{Run, RunStatus};
use crate::verification::receipt::{VerificationReceipt, VerificationStatus};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Succeeded,
    Failed,
    Cancelled,
    Running,
    Pending,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatus {
    Complete,
    Partial,
    Degraded,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunOutcomeView {
    pub schema: String,
    pub run_id: String,
    pub execution: ExecutionBlock,
    pub verification: VerificationBlock,
    pub capture: CaptureBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionBlock {
    pub status: ExecutionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub run_status: RunStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationBlock {
    pub status: VerificationStatus,
    #[serde(default)]
    pub receipt_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_receipt_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureBlock {
    pub status: CaptureStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality_score: Option<u32>,
}

/// Build outcome view without mutating `Run.status`.
pub fn build_outcome_view(
    run: &Run,
    receipts: &[VerificationReceipt],
    capture_quality: Option<u32>,
) -> RunOutcomeView {
    let execution_status = match run.status {
        RunStatus::Succeeded => ExecutionStatus::Succeeded,
        RunStatus::Failed => ExecutionStatus::Failed,
        RunStatus::Cancelled => ExecutionStatus::Cancelled,
        RunStatus::Running => ExecutionStatus::Running,
        RunStatus::Pending => ExecutionStatus::Pending,
        RunStatus::Unknown => ExecutionStatus::Unknown,
    };

    let verification_status = receipts
        .last()
        .map(|r| r.status.clone())
        .unwrap_or(VerificationStatus::Unverified);

    let capture_status = match capture_quality {
        Some(s) if s >= 90 => CaptureStatus::Complete,
        Some(s) if s >= 50 => CaptureStatus::Partial,
        Some(_) => CaptureStatus::Degraded,
        None => CaptureStatus::Unknown,
    };

    RunOutcomeView {
        schema: "blackbox.outcome/v1".into(),
        run_id: run.id.clone(),
        execution: ExecutionBlock {
            status: execution_status,
            exit_code: run.exit_code,
            run_status: run.status.clone(),
        },
        verification: VerificationBlock {
            status: verification_status,
            receipt_ids: receipts.iter().map(|r| r.id.clone()).collect(),
            latest_receipt_id: receipts.last().map(|r| r.id.clone()),
        },
        capture: CaptureBlock {
            status: capture_status,
            quality_score: capture_quality,
        },
    }
}
