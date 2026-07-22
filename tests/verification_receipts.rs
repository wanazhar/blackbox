//! 1.6 C: execution success distinct from verification; receipts immutable.

use std::sync::Arc;

use blackbox::core::run::{Run, RunStatus};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::verification::outcome::build_outcome_view;
use blackbox::verification::receipt::{
    VerificationConfidence, VerificationReceipt, VerificationStatus, VerifierType,
};

#[tokio::test]
async fn run_succeeds_while_verification_fails() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let mut run = Run::new(vec!["true".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    run.exit_code = Some(0);
    store.insert_run(&run).await.unwrap();

    let mut r = VerificationReceipt::new(&run.id, VerifierType::CommandExit);
    r.status = VerificationStatus::Failed;
    r.exit_code = Some(1);
    r.confidence = VerificationConfidence::Confirmed;
    r.summary = Some("tests failed".into());
    store.insert_verification_receipt(&r).await.unwrap();

    let receipts = store.list_verification_receipts(&run.id).await.unwrap();
    assert_eq!(receipts.len(), 1);
    let outcome = build_outcome_view(&run, &receipts, Some(95));
    assert!(matches!(
        outcome.execution.status,
        blackbox::verification::outcome::ExecutionStatus::Succeeded
    ));
    assert!(matches!(
        outcome.verification.status,
        VerificationStatus::Failed
    ));
    assert!(matches!(
        outcome.capture.status,
        blackbox::verification::outcome::CaptureStatus::Complete
    ));
}

#[tokio::test]
async fn reverify_creates_new_receipt_with_lineage() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let mut run = Run::new(vec!["true".into()], "/tmp".into());
    run.status = RunStatus::Failed;
    store.insert_run(&run).await.unwrap();

    let mut first = VerificationReceipt::new(&run.id, VerifierType::CommandExit);
    first.status = VerificationStatus::Failed;
    store.insert_verification_receipt(&first).await.unwrap();

    let mut second = VerificationReceipt::new(&run.id, VerifierType::CommandExit);
    second.status = VerificationStatus::Passed;
    second.parent_receipt_id = Some(first.id.clone());
    store.insert_verification_receipt(&second).await.unwrap();

    let receipts = store.list_verification_receipts(&run.id).await.unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(
        receipts[1].parent_receipt_id.as_deref(),
        Some(first.id.as_str())
    );
    // Original run status unchanged.
    let loaded = store.get_run(&run.id).await.unwrap().unwrap();
    assert!(matches!(loaded.status, RunStatus::Failed));
    // Newest receipt is passed.
    assert!(matches!(
        receipts.last().unwrap().status,
        VerificationStatus::Passed
    ));
}
