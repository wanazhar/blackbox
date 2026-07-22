//! 1.6 D: experiment reports disclose sample size and insufficient evidence.

use blackbox::core::run::{Run, RunStatus};
use blackbox::experiment::model::{ExperimentRole, RunExperimentMeta};
use blackbox::experiment::report::{build_experiment_report, ReportVerdict, RunReportInput};
use blackbox::verification::receipt::{VerificationReceipt, VerificationStatus, VerifierType};

fn row(id: &str, variant: &str, status: RunStatus, verified: bool) -> RunReportInput {
    let mut run = Run::new(vec!["x".into()], "/tmp".into());
    run.id = id.into();
    run.status = status;
    run.duration_ms = Some(100);
    let mut receipts = Vec::new();
    if verified {
        let mut r = VerificationReceipt::new(id, VerifierType::CommandExit);
        r.status = VerificationStatus::Passed;
        receipts.push(r);
    }
    RunReportInput {
        run,
        meta: RunExperimentMeta {
            experiment_id: Some("exp1".into()),
            variant: Some(variant.into()),
            role: ExperimentRole::Unknown,
            ..Default::default()
        },
        receipts,
        capture_complete: true,
        duration_ms: Some(100),
        boundary_ok: None,
        provenance_ok: None,
        critical_findings: 0,
    }
}

#[test]
fn single_run_is_insufficient_evidence() {
    let rows = vec![row("r1", "a", RunStatus::Succeeded, true)];
    let report = build_experiment_report("exp1", "variant", &rows, 3);
    assert!(matches!(
        report.verdict,
        ReportVerdict::InsufficientEvidence
    ));
    assert!(!report.limitations.is_empty());
}

#[test]
fn unverified_success_not_counted_as_verified() {
    let mut rows = Vec::new();
    for i in 0..3 {
        rows.push(row(
            &format!("a{i}"),
            "baseline",
            RunStatus::Succeeded,
            true,
        ));
        rows.push(row(
            &format!("b{i}"),
            "candidate",
            RunStatus::Succeeded,
            false,
        ));
    }
    let report = build_experiment_report("exp1", "variant", &rows, 3);
    let cand = report
        .variants
        .iter()
        .find(|v| v.key == "candidate")
        .unwrap();
    assert_eq!(cand.execution_success, 3);
    assert_eq!(cand.verified_success, 0);
    assert_eq!(cand.unverified, 3);
}
