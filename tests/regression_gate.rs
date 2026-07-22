//! 1.6 D: gates fail closed on insufficient evidence / unverified success.

use blackbox::core::run::{Run, RunStatus};
use blackbox::experiment::gate::{evaluate_gate, GateConfig};
use blackbox::experiment::model::RunExperimentMeta;
use blackbox::experiment::report::{build_experiment_report, RunReportInput};
use blackbox::verification::receipt::{VerificationReceipt, VerificationStatus, VerifierType};

#[test]
fn gate_fails_insufficient_evidence() {
    let mut run = Run::new(vec!["x".into()], "/tmp".into());
    run.id = "r1".into();
    run.status = RunStatus::Succeeded;
    let rows = vec![RunReportInput {
        run,
        meta: RunExperimentMeta {
            experiment_id: Some("e".into()),
            variant: Some("v".into()),
            ..Default::default()
        },
        receipts: vec![],
        capture_complete: true,
        duration_ms: Some(10),
        boundary_ok: None,
        provenance_ok: None,
        critical_findings: 0,
    }];
    let report = build_experiment_report("e", "variant", &rows, 3);
    let result = evaluate_gate(
        &report,
        &GateConfig {
            min_attempts: Some(3),
            fail_on_insufficient_evidence: true,
            ..Default::default()
        },
    );
    assert!(!result.passed);
    assert_eq!(result.exit_code, 1);
    assert!(result.failures.iter().any(|f| f.rule.contains("insufficient")
        || f.rule == "min_attempts"
        || f.rule == "insufficient_evidence"));
}

#[test]
fn gate_min_verified_rate_ignores_execution_only() {
    let mut rows = Vec::new();
    for i in 0..3 {
        let mut run = Run::new(vec!["x".into()], "/tmp".into());
        run.id = format!("r{i}");
        run.status = RunStatus::Succeeded;
        rows.push(RunReportInput {
            run,
            meta: RunExperimentMeta {
                experiment_id: Some("e".into()),
                variant: Some("v".into()),
                ..Default::default()
            },
            receipts: vec![], // unverified
            capture_complete: true,
            duration_ms: Some(10),
            boundary_ok: None,
            provenance_ok: None,
            critical_findings: 0,
        });
    }
    // Add a second variant with verified passes so we leave insufficient_evidence.
    for i in 0..3 {
        let mut run = Run::new(vec!["x".into()], "/tmp".into());
        run.id = format!("b{i}");
        run.status = RunStatus::Succeeded;
        let mut r = VerificationReceipt::new(&run.id, VerifierType::CommandExit);
        r.status = VerificationStatus::Passed;
        rows.push(RunReportInput {
            run,
            meta: RunExperimentMeta {
                experiment_id: Some("e".into()),
                variant: Some("good".into()),
                ..Default::default()
            },
            receipts: vec![r],
            capture_complete: true,
            duration_ms: Some(10),
            boundary_ok: None,
            provenance_ok: None,
            critical_findings: 0,
        });
    }
    let report = build_experiment_report("e", "variant", &rows, 3);
    let result = evaluate_gate(
        &report,
        &GateConfig {
            min_attempts: Some(3),
            min_verified_rate: Some(0.8),
            fail_on_insufficient_evidence: false,
            ..Default::default()
        },
    );
    assert!(!result.passed);
    assert!(result.failures.iter().any(|f| {
        f.rule == "min_verified_rate" || f.rule == "min_domain_confirmed_rate"
    }));
}
