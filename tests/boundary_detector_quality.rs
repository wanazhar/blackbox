//! Permanent 1.7 detector quality gate (FP/FN on committed corpus).

use blackbox::boundary::{
    detect_boundary_findings, evaluate_detector_quality, DetectInputs, MAX_BENIGN_FALSE_POSITIVES,
    MIN_PRECISION, MIN_RECALL,
};
use blackbox::evidence::{import_evidence_ndjson_str, ImportOptions, TELEMETRY_ANOMALY_ATTRIBUTE};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

const TELEMETRY: &str =
    include_str!("fixtures/boundary_1_7/adversarial/telemetry_deception.ndjson");
const PERSISTENCE: &str = include_str!("fixtures/boundary_1_7/adversarial/persistence.ndjson");
const ORDINARY_CHILD_EXIT: &str =
    include_str!("fixtures/boundary_1_7/adversarial/ordinary_child_exit.ndjson");
const FANOUT: &str = include_str!("fixtures/boundary_1_7/adversarial/fanout.ndjson");

#[test]
fn detector_quality_gate_min_recall_precision() {
    let report = evaluate_detector_quality();
    eprintln!(
        "quality: cases={} TP={} FP={} FN={} TN={} recall={:.3} precision={:.3} benign_fp={}",
        report.cases,
        report.true_positives,
        report.false_positives,
        report.false_negatives,
        report.true_negatives,
        report.recall,
        report.precision,
        report.benign_false_positives
    );
    for f in &report.failures {
        eprintln!("  fail: {f}");
    }
    assert!(
        report.passed,
        "detector quality gate failed: {:?}",
        report.failures
    );
    assert!(report.recall + f64::EPSILON >= MIN_RECALL);
    assert!(report.precision + f64::EPSILON >= MIN_PRECISION);
    assert_eq!(report.benign_false_positives, MAX_BENIGN_FALSE_POSITIVES);
    assert!(report.true_positives >= 10, "need labeled positives");
    assert!(report.cases >= 20, "expanded corpus expected");
    let benign_tn = report
        .case_results
        .iter()
        .filter(|c| c.family == "benign" && c.tn)
        .count();
    assert!(
        benign_tn >= 5,
        "need several benign true negatives, got {benign_tn}"
    );
    for family in [
        "escape",
        "probe",
        "credential",
        "package",
        "privilege",
        "poison",
        "persistence",
        "swarm",
        "telemetry_deception",
        "benign",
    ] {
        assert!(
            report.case_results.iter().any(|c| c.family == family),
            "missing family {family}"
        );
    }
}

#[tokio::test]
async fn telemetry_deception_survives_import_store_and_detect() {
    let opts = ImportOptions {
        default_run_id: Some("run-adversarial".into()),
        ..Default::default()
    };
    let (events, report) = import_evidence_ndjson_str(TELEMETRY, &opts).unwrap();
    assert_eq!(report.rejected, 1, "invalid signed input remains rejected");
    assert_eq!(report.duplicates, 1, "source identity collision recorded");
    assert_eq!(report.anomalies, 2);
    assert_eq!(events.len(), 3, "first record plus two anomaly records");
    assert_eq!(
        events
            .iter()
            .filter(|event| event.attributes.contains_key(TELEMETRY_ANOMALY_ATTRIBUTE))
            .count(),
        2
    );

    let store = SqliteStore::open_memory().unwrap();
    let (inserted, _) = store
        .insert_external_evidence_batch(&events, &[])
        .await
        .unwrap();
    assert_eq!(inserted, events.len());
    let persisted = store
        .list_external_evidence_for_run("run-adversarial")
        .await
        .unwrap();
    assert!(!persisted
        .iter()
        .any(|event| event.id == "evext-invalid-signature"));
    assert!(!persisted
        .iter()
        .any(|event| event.id == "evext-source-conflict"));
    let findings = detect_boundary_findings(DetectInputs {
        run_id: "run-adversarial",
        contract: None,
        events: &[],
        external: &persisted,
    });
    assert!(findings
        .iter()
        .any(|finding| finding.detector == "telemetry_integrity_invalid"));
    assert!(findings
        .iter()
        .any(|finding| finding.detector == "telemetry_identity_conflict"));
}

#[tokio::test]
async fn source_identity_conflict_across_imports_creates_persisted_marker() {
    let opts = ImportOptions {
        default_run_id: Some("run-adversarial".into()),
        ..Default::default()
    };
    let lines: Vec<_> = TELEMETRY.lines().collect();
    let (first, _) = import_evidence_ndjson_str(lines[1], &opts).unwrap();
    let (conflicting, _) = import_evidence_ndjson_str(lines[2], &opts).unwrap();
    let store = SqliteStore::open_memory().unwrap();
    assert_eq!(
        store
            .insert_external_evidence_batch(&first, &[])
            .await
            .unwrap()
            .0,
        1
    );
    assert_eq!(
        store
            .insert_external_evidence_batch(&conflicting, &[])
            .await
            .unwrap()
            .0,
        0,
        "conflicting source record is not admitted as ordinary evidence"
    );
    let persisted = store
        .list_external_evidence_for_run("run-adversarial")
        .await
        .unwrap();
    assert_eq!(persisted.len(), 2, "original plus sanitized anomaly");
    let findings = detect_boundary_findings(DetectInputs {
        run_id: "run-adversarial",
        contract: None,
        events: &[],
        external: &persisted,
    });
    assert!(findings
        .iter()
        .any(|finding| finding.detector == "telemetry_identity_conflict"));
}

#[test]
fn imported_persistence_requires_terminal_parent_and_keeps_proving_time() {
    let (persistence, report) =
        import_evidence_ndjson_str(PERSISTENCE, &ImportOptions::default()).unwrap();
    assert_eq!(report.accepted, 2);
    let findings = detect_boundary_findings(DetectInputs {
        run_id: "run-adversarial",
        contract: None,
        events: &[],
        external: &persistence,
    });
    let finding = findings
        .iter()
        .find(|finding| finding.detector == "persistence_after_exit")
        .expect("terminal parent plus causal descendant is persistence");
    assert_eq!(finding.created_at, persistence[1].occurred_at.unwrap());

    let (ordinary, report) =
        import_evidence_ndjson_str(ORDINARY_CHILD_EXIT, &ImportOptions::default()).unwrap();
    assert_eq!(report.accepted, 2);
    let findings = detect_boundary_findings(DetectInputs {
        run_id: "run-benign",
        contract: None,
        events: &[],
        external: &ordinary,
    });
    assert!(!findings
        .iter()
        .any(|finding| finding.detector == "persistence_after_exit"));
}

#[test]
fn imported_fanout_distinguishes_swarm_from_grouped_parallel_build() {
    let (events, report) = import_evidence_ndjson_str(FANOUT, &ImportOptions::default()).unwrap();
    assert_eq!(report.accepted, 16);
    let swarm: Vec<_> = events
        .iter()
        .filter(|event| event.identity.run_id.as_deref() == Some("run-swarm"))
        .cloned()
        .collect();
    let build: Vec<_> = events
        .iter()
        .filter(|event| event.identity.run_id.as_deref() == Some("run-build"))
        .cloned()
        .collect();
    assert_eq!(swarm.len(), 8);
    assert_eq!(build.len(), 8);

    let swarm_findings = detect_boundary_findings(DetectInputs {
        run_id: "run-swarm",
        contract: None,
        events: &[],
        external: &swarm,
    });
    let fanout = swarm_findings
        .iter()
        .find(|finding| finding.detector == "abnormal_fanout")
        .expect("swarm fanout finding");
    assert_eq!(fanout.created_at, swarm[7].occurred_at.unwrap());
    let build_findings = detect_boundary_findings(DetectInputs {
        run_id: "run-build",
        contract: None,
        events: &[],
        external: &build,
    });
    assert!(!build_findings
        .iter()
        .any(|finding| finding.detector == "abnormal_fanout"));
}
