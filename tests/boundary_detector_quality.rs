//! Permanent 1.7 detector quality gate (FP/FN on committed corpus).

use blackbox::boundary::{
    detector_corpus, evaluate_detector_quality, CaseExpectation, MAX_BENIGN_FALSE_POSITIVES,
    MIN_PRECISION, MIN_RECALL,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct AdversarialFixture {
    id: String,
    family: String,
    detector: Option<String>,
    benign: bool,
}

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

#[test]
fn issue_required_adversarial_fixture_is_permanent_and_passing() {
    let fixtures: Vec<AdversarialFixture> = serde_json::from_str(include_str!(
        "fixtures/boundary_1_7/adversarial/corpus.json"
    ))
    .expect("adversarial fixture is valid JSON");
    let corpus = detector_corpus();
    let report = evaluate_detector_quality();

    assert_eq!(fixtures.len(), 10, "fixture must retain all paired cases");
    for fixture in fixtures {
        let case = corpus
            .iter()
            .find(|case| case.id == fixture.id)
            .unwrap_or_else(|| panic!("fixture case {} missing from corpus", fixture.id));
        assert_eq!(case.family, fixture.family);
        let result = report
            .case_results
            .iter()
            .find(|result| result.id == fixture.id)
            .expect("fixture case has a quality result");
        if fixture.benign {
            assert!(
                matches!(
                    case.expectation,
                    CaseExpectation::ExpectClean | CaseExpectation::ExpectStrictClean
                ),
                "{} must remain a benign expectation",
                fixture.id
            );
            assert!(result.tn, "{} must remain a true negative", fixture.id);
        } else {
            let detector = fixture.detector.expect("adversarial detector named");
            assert!(result.tp, "{} must remain a true positive", fixture.id);
            assert!(
                result.detectors_fired.contains(&detector),
                "{} did not fire {}: {:?}",
                fixture.id,
                detector,
                result.detectors_fired
            );
        }
    }
}
