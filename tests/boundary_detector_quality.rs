//! Permanent 1.7 detector quality gate (FP/FN on committed corpus).

use blackbox::boundary::{
    evaluate_detector_quality, MAX_BENIGN_FALSE_POSITIVES, MIN_PRECISION, MIN_RECALL,
};

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
    assert!(report.true_positives >= 4, "need labeled positives");
    assert!(
        report.case_results.iter().any(|c| c.family == "benign" && c.tn),
        "benign control must be true negative"
    );
}
