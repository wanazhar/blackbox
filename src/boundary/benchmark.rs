//! Frozen detector benchmark (1.8).
//!
//! Separate from the implementation-tuning corpus in [`super::corpus`]. Scenario
//! ids and expectations are versioned; thresholds may only change with an
//! explicit reviewed baseline update.

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use super::corpus::{
    detector_corpus, evaluate_detector_quality, CaseExpectation, CaseResult, CorpusCase,
    MAX_BENIGN_FALSE_POSITIVES, MIN_PRECISION, MIN_RECALL,
};
use super::detect::{detect_boundary_findings, DetectInputs};
use super::finding::{EvidenceIntegrityClass, FindingSeverity, ViolationState};
/// Frozen benchmark schema / version. Bump only with a reviewed baseline change.
pub const BENCHMARK_VERSION: &str = "blackbox.boundary.benchmark/v1";

/// Frozen scenario ids included in the release-qualification benchmark.
///
/// This list is intentionally explicit so silent corpus churn cannot expand
/// or shrink the scored set without a deliberate edit.
pub const FROZEN_SCENARIO_IDS: &[&str] = &[
    "tp-public-egress",
    "tp-boundary-probe",
    "tp-dns-probe",
    "tp-credential-path",
    "tp-credential-aws",
    "tp-credential-external",
    "tp-package-install",
    "tp-package-npm",
    "tp-package-apt",
    "tp-privilege-sudo",
    "tp-privilege-nsenter",
    "tp-tool-http-url",
    "tp-prohibited-token-dest",
    "tp-success-to-error",
    "tp-poisoned-input",
    "tp-supply-chain-tamper",
    "tp-persistence-after-exit",
    "tp-abnormal-swarm-fanout",
    "tp-invalid-telemetry-signature",
    "tp-conflicting-telemetry-identity",
    "fp-control-sshd",
    "fp-control-useradd",
    "fp-control-cargo-test",
    "fp-control-rustc",
    "fp-control-git-status",
    "tn-allowed-proxy",
    "tn-local-read",
    "fp-control-workspace-write",
    "tn-legitimate-dependency-use",
    "tn-legitimate-service-startup",
    "tn-legitimate-parallel-build",
    "tn-unsigned-telemetry",
];

/// Per-integrity-class performance slice.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntegrityClassStats {
    pub class: String,
    pub cases: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
}

/// Severity calibration row: expected vs observed for violation cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityCalibrationRow {
    pub scenario_id: String,
    pub detector: String,
    pub observed_severity: String,
    pub violation_state: String,
    pub evidence_integrity: String,
    /// True when severity is not inflated to critical under weak integrity.
    pub calibrated: bool,
}

/// Full frozen benchmark report.
#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkReport {
    pub schema: String,
    pub version: String,
    pub scenarios: usize,
    pub precision: f64,
    pub recall: f64,
    pub benign_false_positive_rate: f64,
    pub benign_false_positives: usize,
    pub benign_cases: usize,
    pub integrity_classes: Vec<IntegrityClassStats>,
    pub severity_calibration: Vec<SeverityCalibrationRow>,
    pub missing_sensor_handling: Vec<String>,
    pub passed: bool,
    pub failures: Vec<String>,
    pub case_results: Vec<CaseResult>,
    /// Layer label for API consumers (1.8 layered output contract).
    pub evidence_layer: String,
}

/// Run the frozen benchmark against current detectors.
pub fn evaluate_frozen_benchmark() -> BenchmarkReport {
    let all = detector_corpus();
    let mut selected: Vec<&CorpusCase> = Vec::new();
    let mut missing_ids = Vec::new();
    for id in FROZEN_SCENARIO_IDS {
        match all.iter().find(|c| c.id == *id) {
            Some(c) => selected.push(c),
            None => missing_ids.push((*id).to_string()),
        }
    }

    // Evaluate only the frozen subset by synthesizing a quality report manually.
    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut fn_ = 0usize;
    let mut tn = 0usize;
    let mut benign_fp = 0usize;
    let mut benign_cases = 0usize;
    let mut failures = missing_ids
        .iter()
        .map(|id| format!("frozen_scenario_missing_from_corpus:{id}"))
        .collect::<Vec<_>>();
    let mut case_results = Vec::new();
    let mut severity_calibration = Vec::new();
    let mut integrity_map: std::collections::BTreeMap<String, IntegrityClassStats> =
        std::collections::BTreeMap::new();
    let mut missing_sensor_handling = Vec::new();

    let selected_count = selected.len();
    for case in &selected {
        // Benign / control families used for false-positive rate.
        if case.family.starts_with("benign")
            || case.family == "control"
            || case.id.starts_with("fp-")
            || case.id.starts_with("tn-")
        {
            benign_cases += 1;
        }
        let findings = detect_boundary_findings(DetectInputs {
            run_id: case.id,
            contract: case.contract.as_ref(),
            events: &case.events,
            external: &case.external,
        });
        let detectors: Vec<String> = findings.iter().map(|f| f.detector.clone()).collect();
        let high_crit: Vec<_> = findings
            .iter()
            .filter(|f| {
                matches!(
                    f.severity,
                    FindingSeverity::High | FindingSeverity::Critical
                )
            })
            .collect();

        let integrity_class = strongest_case_integrity(case);
        let entry = integrity_map
            .entry(integrity_class.as_str().to_string())
            .or_insert_with(|| IntegrityClassStats {
                class: integrity_class.as_str().into(),
                ..Default::default()
            });
        entry.cases += 1;

        let (is_tp, is_fp, is_fn, is_tn, detail) = match case.expectation {
            CaseExpectation::ExpectViolation { detector }
            | CaseExpectation::ExpectTransition { detector } => {
                let hit = findings.iter().any(|f| f.detector == detector);
                if hit {
                    (true, false, false, false, format!("hit {detector}"))
                } else {
                    (
                        false,
                        false,
                        true,
                        false,
                        format!("missed {detector}; fired={detectors:?}"),
                    )
                }
            }
            CaseExpectation::ExpectClean => {
                if high_crit.is_empty() {
                    (false, false, false, true, "clean of high/critical".into())
                } else {
                    (
                        false,
                        true,
                        false,
                        false,
                        format!("unexpected high/crit: {detectors:?}"),
                    )
                }
            }
            CaseExpectation::ExpectStrictClean => {
                if findings.is_empty() {
                    (false, false, false, true, "strict clean".into())
                } else {
                    (
                        false,
                        true,
                        false,
                        false,
                        format!("unexpected findings: {detectors:?}"),
                    )
                }
            }
        };

        if is_tp {
            tp += 1;
            entry.true_positives += 1;
        }
        if is_fp {
            fp += 1;
            entry.false_positives += 1;
            if case.family.starts_with("benign")
                || case.family == "control"
                || case.id.starts_with("fp-")
                || case.id.starts_with("tn-")
            {
                benign_fp += 1;
            }
            failures.push(format!("{}: FP ({detail})", case.id));
        }
        if is_fn {
            fn_ += 1;
            entry.false_negatives += 1;
            failures.push(format!("{}: FN ({detail})", case.id));
        }
        if is_tn {
            tn += 1;
        }

        // Severity calibration for violation expectations.
        if let CaseExpectation::ExpectViolation { detector } = case.expectation {
            if let Some(f) = findings.iter().find(|f| f.detector == detector) {
                let integrity = f
                    .decision
                    .as_ref()
                    .map(|d| d.evidence_integrity)
                    .unwrap_or(integrity_class);
                let vstate = f
                    .decision
                    .as_ref()
                    .map(|d| d.violation_state)
                    .unwrap_or(ViolationState::Violation);
                let calibrated = !(matches!(f.severity, FindingSeverity::Critical)
                    && integrity.strength() < EvidenceIntegrityClass::HashVerified.strength());
                if !calibrated {
                    failures.push(format!(
                        "{}: severity_not_calibrated critical under {}",
                        case.id,
                        integrity.as_str()
                    ));
                }
                severity_calibration.push(SeverityCalibrationRow {
                    scenario_id: case.id.into(),
                    detector: detector.into(),
                    observed_severity: f.severity.as_str().into(),
                    violation_state: vstate.as_str().into(),
                    evidence_integrity: integrity.as_str().into(),
                    calibrated,
                });
            }
        }

        // Sensor-loss honesty: empty external + empty events with required contract.
        if case.external.is_empty() && case.events.is_empty() {
            missing_sensor_handling.push(format!("{}: empty_inputs", case.id));
        }

        case_results.push(CaseResult {
            id: case.id.into(),
            family: case.family.into(),
            tp: is_tp,
            fp: is_fp,
            fn_: is_fn,
            tn: is_tn,
            detectors_fired: detectors,
            detail,
        });
        let _ = tn; // counted for report completeness
    }

    let precision = if tp + fp == 0 {
        1.0
    } else {
        tp as f64 / (tp + fp) as f64
    };
    let recall = if tp + fn_ == 0 {
        1.0
    } else {
        tp as f64 / (tp + fn_) as f64
    };
    let benign_fp_rate = if benign_cases == 0 {
        0.0
    } else {
        benign_fp as f64 / benign_cases as f64
    };

    if precision < MIN_PRECISION {
        failures.push(format!(
            "precision {precision:.3} < min {MIN_PRECISION:.3}"
        ));
    }
    if recall < MIN_RECALL {
        failures.push(format!("recall {recall:.3} < min {MIN_RECALL:.3}"));
    }
    if benign_fp > MAX_BENIGN_FALSE_POSITIVES {
        failures.push(format!(
            "benign_fp {benign_fp} > max {MAX_BENIGN_FALSE_POSITIVES}"
        ));
    }
    if selected_count != FROZEN_SCENARIO_IDS.len() {
        failures.push(format!(
            "frozen_count_mismatch selected={} expected={}",
            selected_count,
            FROZEN_SCENARIO_IDS.len()
        ));
    }

    // Cross-check: tuning corpus gate should still pass (permanent 1.7).
    let tuning = evaluate_detector_quality();
    if !tuning.passed {
        failures.push("tuning_corpus_quality_gate_failed".into());
    }

    let passed = failures.is_empty();
    BenchmarkReport {
        schema: BENCHMARK_VERSION.into(),
        version: BENCHMARK_VERSION.into(),
        scenarios: selected_count,
        precision,
        recall,
        benign_false_positive_rate: benign_fp_rate,
        benign_false_positives: benign_fp,
        benign_cases,
        integrity_classes: integrity_map.into_values().collect(),
        severity_calibration,
        missing_sensor_handling,
        passed,
        failures,
        case_results,
        evidence_layer: EvidenceLayer::Findings.as_str().into(),
    }
}

fn strongest_case_integrity(case: &CorpusCase) -> EvidenceIntegrityClass {
    case.external
        .iter()
        .map(|e| EvidenceIntegrityClass::from_evidence(e.integrity))
        .max_by_key(|c| c.strength())
        .unwrap_or(EvidenceIntegrityClass::Unverified)
}

/// Evidence / interpretation layer labels for API and UI views (1.8 O1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLayer {
    /// Raw captured or imported observation.
    Observation,
    /// Canonicalized / normalized fact.
    NormalizedFact,
    /// Correlation edge / identity binding.
    Correlation,
    /// Deterministic detector finding.
    Findings,
    /// Incident graph interpretation.
    IncidentInterpretation,
    /// Model or human claim (must cite evidence).
    Claim,
}

impl EvidenceLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::NormalizedFact => "normalized_fact",
            Self::Correlation => "correlation",
            Self::Findings => "findings",
            Self::IncidentInterpretation => "incident_interpretation",
            Self::Claim => "claim",
        }
    }
}

/// Attach a layer label to a JSON view envelope.
pub fn label_layer(view: &mut serde_json::Value, layer: EvidenceLayer) {
    if let Some(obj) = view.as_object_mut() {
        obj.insert(
            "evidence_layer".into(),
            serde_json::Value::String(layer.as_str().into()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_benchmark_passes() {
        let report = evaluate_frozen_benchmark();
        assert!(
            report.passed,
            "frozen benchmark failed: {:?}",
            report.failures
        );
        assert_eq!(report.scenarios, FROZEN_SCENARIO_IDS.len());
        assert!(report.precision >= MIN_PRECISION);
        assert!(report.recall >= MIN_RECALL);
        assert_eq!(report.evidence_layer, "findings");
    }

    #[test]
    fn frozen_ids_are_stable_subset() {
        let corpus_ids: std::collections::HashSet<&str> =
            detector_corpus().iter().map(|c| c.id).collect();
        for id in FROZEN_SCENARIO_IDS {
            assert!(
                corpus_ids.contains(id),
                "frozen id {id} missing from tuning corpus — update both deliberately"
            );
        }
    }

    #[test]
    fn layer_label_injected() {
        let mut v = serde_json::json!({"kind": "x"});
        label_layer(&mut v, EvidenceLayer::Observation);
        assert_eq!(v["evidence_layer"], "observation");
    }

    #[test]
    fn severity_calibration_rows_present_for_violations() {
        let report = evaluate_frozen_benchmark();
        assert!(
            !report.severity_calibration.is_empty(),
            "expected calibration rows"
        );
        // Unverified integrity should not produce uncalibrated critical without flag.
        for row in &report.severity_calibration {
            if row.evidence_integrity == "unverified" && row.observed_severity == "critical" {
                assert!(
                    !row.calibrated,
                    "unverified critical must be marked uncalibrated"
                );
            }
        }
    }
}
