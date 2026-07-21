//! CI-friendly regression gates with fail-closed missing-data options.

use serde::{Deserialize, Serialize};

use crate::experiment::report::{ExperimentReport, ReportVerdict};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateConfig {
    pub schema: String,
    #[serde(default)]
    pub min_attempts: Option<usize>,
    #[serde(default)]
    pub min_verified_rate: Option<f64>,
    #[serde(default)]
    pub max_p95_duration_regression: Option<f64>, // fraction e.g. 0.20
    #[serde(default)]
    pub require_capture_complete: bool,
    #[serde(default)]
    pub fail_on_insufficient_evidence: bool,
    #[serde(default)]
    pub baseline_key: Option<String>,
    #[serde(default)]
    pub candidate_key: Option<String>,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            schema: "blackbox.gate/v1".into(),
            min_attempts: Some(3),
            min_verified_rate: None,
            max_p95_duration_regression: None,
            require_capture_complete: false,
            fail_on_insufficient_evidence: true,
            baseline_key: None,
            candidate_key: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateRuleFailure {
    pub rule: String,
    pub message: String,
    #[serde(default)]
    pub contributing_runs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResult {
    pub schema: String,
    pub passed: bool,
    pub exit_code: i32,
    pub failures: Vec<GateRuleFailure>,
    pub verdict: ReportVerdict,
}

pub fn evaluate_gate(report: &ExperimentReport, config: &GateConfig) -> GateResult {
    let mut failures = Vec::new();

    if matches!(
        report.verdict,
        ReportVerdict::InsufficientEvidence | ReportVerdict::InvalidExperiment
    ) && config.fail_on_insufficient_evidence
    {
        failures.push(GateRuleFailure {
            rule: "insufficient_evidence".into(),
            message: format!("report verdict={:?}", report.verdict),
            contributing_runs: vec![],
        });
    }

    if let Some(min) = config.min_attempts {
        for v in &report.variants {
            if v.run_count < min {
                failures.push(GateRuleFailure {
                    rule: "min_attempts".into(),
                    message: format!(
                        "variant {} has {} runs; need >= {min}",
                        v.key, v.run_count
                    ),
                    contributing_runs: vec![],
                });
            }
        }
    }

    if let Some(min_rate) = config.min_verified_rate {
        for v in &report.variants {
            let rate = v.verified_rate.unwrap_or(0.0);
            // Never treat unverified execution success as verified.
            if rate < min_rate {
                failures.push(GateRuleFailure {
                    rule: "min_verified_rate".into(),
                    message: format!(
                        "variant {} verified_rate={rate:.3} < {min_rate:.3} (execution success is not verification)",
                        v.key
                    ),
                    contributing_runs: vec![],
                });
            }
        }
    }

    if config.require_capture_complete {
        for v in &report.variants {
            if v.capture_complete < v.run_count {
                failures.push(GateRuleFailure {
                    rule: "require_capture_complete".into(),
                    message: format!(
                        "variant {} capture_complete={}/{}",
                        v.key, v.capture_complete, v.run_count
                    ),
                    contributing_runs: vec![],
                });
            }
        }
    }

    if let Some(max_reg) = config.max_p95_duration_regression {
        if let (Some(bk), Some(ck)) = (&config.baseline_key, &config.candidate_key) {
            let base = report.variants.iter().find(|v| &v.key == bk);
            let cand = report.variants.iter().find(|v| &v.key == ck);
            if let (Some(b), Some(c)) = (base, cand) {
                if let (Some(bp), Some(cp)) = (b.duration_p95_ms, c.duration_p95_ms) {
                    if bp > 0.0 {
                        let reg = (cp - bp) / bp;
                        if reg > max_reg {
                            failures.push(GateRuleFailure {
                                rule: "max_p95_duration_regression".into(),
                                message: format!(
                                    "p95 duration regression {reg_pct:.1} pct exceeds {max_pct:.1} pct (baseline={bp}, candidate={cp})",
                                    reg_pct = reg * 100.0,
                                    max_pct = max_reg * 100.0,
                                    bp = bp,
                                    cp = cp
                                ),
                                contributing_runs: vec![],
                            });
                        }
                    }
                } else {
                    failures.push(GateRuleFailure {
                        rule: "max_p95_duration_regression".into(),
                        message: "missing duration data for baseline/candidate".into(),
                        contributing_runs: vec![],
                    });
                }
            }
        }
    }

    if matches!(report.verdict, ReportVerdict::Regression) {
        failures.push(GateRuleFailure {
            rule: "verdict_regression".into(),
            message: "experiment report verdict is regression".into(),
            contributing_runs: vec![],
        });
    }

    let passed = failures.is_empty();
    GateResult {
        schema: "blackbox.gate.result/v1".into(),
        passed,
        exit_code: if passed { 0 } else { 1 },
        failures,
        verdict: report.verdict.clone(),
    }
}
