//! CI-friendly regression gates with fail-closed missing-data options.

use serde::{Deserialize, Serialize};

use crate::experiment::report::{ExperimentReport, ReportVerdict};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `GateConfig` value.
pub struct GateConfig {
    /// Schema identifier string.
    pub schema: String,
    #[serde(default)]
    /// Min attempts.
    pub min_attempts: Option<usize>,
    #[serde(default)]
    /// Min verified rate.
    pub min_verified_rate: Option<f64>,
    #[serde(default)]
    /// Max p95 duration regression.
    pub max_p95_duration_regression: Option<f64>, // fraction e.g. 0.20
    #[serde(default)]
    /// Require capture complete.
    pub require_capture_complete: bool,
    #[serde(default)]
    /// Fail on insufficient evidence.
    pub fail_on_insufficient_evidence: bool,
    #[serde(default)]
    /// Baseline key.
    pub baseline_key: Option<String>,
    #[serde(default)]
    /// Candidate key.
    pub candidate_key: Option<String>,
    /// When true, only domain-Confirmed verified successes count toward
    /// `min_verified_rate` (weakly correlated passes do not satisfy the gate).
    #[serde(default = "default_true")]
    pub require_domain_confirmed: bool,
    /// Fail when any run has fail-closed boundary evidence gate failure (1.7).
    #[serde(default)]
    pub require_boundary_ok: bool,
    /// Fail when any run has provenance gate failure (1.7).
    #[serde(default)]
    pub require_provenance_ok: bool,
    /// Fail when any run has critical boundary findings (1.7).
    #[serde(default)]
    pub fail_on_critical_findings: bool,
}

fn default_true() -> bool {
    true
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
            require_domain_confirmed: true,
            require_boundary_ok: false,
            require_provenance_ok: false,
            fail_on_critical_findings: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `GateRuleFailure` value.
pub struct GateRuleFailure {
    /// Rule.
    pub rule: String,
    /// Message.
    pub message: String,
    #[serde(default)]
    /// Contributing runs.
    pub contributing_runs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `GateResult` value.
pub struct GateResult {
    /// Schema identifier string.
    pub schema: String,
    /// Passed.
    pub passed: bool,
    /// Process exit code, if known.
    pub exit_code: i32,
    /// Failures.
    pub failures: Vec<GateRuleFailure>,
    /// Verdict.
    pub verdict: ReportVerdict,
}

/// Evaluate gate.
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `evaluate_gate` — see module docs for full workflow.
/// ```
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

    if config.require_boundary_ok {
        for v in &report.variants {
            if let Some(rate) = v.boundary_ok_rate {
                if rate < 1.0 {
                    failures.push(GateRuleFailure {
                        rule: "require_boundary_ok".into(),
                        message: format!(
                            "variant {} boundary_ok_rate={rate:.3} < 1.0 (containment/evidence gate)",
                            v.key
                        ),
                        contributing_runs: v.boundary_failed_runs.clone(),
                    });
                }
            } else if config.fail_on_insufficient_evidence {
                failures.push(GateRuleFailure {
                    rule: "require_boundary_ok".into(),
                    message: format!(
                        "variant {} missing boundary trust data (insufficient evidence)",
                        v.key
                    ),
                    contributing_runs: vec![],
                });
            }
        }
    }

    if config.require_provenance_ok {
        for v in &report.variants {
            if let Some(rate) = v.provenance_ok_rate {
                if rate < 1.0 {
                    failures.push(GateRuleFailure {
                        rule: "require_provenance_ok".into(),
                        message: format!(
                            "variant {} provenance_ok_rate={rate:.3} < 1.0 (task success is independent)",
                            v.key
                        ),
                        contributing_runs: v.provenance_failed_runs.clone(),
                    });
                }
            } else if config.fail_on_insufficient_evidence {
                failures.push(GateRuleFailure {
                    rule: "require_provenance_ok".into(),
                    message: format!(
                        "variant {} missing provenance trust data",
                        v.key
                    ),
                    contributing_runs: vec![],
                });
            }
        }
    }

    if config.fail_on_critical_findings {
        for v in &report.variants {
            if v.critical_findings > 0 {
                failures.push(GateRuleFailure {
                    rule: "fail_on_critical_findings".into(),
                    message: format!(
                        "variant {} has {} critical boundary finding(s)",
                        v.key, v.critical_findings
                    ),
                    contributing_runs: v.boundary_failed_runs.clone(),
                });
            }
        }
    }

    if let Some(min_rate) = config.min_verified_rate {
        for v in &report.variants {
            // Prefer domain-confirmed rate when the report provides it.
            let rate = if config.require_domain_confirmed {
                v.domain_confirmed_rate
                    .or(v.verified_rate)
                    .unwrap_or(0.0)
            } else {
                v.verified_rate.unwrap_or(0.0)
            };
            // Never treat unverified execution success as verified.
            if rate < min_rate {
                failures.push(GateRuleFailure {
                    rule: if config.require_domain_confirmed {
                        "min_domain_confirmed_rate".into()
                    } else {
                        "min_verified_rate".into()
                    },
                    message: format!(
                        "variant {} verified_rate={rate:.3} < {min_rate:.3} (execution success is not verification; domain_confirmed={})",
                        v.key, config.require_domain_confirmed
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
