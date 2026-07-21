//! Multi-run experiment reports with missing-data honesty.

use serde::{Deserialize, Serialize};

use crate::core::run::{Run, RunStatus};
use crate::experiment::model::{ExperimentRole, RunExperimentMeta};
use crate::experiment::stats::{median_f64, percentile, StatisticalNote};
use crate::verification::{
    VerificationConfidence, VerificationReceipt, VerificationStatus,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// `ReportVerdict` classification.
pub enum ReportVerdict {
    /// `Improvement` variant.
    Improvement,
    /// `Regression` variant.
    Regression,
    /// `NoMaterialChange` variant.
    NoMaterialChange,
    /// `Mixed` variant.
    Mixed,
    /// `InsufficientEvidence` variant.
    InsufficientEvidence,
    /// `InvalidExperiment` variant.
    InvalidExperiment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `VariantMetrics` value.
pub struct VariantMetrics {
    /// Key.
    pub key: String,
    /// Run count.
    pub run_count: usize,
    /// Execution success.
    pub execution_success: usize,
    /// Verified success.
    pub verified_success: usize,
    /// Passed receipts with Confirmed confidence (domain-matched).
    #[serde(default)]
    pub domain_confirmed: usize,
    /// Unverified.
    pub unverified: usize,
    /// Capture complete.
    pub capture_complete: usize,
    /// Excluded incomplete.
    pub excluded_incomplete: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Duration median ms.
    pub duration_median_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Duration p95 ms.
    pub duration_p95_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Verified rate.
    pub verified_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Domain confirmed rate.
    pub domain_confirmed_rate: Option<f64>,
    /// Denominator note.
    pub denominator_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `ExperimentReport` value.
pub struct ExperimentReport {
    /// Schema identifier string.
    pub schema: String,
    /// Experiment id.
    pub experiment_id: String,
    /// Group by.
    pub group_by: String,
    /// Variants.
    pub variants: Vec<VariantMetrics>,
    /// Verdict.
    pub verdict: ReportVerdict,
    /// Sample size total.
    pub sample_size_total: usize,
    /// Statistical notes.
    pub statistical_notes: Vec<StatisticalNote>,
    /// Limitations.
    pub limitations: Vec<String>,
}

/// `RunReportInput` value.
pub struct RunReportInput {
    /// Run.
    pub run: Run,
    /// Meta.
    pub meta: RunExperimentMeta,
    /// Receipts.
    pub receipts: Vec<VerificationReceipt>,
    /// Capture complete.
    pub capture_complete: bool,
    /// Duration in milliseconds.
    pub duration_ms: Option<u64>,
}

/// Build a cohort report. Never declares a winner from n=1 without insufficient_evidence.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `build_experiment_report` — see module docs for full workflow.
/// ```
pub fn build_experiment_report(
    experiment_id: &str,
    group_by: &str,
    rows: &[RunReportInput],
    min_samples_for_comparison: usize,
) -> ExperimentReport {
    let mut groups: std::collections::BTreeMap<String, Vec<&RunReportInput>> =
        std::collections::BTreeMap::new();
    for row in rows {
        let key = group_key(group_by, row);
        groups.entry(key).or_default().push(row);
    }

    let mut variants = Vec::new();
    let mut limitations = Vec::new();
    let mut notes = Vec::new();

    for (key, items) in &groups {
        let run_count = items.len();
        let mut execution_success = 0usize;
        let mut verified_success = 0usize;
        let mut domain_confirmed = 0usize;
        let mut unverified = 0usize;
        let mut capture_complete = 0usize;
        let mut excluded = 0usize;
        let mut durations: Vec<f64> = Vec::new();

        for item in items {
            if matches!(item.run.status, RunStatus::Succeeded) {
                execution_success += 1;
            }
            let latest = item.receipts.last();
            match latest {
                Some(r) if matches!(r.status, VerificationStatus::Passed) => {
                    verified_success += 1;
                    if matches!(r.confidence, VerificationConfidence::Confirmed) {
                        domain_confirmed += 1;
                    }
                }
                Some(r) if matches!(r.status, VerificationStatus::Unverified) => {
                    unverified += 1;
                }
                None => unverified += 1,
                _ => {}
            }
            if item.capture_complete {
                capture_complete += 1;
            } else {
                excluded += 1;
            }
            if let Some(d) = item.duration_ms.or(item.run.duration_ms) {
                durations.push(d as f64);
            }
        }

        let verified_rate = if run_count > 0 {
            Some(verified_success as f64 / run_count as f64)
        } else {
            None
        };
        let domain_confirmed_rate = if run_count > 0 {
            Some(domain_confirmed as f64 / run_count as f64)
        } else {
            None
        };
        let mut d2 = durations.clone();
        let med = median_f64(&mut d2);
        let p95 = percentile(&mut durations, 95.0);

        notes.push(StatisticalNote {
            sample_size: run_count,
            method: "median_nearest_rank_percentile".into(),
            note: Some(format!("variant={key}")),
        });

        variants.push(VariantMetrics {
            key: key.clone(),
            run_count,
            execution_success,
            verified_success,
            domain_confirmed,
            unverified,
            capture_complete,
            excluded_incomplete: excluded,
            duration_median_ms: med,
            duration_p95_ms: p95,
            verified_rate,
            domain_confirmed_rate,
            denominator_note: format!(
                "rates use run_count={run_count}; domain_confirmed requires Passed+Confirmed confidence"
            ),
        });
    }

    let sample_size_total = rows.len();
    let verdict = if sample_size_total == 0 {
        limitations.push("no runs linked to experiment".into());
        ReportVerdict::InvalidExperiment
    } else if variants.iter().any(|v| v.run_count < min_samples_for_comparison)
        || sample_size_total < min_samples_for_comparison
    {
        limitations.push(format!(
            "insufficient samples for comparison (need >= {min_samples_for_comparison} per compared group)"
        ));
        ReportVerdict::InsufficientEvidence
    } else if variants.len() < 2 {
        limitations.push("single variant/group — no pairwise comparison".into());
        ReportVerdict::InsufficientEvidence
    } else {
        // Compare first two groups by verified_rate when present.
        let a = &variants[0];
        let b = &variants[1];
        match (a.verified_rate, b.verified_rate) {
            (Some(ra), Some(rb)) => {
                let delta = rb - ra;
                if delta > 0.05 {
                    ReportVerdict::Improvement
                } else if delta < -0.05 {
                    ReportVerdict::Regression
                } else {
                    ReportVerdict::NoMaterialChange
                }
            }
            _ => {
                limitations.push("missing verification data for comparison".into());
                ReportVerdict::InsufficientEvidence
            }
        }
    };

    ExperimentReport {
        schema: "blackbox.experiment.report/v1".into(),
        experiment_id: experiment_id.into(),
        group_by: group_by.into(),
        variants,
        verdict,
        sample_size_total,
        statistical_notes: notes,
        limitations,
    }
}

fn group_key(group_by: &str, row: &RunReportInput) -> String {
    match group_by {
        "variant" => row
            .meta
            .variant
            .clone()
            .unwrap_or_else(|| "unknown".into()),
        "task" => row
            .meta
            .task_id
            .clone()
            .unwrap_or_else(|| "unknown".into()),
        "role" => match row.meta.role {
            ExperimentRole::Baseline => "baseline".into(),
            ExperimentRole::Candidate => "candidate".into(),
            ExperimentRole::Control => "control".into(),
            ExperimentRole::Treatment => "treatment".into(),
            ExperimentRole::Unknown => "unknown".into(),
        },
        "model" => row.meta.model.clone().unwrap_or_else(|| "unknown".into()),
        other => format!("unhandled:{other}"),
    }
}
