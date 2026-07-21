//! Eval / CI score schema (`blackbox.score/v1`).
//!
//! Written as `score.json` under `--artifact-dir` for harness benchmarks and CI.
//! Stable machine shape — additive fields only in later versions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::run::Run;
use crate::summary::SummaryView;
use crate::util::short_id;

/// Schema id for the eval score document.
pub const SCORE_SCHEMA: &str = "blackbox.score/v1";

/// Machine-readable run score for eval / CI scoring harnesses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvalScore {
    /// Always `blackbox.score/v1`.
    pub schema: String,
    /// Owning run id.
    pub run_id: String,
    /// Short id.
    pub short_id: String,
    /// Lowercase status debug name (e.g. `succeeded`, `failed`).
    pub status: String,
    /// Process exit code, if known.
    pub exit_code: Option<i32>,
    /// True when status is Failed/Cancelled or exit_code != 0.
    pub failed: bool,
    /// Duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// Adapter.
    pub adapter: Option<String>,
    /// Associated tags.
    pub tags: Vec<String>,
    /// Display name.
    pub name: Option<String>,
    /// Command argv.
    pub command: Vec<String>,
    /// Postmortem headline (may be empty on trivial success).
    pub headline: String,
    /// Next action.
    pub next_action: String,
    /// Total anomaly markers.
    pub anomaly_count: usize,
    /// Counts by severity (`high` / `warn` / `info`).
    pub anomalies_by_severity: BTreeMap<String, usize>,
    /// Counts by kind (`tool_loop`, `destructive`, …).
    pub anomalies_by_kind: BTreeMap<String, usize>,
    /// Capture coverage quality 0–100 when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_quality: Option<u8>,
    /// Events scanned for the postmortem window.
    pub events_scanned: usize,
    /// Tool call total from summary when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools_total: Option<usize>,
    /// Structured error count from summary.
    pub error_count: usize,
    /// Optional estimated cost when pricing enabled on the run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd: Option<f64>,
    /// Wall clock of score build (always present for scorer hygiene).
    pub scored_at: String,
}

impl EvalScore {
    /// Build a score document from a finished run + its postmortem summary.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_run_summary` — see module docs for full workflow.
    /// ```
    pub fn from_run_summary(run: &Run, summary: &SummaryView) -> Self {
        let failed = matches!(
            run.status,
            crate::core::run::RunStatus::Failed | crate::core::run::RunStatus::Cancelled
        ) || run.exit_code.is_some_and(|c| c != 0);

        let mut by_sev: BTreeMap<String, usize> = BTreeMap::new();
        let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
        for a in &summary.anomalies {
            *by_sev.entry(a.severity.clone()).or_default() += 1;
            *by_kind.entry(a.kind.clone()).or_default() += 1;
        }

        let capture_quality = summary.capture_coverage.as_ref().map(|c| c.quality_score);

        Self {
            schema: SCORE_SCHEMA.into(),
            run_id: run.id.clone(),
            short_id: short_id(&run.id).to_string(),
            status: format!("{:?}", run.status).to_lowercase(),
            exit_code: run.exit_code,
            failed,
            duration_ms: run.duration_ms.or(summary.duration_ms),
            adapter: run.adapter.clone(),
            tags: run.tags.clone(),
            name: run.name.clone(),
            command: run.command.clone(),
            headline: summary.headline.clone(),
            next_action: summary.next_action.clone(),
            anomaly_count: summary.anomalies.len(),
            anomalies_by_severity: by_sev,
            anomalies_by_kind: by_kind,
            capture_quality,
            events_scanned: summary.events_scanned,
            tools_total: Some(summary.tools.total),
            error_count: summary.errors.len(),
            estimated_cost_usd: run.estimated_cost_usd,
            scored_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Serialize as pretty JSON for `score.json`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `to_pretty_json` — see module docs for full workflow.
    /// ```
    pub fn to_pretty_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::run::RunStatus;
    use crate::summary::{AnomalyView, SummaryView, ToolsSummary};

    fn empty_summary(run: &Run) -> SummaryView {
        SummaryView {
            run_id: run.id.clone(),
            short_id: short_id(&run.id).to_string(),
            status: run.status.clone(),
            exit_code: run.exit_code,
            duration_ms: run.duration_ms,
            command: run.command.clone(),
            tags: run.tags.clone(),
            tools: ToolsSummary {
                total: 0,
                failed: 0,
                names: vec![],
            },
            errors: vec![],
            side_effects: vec![],
            git: crate::summary::GitSummary {
                start: None,
                end: None,
            },
            resume: crate::views::ResumeView {
                available: false,
                command: None,
            },
            truncated: false,
            events_scanned: 3,
            total_events: Some(3),
            hints: vec![],
            failure_fix_chains: vec![],
            narrative: String::new(),
            capture_coverage: None,
            retry_waste: vec![],
            turning_points: vec![],
            next_action: "inspect timeline".into(),
            evidence: vec![],
            headline: "failed run".into(),
            anomalies: vec![AnomalyView {
                kind: "tool_loop".into(),
                severity: "high".into(),
                detail: "Bash×5".into(),
                event_id: None,
                sequence: Some(9),
                count: Some(5),
            }],
            claims: vec![],
            goal_source: "unavailable".into(),
            goal: "goal unavailable".into(),
            verification_coverage: None,
            latest_verification_receipt_id: None,
            latest_verification_status: None,
            outcome: None,
            analysis_scope: None,
            aggregates: None,
        }
    }

    #[test]
    fn score_schema_and_anomaly_rollups() {
        let mut run = Run::new(vec!["false".into()], "/tmp".into());
        run.status = RunStatus::Failed;
        run.exit_code = Some(1);
        run.tags = vec!["eval".into(), "ci".into()];
        run.adapter = Some("generic".into());
        let summary = empty_summary(&run);
        let score = EvalScore::from_run_summary(&run, &summary);
        assert_eq!(score.schema, SCORE_SCHEMA);
        assert!(score.failed);
        assert_eq!(score.anomaly_count, 1);
        assert_eq!(score.anomalies_by_severity.get("high"), Some(&1));
        assert_eq!(score.anomalies_by_kind.get("tool_loop"), Some(&1));
        assert_eq!(score.exit_code, Some(1));
        let json = score.to_pretty_json().unwrap();
        assert!(json.contains("blackbox.score/v1"));
        assert!(json.contains("tool_loop"));
    }
}
