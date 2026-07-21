//! Experiment schema and run metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EXPERIMENT_SCHEMA: &str = "blackbox.experiment/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentRole {
    Baseline,
    Candidate,
    Control,
    Treatment,
    #[default]
    Unknown,
}

/// Checked-in or created experiment manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentManifest {
    pub schema: String,
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub tasks: Vec<String>,
    #[serde(default)]
    pub variants: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl ExperimentManifest {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            schema: EXPERIMENT_SCHEMA.into(),
            id: id.into(),
            name: name.into(),
            description: None,
            created_at: Utc::now(),
            tasks: Vec::new(),
            variants: Vec::new(),
            tags: Vec::new(),
        }
    }
}

/// Typed metadata linking a run to an experiment (stored separately from Run.status).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunExperimentMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experiment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u32>,
    #[serde(default)]
    pub role: ExperimentRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_case: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_fingerprint: Option<String>,
}

impl RunExperimentMeta {
    /// Stable fingerprint of configuration knobs (not the run id).
    ///
    /// Covers variant/task/role/model/provider/harness/seed/dataset so identical
    /// experimental setups share a fingerprint across attempts.
    pub fn compute_config_fingerprint(&self) -> String {
        use crate::crypto::content_key;
        let raw = format!(
            "v1|exp={}|task={}|variant={}|role={:?}|seed={}|case={}|model={}|provider={}|harness={}|hver={}|git={}",
            self.experiment_id.as_deref().unwrap_or(""),
            self.task_id.as_deref().unwrap_or(""),
            self.variant.as_deref().unwrap_or(""),
            self.role,
            self.seed.as_deref().unwrap_or(""),
            self.dataset_case.as_deref().unwrap_or(""),
            self.model.as_deref().unwrap_or(""),
            self.provider.as_deref().unwrap_or(""),
            self.harness.as_deref().unwrap_or(""),
            self.harness_version.as_deref().unwrap_or(""),
            self.git_commit.as_deref().unwrap_or(""),
        );
        content_key(raw.as_bytes())[..16].to_string()
    }

    /// Ensure `config_fingerprint` is populated from current fields.
    pub fn with_fingerprint(mut self) -> Self {
        if self.config_fingerprint.is_none() {
            self.config_fingerprint = Some(self.compute_config_fingerprint());
        }
        self
    }
}

/// Suggest the next attempt number for an experiment cohort (1-based).
///
/// Counts existing runs that share the same experiment_id + task + variant
/// fingerprint key. Pass already-loaded metas for the experiment.
pub fn next_attempt_number(existing: &[RunExperimentMeta], for_meta: &RunExperimentMeta) -> u32 {
    let key = (
        for_meta.experiment_id.as_deref(),
        for_meta.task_id.as_deref(),
        for_meta.variant.as_deref(),
    );
    let mut max_attempt = 0u32;
    for m in existing {
        let k = (
            m.experiment_id.as_deref(),
            m.task_id.as_deref(),
            m.variant.as_deref(),
        );
        if k == key {
            max_attempt = max_attempt.max(m.attempt.unwrap_or(0));
        }
    }
    max_attempt.saturating_add(1).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_stable_and_attempt_increments() {
        let a = RunExperimentMeta {
            experiment_id: Some("e1".into()),
            task_id: Some("t1".into()),
            variant: Some("baseline".into()),
            model: Some("gpt".into()),
            ..Default::default()
        }
        .with_fingerprint();
        let b = RunExperimentMeta {
            experiment_id: Some("e1".into()),
            task_id: Some("t1".into()),
            variant: Some("baseline".into()),
            model: Some("gpt".into()),
            attempt: Some(1),
            ..Default::default()
        }
        .with_fingerprint();
        assert_eq!(a.config_fingerprint, b.config_fingerprint);
        assert_eq!(next_attempt_number(&[b], &a), 2);
    }
}
