//! Experiment schema and run metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// `EXPERIMENT_SCHEMA` constant.
pub const EXPERIMENT_SCHEMA: &str = "blackbox.experiment/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
/// `ExperimentRole` classification.
pub enum ExperimentRole {
    /// `Baseline` variant.
    Baseline,
    /// `Candidate` variant.
    Candidate,
    /// `Control` variant.
    Control,
    /// `Treatment` variant.
    Treatment,
    #[default]
    /// `Unknown` variant.
    Unknown,
}

/// Checked-in or created experiment manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentManifest {
    /// Schema identifier string.
    pub schema: String,
    /// Unique identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Human-readable description.
    pub description: Option<String>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    /// Tasks.
    pub tasks: Vec<String>,
    #[serde(default)]
    /// Variants.
    pub variants: Vec<String>,
    #[serde(default)]
    /// Associated tags.
    pub tags: Vec<String>,
}

impl ExperimentManifest {
    /// Create a new instance.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `new` — see module docs for full workflow.
    /// ```
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
    /// Experiment id.
    pub experiment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Task id.
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Variant.
    pub variant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Attempt.
    pub attempt: Option<u32>,
    #[serde(default)]
    /// Role.
    pub role: ExperimentRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Seed.
    pub seed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Dataset case.
    pub dataset_case: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Model.
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Provider.
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Harness.
    pub harness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Harness version.
    pub harness_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Git commit.
    pub git_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Config fingerprint.
    pub config_fingerprint: Option<String>,
}

impl RunExperimentMeta {
    /// Stable fingerprint of configuration knobs (not the run id).
    ///
    /// Covers variant/task/role/model/provider/harness/seed/dataset so identical
    /// experimental setups share a fingerprint across attempts.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `compute_config_fingerprint` — see module docs for full workflow.
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `with_fingerprint` — see module docs for full workflow.
    /// ```
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
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `next_attempt_number` — see module docs for full workflow.
/// ```
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
