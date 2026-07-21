//! Experiment schema and run metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EXPERIMENT_SCHEMA: &str = "blackbox.experiment/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentRole {
    Baseline,
    Candidate,
    Control,
    Treatment,
    Unknown,
}

impl Default for ExperimentRole {
    fn default() -> Self {
        Self::Unknown
    }
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
