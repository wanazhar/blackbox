//! Adapter TOML/JSON manifest.

use serde::{Deserialize, Serialize};

pub const ADAPTER_PROTOCOL: &str = "blackbox.adapter/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterManifest {
    pub name: String,
    pub protocol: String,
    pub command: Vec<String>,
    #[serde(default)]
    pub detect_basenames: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl AdapterManifest {
    pub fn from_toml(s: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(s)?)
    }

    pub fn from_json(s: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}
