//! Adapter TOML/JSON manifest.

use serde::{Deserialize, Serialize};

/// `ADAPTER_PROTOCOL` constant.
pub const ADAPTER_PROTOCOL: &str = "blackbox.adapter/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `AdapterManifest` value.
pub struct AdapterManifest {
    /// Display name.
    pub name: String,
    /// Protocol.
    pub protocol: String,
    /// Command argv.
    pub command: Vec<String>,
    #[serde(default)]
    /// Detect basenames.
    pub detect_basenames: Vec<String>,
    #[serde(default)]
    /// Capabilities.
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Version string or number.
    pub version: Option<String>,
}

impl AdapterManifest {
    /// Build from toml.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_toml` — see module docs for full workflow.
    /// ```
    pub fn from_toml(s: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(s)?)
    }

    /// Build from json.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_json` — see module docs for full workflow.
    /// ```
    pub fn from_json(s: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}
