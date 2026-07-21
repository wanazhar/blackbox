//! Cassette file format for MCP JSON-RPC tool calls.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// `SideEffectClass` classification.
pub enum SideEffectClass {
    /// `None` variant.
    None,
    /// `Read` variant.
    Read,
    /// `Write` variant.
    Write,
    /// `External` variant.
    External,
    /// `Unknown` variant.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `CassetteEntry` value.
pub struct CassetteEntry {
    /// Monotonic sequence number within the run.
    pub sequence: u64,
    /// Request id.
    pub request_id: serde_json::Value,
    /// Tool name.
    pub tool_name: String,
    /// Request.
    pub request: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Response.
    pub response: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Error.
    pub error: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Latency ms.
    pub latency_ms: Option<u64>,
    /// Side effect.
    pub side_effect: SideEffectClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Request hash.
    pub request_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Response hash.
    pub response_hash: Option<String>,
    /// mock | live
    #[serde(default = "default_source")]
    pub result_source: String,
}

fn default_source() -> String {
    "mock".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `CassetteFile` value.
pub struct CassetteFile {
    /// Schema identifier string.
    pub schema: String,
    /// Protocol.
    pub protocol: String,
    /// Version string or number.
    pub version: u32,
    /// Experimental.
    pub experimental: bool,
    #[serde(default)]
    /// Limitations.
    pub limitations: Vec<String>,
    /// Entries.
    pub entries: Vec<CassetteEntry>,
}

impl Default for CassetteFile {
    fn default() -> Self {
        Self {
            schema: "blackbox.cassette.mcp/v1".into(),
            protocol: "mcp".into(),
            version: 1,
            experimental: true,
            limitations: vec![
                "MCP cassette only; does not intercept unproxied harness-internal tools".into(),
                "default replay has no external server side effects".into(),
            ],
            entries: Vec::new(),
        }
    }
}

impl CassetteFile {
    /// Convert to json.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `to_json` — see module docs for full workflow.
    /// ```
    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
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
