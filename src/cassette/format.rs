//! Cassette file format for MCP JSON-RPC tool calls.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectClass {
    None,
    Read,
    Write,
    External,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CassetteEntry {
    pub sequence: u64,
    pub request_id: serde_json::Value,
    pub tool_name: String,
    pub request: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub side_effect: SideEffectClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_hash: Option<String>,
    /// mock | live
    #[serde(default = "default_source")]
    pub result_source: String,
}

fn default_source() -> String {
    "mock".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CassetteFile {
    pub schema: String,
    pub protocol: String,
    pub version: u32,
    pub experimental: bool,
    #[serde(default)]
    pub limitations: Vec<String>,
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
    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(s: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}
