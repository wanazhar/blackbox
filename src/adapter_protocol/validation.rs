//! Adapter manifest and event validation / conformance helpers.

use serde::{Deserialize, Serialize};

use crate::adapter_protocol::manifest::{AdapterManifest, ADAPTER_PROTOCOL};

pub const MAX_ADAPTER_EVENT_BYTES: usize = 1024 * 1024; // 1 MiB

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationReport {
    pub ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn validate_adapter_manifest(m: &AdapterManifest) -> ValidationReport {
    let mut r = ValidationReport {
        ok: true,
        ..Default::default()
    };
    if m.name.trim().is_empty() {
        r.ok = false;
        r.errors.push("name is required".into());
    }
    if m.protocol != ADAPTER_PROTOCOL {
        r.ok = false;
        r.errors.push(format!(
            "unsupported protocol {:?} (expected {ADAPTER_PROTOCOL})",
            m.protocol
        ));
    }
    if m.command.is_empty() {
        r.ok = false;
        r.errors.push("command must be non-empty".into());
    }
    if m.detect_basenames.is_empty() {
        r.warnings
            .push("detect_basenames empty — adapter will not auto-detect".into());
    }
    r
}

/// Validate one NDJSON adapter event line (canonical subset).
pub fn validate_adapter_event(line: &str) -> ValidationReport {
    let mut r = ValidationReport {
        ok: true,
        ..Default::default()
    };
    if line.len() > MAX_ADAPTER_EVENT_BYTES {
        r.ok = false;
        r.errors.push(format!(
            "event exceeds max size {} bytes",
            MAX_ADAPTER_EVENT_BYTES
        ));
        return r;
    }
    let v: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            r.ok = false;
            r.errors.push(format!("invalid JSON: {e}"));
            return r;
        }
    };
    let obj = match v.as_object() {
        Some(o) => o,
        None => {
            r.ok = false;
            r.errors.push("event must be a JSON object".into());
            return r;
        }
    };
    for req in ["kind", "source_sequence"] {
        if !obj.contains_key(req) {
            r.ok = false;
            r.errors.push(format!("missing required field {req}"));
        }
    }
    if let Some(kind) = obj.get("kind").and_then(|k| k.as_str()) {
        if kind.is_empty() {
            r.ok = false;
            r.errors.push("kind must be non-empty".into());
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_protocol() {
        let m = AdapterManifest {
            name: "x".into(),
            protocol: "nope".into(),
            command: vec!["x".into()],
            detect_basenames: vec![],
            capabilities: vec![],
            version: None,
        };
        assert!(!validate_adapter_manifest(&m).ok);
    }

    #[test]
    fn accepts_event() {
        let line = r#"{"kind":"tool.call","source_sequence":1,"tool_name":"Bash"}"#;
        assert!(validate_adapter_event(line).ok);
    }
}
