//! Cassette request matching modes.

use serde::{Deserialize, Serialize};

use crate::cassette::format::CassetteEntry;
use crate::crypto::content_key;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    /// Exact canonical request JSON and order.
    Strict,
    /// Ignore configured volatile fields (id, timestamps).
    Normalized,
    /// Match next compatible request by tool name + normalized body.
    Ordered,
    /// Allow extra unknown calls by policy (not auto-pass).
    AllowExtra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub matched: bool,
    pub entry_sequence: Option<u64>,
    pub mode: MatchMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
    pub unsupported_unproxied: bool,
}

/// Normalize a JSON-RPC request for comparison: drop id and known volatile keys.
pub fn normalize_request(req: &serde_json::Value) -> serde_json::Value {
    let mut v = req.clone();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("id");
        if let Some(params) = obj.get_mut("params").and_then(|p| p.as_object_mut()) {
            params.remove("_meta");
            params.remove("progressToken");
        }
    }
    v
}

pub fn request_hash(req: &serde_json::Value) -> String {
    content_key(serde_json::to_string(req).unwrap_or_default().as_bytes())
}

pub fn match_request(
    mode: MatchMode,
    entries: &[CassetteEntry],
    cursor: usize,
    incoming: &serde_json::Value,
    tool_name: &str,
) -> (MatchResult, usize) {
    match mode {
        MatchMode::Strict => {
            if let Some(entry) = entries.get(cursor) {
                let same_tool = entry.tool_name == tool_name;
                let same_body = entry.request == *incoming;
                if same_tool && same_body {
                    return (
                        MatchResult {
                            matched: true,
                            entry_sequence: Some(entry.sequence),
                            mode,
                            diff: None,
                            unsupported_unproxied: false,
                        },
                        cursor + 1,
                    );
                }
                return (
                    MatchResult {
                        matched: false,
                        entry_sequence: Some(entry.sequence),
                        mode,
                        diff: Some(format!(
                            "strict mismatch tool={} vs {}",
                            entry.tool_name, tool_name
                        )),
                        unsupported_unproxied: false,
                    },
                    cursor,
                );
            }
            (
                MatchResult {
                    matched: false,
                    entry_sequence: None,
                    mode,
                    diff: Some("no more cassette entries".into()),
                    unsupported_unproxied: false,
                },
                cursor,
            )
        }
        MatchMode::Normalized | MatchMode::Ordered => {
            let norm_in = normalize_request(incoming);
            for (i, entry) in entries.iter().enumerate().skip(cursor) {
                if entry.tool_name != tool_name {
                    if matches!(mode, MatchMode::Ordered) {
                        continue;
                    } else {
                        break;
                    }
                }
                let norm_entry = normalize_request(&entry.request);
                if norm_entry == norm_in {
                    return (
                        MatchResult {
                            matched: true,
                            entry_sequence: Some(entry.sequence),
                            mode,
                            diff: None,
                            unsupported_unproxied: false,
                        },
                        i + 1,
                    );
                }
                if matches!(mode, MatchMode::Normalized) {
                    return (
                        MatchResult {
                            matched: false,
                            entry_sequence: Some(entry.sequence),
                            mode,
                            diff: Some("normalized payload mismatch".into()),
                            unsupported_unproxied: false,
                        },
                        cursor,
                    );
                }
            }
            (
                MatchResult {
                    matched: false,
                    entry_sequence: None,
                    mode,
                    diff: Some("no matching entry".into()),
                    unsupported_unproxied: false,
                },
                cursor,
            )
        }
        MatchMode::AllowExtra => {
            let (mut r, c) = match_request(MatchMode::Ordered, entries, cursor, incoming, tool_name);
            if !r.matched {
                r.diff = Some("unknown call under allow_extra — policy must pass/deny".into());
            }
            (r, c)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cassette::format::{CassetteEntry, SideEffectClass};

    #[test]
    fn normalized_ignores_jsonrpc_id() {
        let entry = CassetteEntry {
            sequence: 1,
            request_id: serde_json::json!(1),
            tool_name: "tools/call".into(),
            request: serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}),
            response: Some(serde_json::json!({"ok":true})),
            error: None,
            latency_ms: Some(1),
            side_effect: SideEffectClass::None,
            request_hash: None,
            response_hash: None,
            result_source: "mock".into(),
        };
        let incoming = serde_json::json!({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"x"}});
        let (r, _) = match_request(MatchMode::Normalized, &[entry], 0, &incoming, "tools/call");
        assert!(r.matched);
    }
}
