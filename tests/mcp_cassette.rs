//! 1.6 E: MCP cassette matching (experimental).

use blackbox::cassette::format::{CassetteEntry, CassetteFile, SideEffectClass};
use blackbox::cassette::matching::{match_request, MatchMode};

#[test]
fn cassette_marks_experimental_and_matches_normalized() {
    let mut cass = CassetteFile::default();
    assert!(cass.experimental);
    assert!(cass
        .limitations
        .iter()
        .any(|l| l.contains("unproxied") || l.contains("MCP")));

    cass.entries.push(CassetteEntry {
        sequence: 1,
        request_id: serde_json::json!(1),
        tool_name: "tools/call".into(),
        request: serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "a.rs"}}
        }),
        response: Some(serde_json::json!({"content": "ok"})),
        error: None,
        latency_ms: Some(5),
        side_effect: SideEffectClass::Read,
        request_hash: None,
        response_hash: None,
        result_source: "mock".into(),
    });

    let incoming = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "a.rs"}}
    });
    let (r, next) = match_request(
        MatchMode::Normalized,
        &cass.entries,
        0,
        &incoming,
        "tools/call",
    );
    assert!(r.matched);
    assert_eq!(next, 1);
    assert!(!r.unsupported_unproxied);
}
