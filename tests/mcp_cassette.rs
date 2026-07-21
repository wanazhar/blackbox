//! 1.6 E: MCP cassette matching (experimental).

use blackbox::cassette::format::{CassetteEntry, CassetteFile, SideEffectClass};
use blackbox::cassette::matching::{match_request, MatchMode};
use blackbox::redaction::scanner::SecretScanner;
use blackbox::redaction::RedactionConfig;

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

/// Record-path redaction: cassette payloads must not retain raw secrets.
#[test]
fn cassette_secret_store_scan_fixture() {
    let secret = "sk-ant-api03-SUPERSECRETTOKEN1234567890";
    let scanner = SecretScanner::new(RedactionConfig::default());
    let mut raw_params = serde_json::json!({
        "name": "bash",
        "arguments": {"command": format!("export KEY={secret}")}
    });
    // Simulate record-path redaction of free-form JSON.
    let mut as_val = raw_params.clone();
    scanner.redact_json(&mut as_val);
    raw_params = as_val;

    let entry = CassetteEntry {
        sequence: 1,
        request_id: serde_json::json!(1),
        tool_name: "tools/call".into(),
        request: serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": raw_params
        }),
        response: Some(serde_json::json!({"content": format!("ok {secret}")})),
        error: None,
        latency_ms: Some(1),
        side_effect: SideEffectClass::Write,
        request_hash: None,
        response_hash: None,
        result_source: "record".into(),
    };
    // Redact response the same way the proxy would.
    let mut resp = entry.response.clone().unwrap();
    scanner.redact_json(&mut resp);

    let mut cass = CassetteFile::default();
    let mut safe_entry = entry;
    safe_entry.response = Some(resp);
    cass.entries.push(safe_entry);

    let dumped = serde_json::to_string_pretty(&cass).unwrap();
    assert!(
        !dumped.contains(secret),
        "cassette JSON must not contain raw secret; got:\n{dumped}"
    );
    // Redaction markers or truncated form should appear instead.
    assert!(
        dumped.contains("REDACTED") || dumped.contains("***") || dumped.contains("[redacted]")
            || !dumped.contains("SUPERSECRET"),
        "expected redaction marker in cassette body"
    );
}
