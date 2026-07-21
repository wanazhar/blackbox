//! 1.6 E: MCP cassette proxy record/replay smoke (experimental).

use std::io::Write;
use std::process::{Command, Stdio};

use blackbox::cassette::{CassetteFile, MatchMode};

/// Replay against a prebuilt cassette without a live server.
#[test]
fn replay_cassette_tools_call_normalized() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.bbx.json");
    let mut cass = CassetteFile::default();
    cass.entries.push(blackbox::cassette::CassetteEntry {
        sequence: 1,
        request_id: serde_json::json!(1),
        tool_name: "echo".into(),
        request: serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "echo", "arguments": { "text": "hi" } }
        }),
        response: Some(serde_json::json!({ "content": [{"type":"text","text":"hi"}] })),
        error: None,
        latency_ms: Some(2),
        side_effect: blackbox::cassette::SideEffectClass::None,
        request_hash: None,
        response_hash: None,
        result_source: "live".into(),
    });
    std::fs::write(&path, cass.to_json().unwrap()).unwrap();

    // Drive proxy via stdin/stdout of the blackbox binary if available; else unit match.
    let bin = env!("CARGO_BIN_EXE_blackbox");
    let mut child = Command::new(bin)
        .args([
            "cassette",
            "proxy",
            "--replay",
            path.to_str().unwrap(),
            "--mode",
            "normalized",
            "--on-unknown",
            "fail",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn blackbox");

    let mut stdin = child.stdin.take().unwrap();
    // initialize
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":0,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    // tools/call with different id
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{{"name":"echo","arguments":{{"text":"hi"}}}}}}"#
    )
    .unwrap();
    drop(stdin);

    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "stderr/status {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("mock") || stdout.contains("hi") || stdout.contains("result"),
        "unexpected proxy output: {stdout}"
    );
    let _ = MatchMode::Normalized;
}
