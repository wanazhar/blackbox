//! 1.6 E: live MCP cassette **record** e2e against a real stdio server (CI).

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use blackbox::cassette::CassetteFile;

fn fixture_server() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mcp_echo_server.py")
}

#[test]
fn record_against_python_echo_server() {
    let server = fixture_server();
    assert!(
        server.is_file(),
        "missing fixture server at {}",
        server.display()
    );

    let dir = tempfile::tempdir().unwrap();
    let cassette = dir.path().join("recorded.bbx.json");
    let bin = env!("CARGO_BIN_EXE_blackbox");

    let mut child = Command::new(bin)
        .args([
            "cassette",
            "proxy",
            "--record",
            cassette.to_str().unwrap(),
            "--",
            "python3",
            server.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn blackbox cassette proxy");

    let mut stdin = child.stdin.take().unwrap();
    // Client session against the proxy (which fronts the real echo server).
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{{}},"clientInfo":{{"name":"test","version":"0"}}}}}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"echo","arguments":{{"text":"hello-cassette"}}}}}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"echo","arguments":{{"text":"second"}}}}}}"#
    )
    .unwrap();
    drop(stdin);

    let out = child.wait_with_output().expect("wait proxy");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "proxy failed status={:?} stderr={stderr} stdout={stdout}",
        out.status
    );
    assert!(
        stdout.contains("hello-cassette") || stdout.contains("result"),
        "client did not receive server results: {stdout}"
    );

    assert!(
        cassette.is_file(),
        "cassette not written: {}",
        cassette.display()
    );
    let cass = CassetteFile::from_json(&std::fs::read_to_string(&cassette).unwrap()).unwrap();
    assert!(cass.experimental, "cassette must be marked experimental");
    assert!(
        cass.entries.len() >= 2,
        "expected >=2 recorded tools/call entries, got {}: {:?}",
        cass.entries.len(),
        cass.entries
            .iter()
            .map(|e| e.tool_name.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        cass.entries.iter().all(|e| e.result_source == "live"),
        "record mode should mark result_source=live"
    );
    // Replay the cassette without a live server.
    let mut replay = Command::new(bin)
        .args([
            "cassette",
            "proxy",
            "--replay",
            cassette.to_str().unwrap(),
            "--mode",
            "normalized",
            "--on-unknown",
            "fail",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    {
        let mut rin = replay.stdin.take().unwrap();
        writeln!(
            rin,
            r#"{{"jsonrpc":"2.0","id":10,"method":"initialize","params":{{}}}}"#
        )
        .unwrap();
        writeln!(
            rin,
            r#"{{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{{"name":"echo","arguments":{{"text":"hello-cassette"}}}}}}"#
        )
        .unwrap();
    }
    let rout = replay.wait_with_output().unwrap();
    let rstdout = String::from_utf8_lossy(&rout.stdout);
    assert!(rout.status.success(), "replay failed");
    assert!(
        rstdout.contains("hello-cassette") || rstdout.contains("mock"),
        "replay did not return recorded payload: {rstdout}"
    );
}
