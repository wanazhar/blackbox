//! Experimental MCP stdio proxy for cassette record/replay (1.6 Phase E).
//!
//! Blackbox sits between an MCP client and an MCP server process:
//!
//! ```text
//! client  --stdio-->  blackbox mcp proxy  --stdio-->  server
//! ```
//!
//! Record mode redacts nothing structural beyond the existing secret scanner
//! on string payloads when enabled. Replay mode never starts a live server
//! unless `--live-passthrough` is set for unmatched calls.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::Value;

use crate::cassette::format::{CassetteEntry, CassetteFile, SideEffectClass};
use crate::cassette::matching::{match_request, normalize_request, request_hash, MatchMode};
use crate::crypto::content_key;
use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub mode: ProxyMode,
    pub cassette_path: PathBuf,
    pub match_mode: MatchMode,
    /// When replaying, unmatched calls: fail | deny | live
    pub on_unknown: UnknownPolicy,
    pub server_argv: Vec<String>,
    pub redact: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    Record,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownPolicy {
    /// Return JSON-RPC error (default safe).
    Fail,
    /// Return a structured deny result.
    Deny,
    /// Forward to live server (requires server_argv; visibly marked).
    Live,
}

impl UnknownPolicy {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "fail" => Ok(Self::Fail),
            "deny" => Ok(Self::Deny),
            "live" | "live_passthrough" => Ok(Self::Live),
            other => anyhow::bail!("unknown on-unknown policy: {other} (fail|deny|live)"),
        }
    }
}

/// Run the proxy until stdin EOF. Returns the final cassette (record) or match stats.
pub fn run_mcp_proxy(config: ProxyConfig) -> anyhow::Result<ProxyReport> {
    match config.mode {
        ProxyMode::Record => run_record(config),
        ProxyMode::Replay => run_replay(config),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyReport {
    pub mode: String,
    pub experimental: bool,
    pub entries: usize,
    pub matched: usize,
    pub unmatched: usize,
    pub live_passthrough: usize,
    pub cassette_path: String,
    #[serde(default)]
    pub limitations: Vec<String>,
}

fn run_record(config: ProxyConfig) -> anyhow::Result<ProxyReport> {
    if config.server_argv.is_empty() {
        anyhow::bail!("record mode requires a server command after `--`");
    }
    let mut child = spawn_server(&config.server_argv)?;
    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("server stdin missing"))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("server stdout missing"))?;
    let mut child_out = BufReader::new(child_stdout);

    let scanner = if config.redact {
        Some(SecretScanner::new(RedactionConfig::default()))
    } else {
        None
    };

    let mut cassette = CassetteFile::default();
    let mut sequence = 0u64;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let client_in = BufReader::new(stdin.lock());

    // Pending request by JSON-RPC id for pairing responses.
    let mut pending: std::collections::HashMap<String, (Value, Instant, String)> =
        std::collections::HashMap::new();

    for line in client_in.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut msg: Value = serde_json::from_str(line)?;
        if let Some(ref sc) = scanner {
            sc.redact_json(&mut msg);
        }
        // Forward to server
        writeln!(child_stdin, "{}", serde_json::to_string(&msg)?)?;
        child_stdin.flush()?;

        // Track tools/call (and methods that look like tool invocations)
        if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
            if method == "tools/call" || method.starts_with("tools/") {
                let id_key = id_key(msg.get("id"));
                let tool = msg
                    .get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or(method)
                    .to_string();
                pending.insert(id_key, (msg.clone(), Instant::now(), tool));
            }
        }

        // Read one response line (blocking). MCP is typically request/response ordered.
        let mut resp_line = String::new();
        child_out.read_line(&mut resp_line)?;
        if resp_line.is_empty() {
            break;
        }
        let mut resp: Value = serde_json::from_str(resp_line.trim())?;
        if let Some(ref sc) = scanner {
            sc.redact_json(&mut resp);
        }

        if let Some(id) = resp.get("id") {
            let key = id_key(Some(id));
            if let Some((req, t0, tool_name)) = pending.remove(&key) {
                sequence += 1;
                let latency = t0.elapsed().as_millis() as u64;
                let (response, error) = if resp.get("error").is_some() {
                    (None, resp.get("error").cloned())
                } else {
                    (resp.get("result").cloned(), None)
                };
                let req_hash = request_hash(&normalize_request(&req));
                let resp_hash = response
                    .as_ref()
                    .map(|r| content_key(serde_json::to_string(r).unwrap_or_default().as_bytes()));
                cassette.entries.push(CassetteEntry {
                    sequence,
                    request_id: id.clone(),
                    tool_name,
                    request: req,
                    response,
                    error,
                    latency_ms: Some(latency),
                    side_effect: SideEffectClass::Unknown,
                    request_hash: Some(req_hash),
                    response_hash: resp_hash,
                    result_source: "live".into(),
                });
            }
        }

        writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
        stdout.flush()?;
    }

    let _ = child.kill();
    let _ = child.wait();

    std::fs::write(&config.cassette_path, cassette.to_json()?)?;
    Ok(ProxyReport {
        mode: "record".into(),
        experimental: true,
        entries: cassette.entries.len(),
        matched: 0,
        unmatched: 0,
        live_passthrough: 0,
        cassette_path: config.cassette_path.display().to_string(),
        limitations: cassette.limitations,
    })
}

fn run_replay(config: ProxyConfig) -> anyhow::Result<ProxyReport> {
    let text = std::fs::read_to_string(&config.cassette_path)?;
    let cassette = CassetteFile::from_json(&text)?;
    let mut cursor = 0usize;
    let mut matched = 0usize;
    let mut unmatched = 0usize;
    let mut live_passthrough = 0usize;

    let mut live_child: Option<Child> = None;
    let live_io: Arc<Mutex<Option<(std::process::ChildStdin, BufReader<std::process::ChildStdout>)>>> =
        Arc::new(Mutex::new(None));

    if matches!(config.on_unknown, UnknownPolicy::Live) {
        if config.server_argv.is_empty() {
            anyhow::bail!("live passthrough requires a server command after `--`");
        }
        let mut child = spawn_server(&config.server_argv)?;
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        *live_io.lock().unwrap() = Some((stdin, stdout));
        live_child = Some(child);
    }

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let client_in = BufReader::new(stdin.lock());

    for line in client_in.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = serde_json::from_str(line)?;
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");

        // Non-tool methods: handle initialize/ping locally or passthrough.
        if method == "initialize" {
            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "blackbox-cassette-replay",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "blackbox": {
                        "experimental": true,
                        "result_source": "mock",
                        "note": "MCP cassette replay — unproxied harness tools are unsupported"
                    }
                }
            });
            writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
            stdout.flush()?;
            continue;
        }
        if method == "ping" || method == "notifications/initialized" || method.starts_with("notifications/") {
            if id.is_some() && !id.as_ref().map(|v| v.is_null()).unwrap_or(true) {
                let resp = serde_json::json!({"jsonrpc":"2.0","id": id, "result": {}});
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
            }
            continue;
        }
        if method == "tools/list" {
            // Advertise tools from cassette uniqueness.
            let mut names = std::collections::BTreeSet::new();
            for e in &cassette.entries {
                names.insert(e.tool_name.clone());
            }
            let tools: Vec<Value> = names
                .into_iter()
                .map(|n| {
                    serde_json::json!({
                        "name": n,
                        "description": "replayed from blackbox cassette (experimental)",
                        "inputSchema": { "type": "object" }
                    })
                })
                .collect();
            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": tools }
            });
            writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
            stdout.flush()?;
            continue;
        }

        let tool_name = if method == "tools/call" {
            msg.get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("tools/call")
                .to_string()
        } else {
            method.to_string()
        };

        let (mres, new_cursor) =
            match_request(config.match_mode, &cassette.entries, cursor, &msg, &tool_name);

        if mres.matched {
            matched += 1;
            cursor = new_cursor;
            let entry = &cassette.entries[new_cursor - 1];
            let resp = if let Some(ref err) = entry.error {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": err,
                    "blackbox": { "result_source": "mock", "experimental": true }
                })
            } else {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": entry.response.clone().unwrap_or(serde_json::json!({})),
                    "blackbox": {
                        "result_source": "mock",
                        "experimental": true,
                        "cassette_sequence": entry.sequence
                    }
                })
            };
            writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
            stdout.flush()?;
            continue;
        }

        unmatched += 1;
        match config.on_unknown {
            UnknownPolicy::Fail => {
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": format!(
                            "cassette miss (unproxied or unmatched): {}",
                            mres.diff.unwrap_or_else(|| "no match".into())
                        ),
                        "data": {
                            "unsupported_unproxied": true,
                            "experimental": true
                        }
                    }
                });
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
            }
            UnknownPolicy::Deny => {
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": "denied by blackbox cassette policy (unknown call)"
                        }],
                        "isError": true,
                        "blackbox": { "result_source": "deny", "experimental": true }
                    }
                });
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
            }
            UnknownPolicy::Live => {
                live_passthrough += 1;
                let mut guard = live_io.lock().unwrap();
                let (ref mut c_in, ref mut c_out) = guard
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("live server not started"))?;
                writeln!(c_in, "{line}")?;
                c_in.flush()?;
                let mut resp_line = String::new();
                c_out.read_line(&mut resp_line)?;
                let mut resp: Value = serde_json::from_str(resp_line.trim())?;
                if let Some(obj) = resp.as_object_mut() {
                    obj.insert(
                        "blackbox".into(),
                        serde_json::json!({
                            "result_source": "live",
                            "experimental": true,
                            "live_passthrough": true
                        }),
                    );
                }
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
            }
        }
    }

    if let Some(mut child) = live_child {
        let _ = child.kill();
        let _ = child.wait();
    }

    Ok(ProxyReport {
        mode: "replay".into(),
        experimental: true,
        entries: cassette.entries.len(),
        matched,
        unmatched,
        live_passthrough,
        cassette_path: config.cassette_path.display().to_string(),
        limitations: cassette.limitations,
    })
}

fn spawn_server(argv: &[String]) -> anyhow::Result<Child> {
    let mut cmd = Command::new(&argv[0]);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    Ok(cmd.spawn()?)
}

fn id_key(id: Option<&Value>) -> String {
    match id {
        Some(v) => v.to_string(),
        None => "null".into(),
    }
}

/// Convenience: write an empty cassette skeleton.
pub fn init_cassette(path: &Path) -> anyhow::Result<()> {
    let c = CassetteFile::default();
    std::fs::write(path, c.to_json()?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cassette::format::CassetteEntry;

    #[test]
    fn unknown_policy_parse() {
        assert!(matches!(
            UnknownPolicy::parse("fail").unwrap(),
            UnknownPolicy::Fail
        ));
        assert!(UnknownPolicy::parse("nope").is_err());
    }

    #[test]
    fn replay_match_mode_normalized_pairs() {
        // Unit-level: matching used by proxy.
        let entry = CassetteEntry {
            sequence: 1,
            request_id: serde_json::json!(1),
            tool_name: "read".into(),
            request: serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}),
            response: Some(serde_json::json!({"ok":true})),
            error: None,
            latency_ms: Some(1),
            side_effect: SideEffectClass::None,
            request_hash: None,
            response_hash: None,
            result_source: "live".into(),
        };
        let cass = CassetteFile {
            entries: vec![entry],
            ..Default::default()
        };
        let incoming = serde_json::json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read"}});
        let (r, _) = match_request(MatchMode::Normalized, &cass.entries, 0, &incoming, "read");
        assert!(r.matched);
    }
}
