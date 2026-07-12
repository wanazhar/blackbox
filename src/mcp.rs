//! Minimal MCP (Model Context Protocol) stdio server.
//!
//! JSON-RPC 2.0, newline-delimited messages on stdin/stdout.
//! Spec subset: initialize, tools/list, tools/call, ping.

use std::io::{BufRead, BufReader, Write};

use serde_json::{json, Value};

use crate::config::discover_project;
use crate::context::{build_context_pack, ContextOptions};
use crate::search::search_store;
use crate::status::{build_status, StatusOptions};
use crate::storage::sqlite::{SqliteStore, SCHEMA_VERSION};
use crate::storage::TraceStore;
use crate::summary::{build_summary, SummaryOptions};

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "blackbox";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run the MCP server until stdin closes.
pub async fn run_mcp_stdio(store_override: Option<&std::path::Path>) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let reader = BufReader::new(stdin.lock());

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                write_msg(
                    &mut stdout,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": { "code": -32700, "message": format!("parse error: {e}") }
                    }),
                )?;
                continue;
            }
        };

        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(json!({}));

        if method == "notifications/initialized" || method.starts_with("notifications/") {
            continue;
        }

        let result = match method {
            "initialize" => Ok(initialize_result()),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(tools_list()),
            "tools/call" => handle_tool_call(store_override, &params).await,
            "resources/list" => Ok(json!({ "resources": [] })),
            "prompts/list" => Ok(json!({ "prompts": [] })),
            "" => Err(rpc_err(-32600, "invalid request: missing method")),
            other => Err(rpc_err(-32601, &format!("method not found: {other}"))),
        };

        if id.is_none() || id.as_ref().map(|v| v.is_null()).unwrap_or(false) {
            continue;
        }

        let response = match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e }),
        };
        write_msg(&mut stdout, &response)?;
    }
    Ok(())
}

fn write_msg(out: &mut impl Write, msg: &Value) -> anyhow::Result<()> {
    let s = serde_json::to_string(msg)?;
    writeln!(out, "{s}")?;
    out.flush()?;
    Ok(())
}

fn rpc_err(code: i64, message: &str) -> Value {
    json!({ "code": code, "message": message })
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION
        },
        "instructions": "blackbox flight recorder. Prefer blackbox_handoff at session start; use blackbox_status for lightweight checks."
    })
}

fn tools_list() -> Value {
    json!({
        "tools": [
            tool_def(
                "blackbox_status",
                "Project capture status: enabled, last run, attention, next commands. Call at session start or when unsure if a prior agent failed.",
                json!({
                    "type": "object",
                    "properties": {
                        "resume": { "type": "boolean", "description": "Attach resume pack when attention is needed", "default": false },
                        "max_tokens": { "type": "integer", "description": "Max tokens for resume pack", "default": 4000 }
                    }
                }),
            ),
            tool_def(
                "blackbox_handoff",
                "Agent handoff: status plus resume pack when the last run needs attention. Preferred session-start tool.",
                json!({
                    "type": "object",
                    "properties": {
                        "always": { "type": "boolean", "description": "Always attach resume pack for last run", "default": false },
                        "max_tokens": { "type": "integer", "default": 4000 }
                    }
                }),
            ),
            tool_def(
                "blackbox_postmortem",
                "One-command postmortem / summary of a recorded run.",
                json!({
                    "type": "object",
                    "properties": {
                        "run_id": { "type": "string", "description": "Run id, prefix, or 'latest'", "default": "latest" }
                    }
                }),
            ),
            tool_def(
                "blackbox_context",
                "Bounded resume context pack for retrying a run.",
                json!({
                    "type": "object",
                    "properties": {
                        "run_id": { "type": "string", "default": "latest" },
                        "max_tokens": { "type": "integer", "default": 4000 },
                        "no_transcript": { "type": "boolean", "default": false }
                    }
                }),
            ),
            tool_def(
                "blackbox_runs",
                "List recorded runs (newest first).",
                json!({
                    "type": "object",
                    "properties": {
                        "limit": { "type": "integer", "default": 20 },
                        "status": { "type": "string", "description": "Filter: succeeded|failed|cancelled|running|…" }
                    }
                }),
            ),
            tool_def(
                "blackbox_search",
                "Full-text search across runs and events.",
                json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" },
                        "limit": { "type": "integer", "default": 20 }
                    },
                    "required": ["query"]
                }),
            ),
            tool_def(
                "blackbox_doctor",
                "Diagnose store path, schema, and environment health.",
                json!({ "type": "object", "properties": {} }),
            ),
        ]
    })
}

fn tool_def(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema
    })
}

async fn handle_tool_call(
    store_override: Option<&std::path::Path>,
    params: &Value,
) -> Result<Value, Value> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| rpc_err(-32602, "missing tool name"))?;
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    match name {
        "blackbox_status" => tool_status(store_override, &args, false).await,
        "blackbox_handoff" => tool_status(store_override, &args, true).await,
        "blackbox_postmortem" => tool_postmortem(store_override, &args).await,
        "blackbox_context" => tool_context(store_override, &args).await,
        "blackbox_runs" => tool_runs(store_override, &args).await,
        "blackbox_search" => tool_search(store_override, &args).await,
        "blackbox_doctor" => tool_doctor(store_override).await,
        other => Err(rpc_err(-32602, &format!("unknown tool: {other}"))),
    }
}

fn tool_ok(value: &Value) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
        }],
        "structuredContent": value,
        "isError": false
    })
}

async fn open_ctx(
    store_override: Option<&std::path::Path>,
) -> Result<(crate::config::ProjectDiscovery, Option<SqliteStore>), Value> {
    let cwd = std::env::current_dir().map_err(|e| rpc_err(-32000, &e.to_string()))?;
    let discovery =
        discover_project(&cwd, store_override).map_err(|e| rpc_err(-32000, &e.to_string()))?;
    let store = if discovery.paths.db_path.exists() {
        Some(
            SqliteStore::open_with_blobs(&discovery.paths.db_path, &discovery.paths.blob_dir)
                .map_err(|e| rpc_err(-32000, &e.to_string()))?,
        )
    } else {
        None
    };
    Ok((discovery, store))
}

async fn tool_status(
    store_override: Option<&std::path::Path>,
    args: &Value,
    handoff: bool,
) -> Result<Value, Value> {
    let (discovery, store) = open_ctx(store_override).await?;
    let store_ref = store.as_ref().map(|s| s as &dyn TraceStore);
    let max_tokens = args
        .get("max_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(4000) as usize;

    let opts = if handoff {
        StatusOptions {
            include_resume: true,
            max_tokens,
            force_resume: args
                .get("always")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        }
    } else {
        StatusOptions {
            include_resume: args
                .get("resume")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            max_tokens,
            force_resume: false,
        }
    };

    let view = build_status(&discovery, store_ref, opts)
        .await
        .map_err(|e| rpc_err(-32000, &e.to_string()))?;
    let v = serde_json::to_value(&view).map_err(|e| rpc_err(-32000, &e.to_string()))?;
    Ok(tool_ok(&v))
}

async fn resolve_run(store: &dyn TraceStore, spec: &str) -> Result<crate::core::run::Run, Value> {
    let runs = store
        .list_runs()
        .await
        .map_err(|e| rpc_err(-32000, &e.to_string()))?;
    if runs.is_empty() {
        return Err(rpc_err(-32000, "no runs in store"));
    }
    if spec == "latest" || spec.is_empty() {
        return Ok(runs.into_iter().next().unwrap());
    }
    if let Some(r) = runs.iter().find(|r| r.id == spec) {
        return Ok(r.clone());
    }
    let matches: Vec<_> = runs.iter().filter(|r| r.id.starts_with(spec)).collect();
    match matches.len() {
        1 => Ok(matches[0].clone()),
        0 => Err(rpc_err(-32000, &format!("run not found: {spec}"))),
        _ => Err(rpc_err(
            -32000,
            &format!("ambiguous run prefix: {spec} ({} matches)", matches.len()),
        )),
    }
}

async fn tool_postmortem(
    store_override: Option<&std::path::Path>,
    args: &Value,
) -> Result<Value, Value> {
    let (_d, store) = open_ctx(store_override).await?;
    let store = store
        .ok_or_else(|| rpc_err(-32000, "no store; run blackbox enable / record a run first"))?;
    let run_id = args
        .get("run_id")
        .and_then(|v| v.as_str())
        .unwrap_or("latest");
    let run = resolve_run(&store, run_id).await?;
    let view = build_summary(&store, &run, SummaryOptions::default())
        .await
        .map_err(|e| rpc_err(-32000, &e.to_string()))?;
    let v = serde_json::to_value(&view).map_err(|e| rpc_err(-32000, &e.to_string()))?;
    Ok(tool_ok(&v))
}

async fn tool_context(
    store_override: Option<&std::path::Path>,
    args: &Value,
) -> Result<Value, Value> {
    let (_d, store) = open_ctx(store_override).await?;
    let store = store.ok_or_else(|| rpc_err(-32000, "no store"))?;
    let run_id = args
        .get("run_id")
        .and_then(|v| v.as_str())
        .unwrap_or("latest");
    let run = resolve_run(&store, run_id).await?;
    let max_tokens = args
        .get("max_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(4000) as usize;
    let no_transcript = args
        .get("no_transcript")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let pack = build_context_pack(
        &store,
        &run,
        ContextOptions {
            max_tokens,
            include_transcript: !no_transcript,
        },
    )
    .await
    .map_err(|e| rpc_err(-32000, &e.to_string()))?;
    let v = serde_json::to_value(&pack).map_err(|e| rpc_err(-32000, &e.to_string()))?;
    Ok(tool_ok(&v))
}

async fn tool_runs(store_override: Option<&std::path::Path>, args: &Value) -> Result<Value, Value> {
    let (_d, store) = open_ctx(store_override).await?;
    let store = store.ok_or_else(|| rpc_err(-32000, "no store"))?;
    let mut runs = store
        .list_runs()
        .await
        .map_err(|e| rpc_err(-32000, &e.to_string()))?;
    if let Some(status) = args.get("status").and_then(|v| v.as_str()) {
        let s = status.to_lowercase();
        runs.retain(|r| format!("{:?}", r.status).to_lowercase() == s);
    }
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    runs.truncate(limit);
    let items: Vec<Value> = runs
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "short_id": crate::util::short_id(&r.id),
                "status": format!("{:?}", r.status).to_lowercase(),
                "exit_code": r.exit_code,
                "name": r.name,
                "command": r.command,
                "started_at": r.started_at,
                "ended_at": r.ended_at,
                "tags": r.tags,
                "adapter": r.adapter,
            })
        })
        .collect();
    Ok(tool_ok(&json!({ "runs": items, "count": items.len() })))
}

async fn tool_search(
    store_override: Option<&std::path::Path>,
    args: &Value,
) -> Result<Value, Value> {
    let (_d, store) = open_ctx(store_override).await?;
    let store = store.ok_or_else(|| rpc_err(-32000, "no store"))?;
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| rpc_err(-32602, "query required"))?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let hits = search_store(&store, query, 50, limit)
        .await
        .map_err(|e| rpc_err(-32000, &e.to_string()))?;
    let items: Vec<Value> = hits
        .iter()
        .map(|h| {
            json!({
                "run_id": h.run_id,
                "run_label": h.run_label,
                "event_id": h.event_id,
                "sequence": h.sequence,
                "kind": h.kind,
                "snippet": h.snippet,
                "score": h.score,
                "backend": h.backend,
            })
        })
        .collect();
    Ok(tool_ok(&json!({ "hits": items, "count": items.len() })))
}

async fn tool_doctor(store_override: Option<&std::path::Path>) -> Result<Value, Value> {
    let (discovery, store) = open_ctx(store_override).await?;
    let run_count = if let Some(ref s) = store {
        s.list_runs().await.map(|r| r.len()).unwrap_or(0)
    } else {
        0
    };
    let v = json!({
        "project_root": discovery.project_root,
        "store_db": discovery.paths.db_path,
        "blob_dir": discovery.paths.blob_dir,
        "enabled": discovery.config.as_ref().map(|c| c.enabled).unwrap_or(false),
        "schema_version": SCHEMA_VERSION,
        "run_count": run_count,
        "config": discovery.config,
    });
    Ok(tool_ok(&v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_list_has_core_tools() {
        let list = tools_list();
        let tools = list["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"blackbox_handoff"));
        assert!(names.contains(&"blackbox_status"));
        assert!(names.contains(&"blackbox_search"));
    }

    #[test]
    fn initialize_has_protocol() {
        let r = initialize_result();
        assert_eq!(r["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(r["serverInfo"]["name"], "blackbox");
    }
}
