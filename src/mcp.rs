//! Minimal MCP (Model Context Protocol) stdio server.
//!
//! JSON-RPC 2.0, newline-delimited messages on stdin/stdout.
//! Spec subset: initialize, tools/list, tools/call, ping.

use std::io::{BufRead, BufReader, Write};

use serde_json::{json, Value};

use crate::analysis::detect_anomalies;
use crate::config::discover_project;
use crate::context::{build_context_pack, ContextOptions};
use crate::search::search_store;
use crate::status::{build_status, StatusOptions};
use crate::storage::sqlite::{SqliteStore, SCHEMA_VERSION};
use crate::storage::TraceStore;
use crate::summary::{build_summary, SummaryOptions};
use crate::util::{is_bookkeeping, short_id};
use crate::views::TimelineEventView;

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "blackbox";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run the MCP server until stdin closes.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `run_mcp_stdio` — see module docs for full workflow.
/// ```
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
        "instructions": "Enabled project: call blackbox_handoff or blackbox_memory before other work. Prefer project_memory over re-reading transcripts. Honor active claims. On failure: blackbox_postmortem or blackbox_fail, then blackbox_timeline / blackbox_anomalies. Use blackbox_status for lightweight checks."
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
                "One-command postmortem / summary of a recorded run (headline, next_action, evidence, anomalies).",
                json!({
                    "type": "object",
                    "properties": {
                        "run_id": { "type": "string", "description": "Run id, prefix, or 'latest'", "default": "latest" }
                    }
                }),
            ),
            tool_def(
                "blackbox_fail",
                "One-shot failure focus: picks unresolved failure / last failure / latest, returns postmortem + next commands. Prefer when debugging a bad run.",
                json!({
                    "type": "object",
                    "properties": {
                        "run_id": { "type": "string", "description": "Optional run id/prefix; omit to auto-focus failure" },
                        "full": { "type": "boolean", "description": "Larger event window for postmortem", "default": false }
                    }
                }),
            ),
            tool_def(
                "blackbox_timeline",
                "Event timeline for a run (semantic filter by default). Use after postmortem evidence seq=…",
                json!({
                    "type": "object",
                    "properties": {
                        "run_id": { "type": "string", "description": "Run id, prefix, or 'latest'", "default": "latest" },
                        "semantic": { "type": "boolean", "description": "Hide bookkeeping observer events", "default": true },
                        "kind": { "type": "string", "description": "Filter by event kind, e.g. tool.call" },
                        "limit": { "type": "integer", "description": "Max events to return", "default": 200 }
                    }
                }),
            ),
            tool_def(
                "blackbox_anomalies",
                "Anomaly markers for a run (tool loops, destructive ops, error storms, token spikes, long silence, process fan-out).",
                json!({
                    "type": "object",
                    "properties": {
                        "run_id": { "type": "string", "description": "Run id, prefix, or 'latest'", "default": "latest" },
                        "limit": { "type": "integer", "description": "Max events to scan (default 8000)", "default": 8000 }
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
            tool_def(
                "blackbox_memory",
                "Project memory pack (blackbox.memory/v1). Call at session start; prefer over transcripts.",
                json!({
                    "type": "object",
                    "properties": {
                        "max_tokens": { "type": "integer", "default": 4000 }
                    }
                }),
            ),
            tool_def(
                "blackbox_claim",
                "Project or path-scoped claim acquire|release|status for multi-agent coordination. Use path for non-overlapping tree scopes.",
                json!({
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "enum": ["acquire", "release", "status"], "default": "status" },
                        "goal": { "type": "string" },
                        "ttl_secs": { "type": "integer" },
                        "holder": { "type": "string" },
                        "path": { "type": "string", "description": "Path scope relative to project root (omit for whole-project claim)" }
                    }
                }),
            ),
            tool_def(
                "blackbox_resolve",
                "Clear unresolved failure attention (optional clear open_items).",
                json!({
                    "type": "object",
                    "properties": {
                        "clear_wip": { "type": "boolean", "default": false },
                        "clear_goal": { "type": "boolean", "default": false }
                    }
                }),
            ),
            tool_def(
                "blackbox_memory_update",
                "Set project intent: goal / open_items (redacted).",
                json!({
                    "type": "object",
                    "properties": {
                        "goal": { "type": "string" },
                        "open_items": { "type": "array", "items": { "type": "string" } },
                        "clear_open": { "type": "boolean" },
                        "clear_goal": { "type": "boolean" },
                        "plan": { "type": "string" }
                    }
                }),
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
        "blackbox_fail" => tool_fail(store_override, &args).await,
        "blackbox_timeline" => tool_timeline(store_override, &args).await,
        "blackbox_anomalies" => tool_anomalies(store_override, &args).await,
        "blackbox_context" => tool_context(store_override, &args).await,
        "blackbox_runs" => tool_runs(store_override, &args).await,
        "blackbox_search" => tool_search(store_override, &args).await,
        "blackbox_doctor" => tool_doctor(store_override).await,
        "blackbox_memory" => tool_memory(store_override, &args).await,
        "blackbox_claim" => tool_claim(store_override, &args).await,
        "blackbox_resolve" => tool_resolve(store_override, &args).await,
        "blackbox_memory_update" => tool_memory_update(store_override, &args).await,
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
            include_project_memory: true,
        }
    } else {
        let resume = args
            .get("resume")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        StatusOptions {
            include_resume: resume,
            max_tokens,
            force_resume: false,
            include_project_memory: resume,
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

/// MCP mirror of CLI `blackbox fail` focus order.
async fn resolve_fail_run(
    store: &dyn TraceStore,
    discovery: &crate::config::ProjectDiscovery,
    spec: Option<&str>,
) -> Result<(crate::core::run::Run, &'static str), Value> {
    if let Some(s) = spec {
        if !s.is_empty() {
            let run = resolve_run(store, s).await?;
            return Ok((run, "explicit"));
        }
    }
    if let Ok(Some(st)) = crate::state::ProjectState::load(&discovery.paths.root) {
        if let Some(fid) = st.unresolved_failure_id {
            if let Ok(Some(r)) = store.get_run(&fid).await {
                return Ok((r, "unresolved_failure"));
            }
        }
    }
    let runs = store
        .list_runs()
        .await
        .map_err(|e| rpc_err(-32000, &e.to_string()))?;
    if runs.is_empty() {
        return Err(rpc_err(-32000, "no runs in store"));
    }
    if let Some(r) = runs.iter().find(|r| {
        matches!(
            r.status,
            crate::core::run::RunStatus::Failed | crate::core::run::RunStatus::Cancelled
        ) || r.exit_code.is_some_and(|c| c != 0)
    }) {
        return Ok((r.clone(), "last_failure"));
    }
    Ok((runs.into_iter().next().unwrap(), "latest"))
}

async fn tool_fail(store_override: Option<&std::path::Path>, args: &Value) -> Result<Value, Value> {
    let (discovery, store) = open_ctx(store_override).await?;
    let store = store
        .ok_or_else(|| rpc_err(-32000, "no store; run blackbox enable / record a run first"))?;
    let spec = args.get("run_id").and_then(|v| v.as_str());
    let (run, focus) = resolve_fail_run(&store, &discovery, spec).await?;
    let full = args.get("full").and_then(|v| v.as_bool()).unwrap_or(false);
    let opts = if full {
        SummaryOptions {
            short: false,
            full: true,
        }
    } else {
        SummaryOptions::default()
    };
    let summary = build_summary(&store, &run, opts)
        .await
        .map_err(|e| rpc_err(-32000, &e.to_string()))?;
    let failed = matches!(
        run.status,
        crate::core::run::RunStatus::Failed | crate::core::run::RunStatus::Cancelled
    ) || run.exit_code.is_some_and(|c| c != 0);
    let short = short_id(&run.id).to_string();
    let v = json!({
        "focus": focus,
        "run_id": run.id,
        "short_id": short,
        "failed": failed,
        "summary": summary,
        "next_commands": [
            format!("blackbox timeline {short} --semantic"),
            format!("blackbox show {short} --tui"),
            format!("blackbox postmortem {short} --json"),
            "blackbox resolve",
        ],
    });
    Ok(tool_ok(&v))
}

fn event_detail_line(ev: &crate::core::event::TraceEvent) -> String {
    let m = &ev.metadata;
    if let Some(p) = m.get("preview").and_then(|v| v.as_str()) {
        return p.chars().take(160).collect();
    }
    if let Some(t) = m.get("tool_name").and_then(|v| v.as_str()) {
        return t.to_string();
    }
    if let Some(p) = m.get("path").and_then(|v| v.as_str()) {
        return p.to_string();
    }
    if let Some(c) = m.get("exit_code") {
        return format!("exit={c}");
    }
    String::new()
}

async fn tool_timeline(
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
    let semantic = args
        .get("semantic")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let kind_filter = args.get("kind").and_then(|v| v.as_str());
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;

    let events = store
        .get_events_limited(&run.id, 8_000)
        .await
        .map_err(|e| rpc_err(-32000, &e.to_string()))?
        .0;

    let mut matched: Vec<_> = events
        .iter()
        .filter(|e| {
            if semantic && is_bookkeeping(&e.kind) {
                return false;
            }
            if let Some(k) = kind_filter {
                if e.kind != k {
                    return false;
                }
            }
            true
        })
        .collect();
    let total_matched = matched.len();
    let truncated = total_matched > limit;
    matched.truncate(limit);

    let views: Vec<TimelineEventView> = matched
        .iter()
        .map(|ev| TimelineEventView::from_event(ev, event_detail_line(ev)))
        .collect();

    let v = json!({
        "run_id": run.id,
        "short_id": short_id(&run.id),
        "semantic": semantic,
        "kind": kind_filter,
        "events": views,
        "truncated": truncated,
        "total_matched": total_matched,
        "returned": views.len(),
    });
    Ok(tool_ok(&v))
}

async fn tool_anomalies(
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
    let scan_limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(8_000) as usize;
    let events = store
        .get_events_limited(&run.id, scan_limit)
        .await
        .map_err(|e| rpc_err(-32000, &e.to_string()))?
        .0;
    let anomalies = detect_anomalies(&events);
    let v = json!({
        "run_id": run.id,
        "short_id": short_id(&run.id),
        "count": anomalies.len(),
        "anomalies": anomalies,
        "events_scanned": events.len(),
    });
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

async fn tool_memory(
    store_override: Option<&std::path::Path>,
    args: &Value,
) -> Result<Value, Value> {
    use crate::memory::{build_project_memory, MemoryBuildOptions};
    use crate::state::ProjectState;
    let (discovery, store) = open_ctx(store_override).await?;
    let sticky = ProjectState::load(&discovery.paths.root)
        .map_err(|e| rpc_err(-32000, &e.to_string()))?
        .unwrap_or_default();
    let max_tokens = args
        .get("max_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(4000) as usize;
    let continuity = discovery
        .config
        .as_ref()
        .map(|c| c.capture.continuity_from_config())
        .unwrap_or(crate::config::ContinuityMode::Off);
    let pack = build_project_memory(
        store.as_ref().map(|s| s as &dyn TraceStore),
        &sticky,
        MemoryBuildOptions {
            max_tokens,
            purpose: "project-memory".into(),
            continuity_mode: continuity.as_str().into(),
            project_root: discovery.project_root.clone(),
            store_db: discovery.paths.db_path.clone(),
            skip_porcelain_if_none: sticky.attention_level.is_none(),
        },
    )
    .await
    .map_err(|e| rpc_err(-32000, &e.to_string()))?;
    let v = serde_json::to_value(&pack).map_err(|e| rpc_err(-32000, &e.to_string()))?;
    Ok(tool_ok(&v))
}

async fn tool_claim(
    store_override: Option<&std::path::Path>,
    args: &Value,
) -> Result<Value, Value> {
    use crate::state::{claim_acquire_scoped, claim_holder_id, claim_release, ProjectState};
    let (discovery, _) = open_ctx(store_override).await?;
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("status");
    let ttl = args
        .get("ttl_secs")
        .and_then(|v| v.as_u64())
        .or_else(|| discovery.config.as_ref().map(|c| c.capture.claim_ttl_secs))
        .unwrap_or(1800);
    match action {
        "acquire" => {
            let (default_holder, kind) = claim_holder_id(None, None, false);
            let holder = args
                .get("holder")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or(default_holder);
            let goal = args
                .get("goal")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            match claim_acquire_scoped(&discovery.paths.root, &holder, &kind, None, goal, ttl, path)
                .map_err(|e| rpc_err(-32000, &e.to_string()))?
            {
                Ok(c) => {
                    let v =
                        serde_json::to_value(&c).map_err(|e| rpc_err(-32000, &e.to_string()))?;
                    Ok(tool_ok(&v))
                }
                Err(conflict) => Ok(tool_ok(&json!({ "ok": false, "conflict": conflict }))),
            }
        }
        "release" => {
            let holder = args.get("holder").and_then(|v| v.as_str());
            let c = claim_release(&discovery.paths.root, holder)
                .map_err(|e| rpc_err(-32000, &e.to_string()))?;
            let v = serde_json::to_value(&c).map_err(|e| rpc_err(-32000, &e.to_string()))?;
            Ok(tool_ok(&v))
        }
        _ => {
            let mut sticky = ProjectState::load(&discovery.paths.root)
                .map_err(|e| rpc_err(-32000, &e.to_string()))?
                .unwrap_or_default();
            sticky.expire_claim_if_needed(chrono::Utc::now());
            let v = json!({
                "project_claim": sticky.active_claim,
                "path_claims": sticky.path_claims,
            });
            Ok(tool_ok(&v))
        }
    }
}

async fn tool_resolve(
    store_override: Option<&std::path::Path>,
    args: &Value,
) -> Result<Value, Value> {
    use crate::core::run::{Run, RunStatus};
    use crate::state::{apply_run_outcome, with_state_lock, OutcomeExtras};
    let (discovery, _) = open_ctx(store_override).await?;
    let clear_wip = args
        .get("clear_wip")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let clear_goal = args
        .get("clear_goal")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let remaining = with_state_lock(&discovery.paths.root, |state| {
        let fid = state.unresolved_failure_id.clone();
        let mut run = Run::new(
            vec!["blackbox".into(), "resolve".into()],
            discovery.project_root.display().to_string(),
        );
        run.status = RunStatus::Succeeded;
        run.exit_code = Some(0);
        run.ended_at = Some(chrono::Utc::now());
        if let Some(ref id) = fid {
            run.parent_run_id = Some(id.clone());
        }
        apply_run_outcome(
            state,
            &run,
            OutcomeExtras {
                resolve_failure: true,
                clear_wip,
                ..Default::default()
            },
        );
        if clear_goal {
            state.intent.goal = None;
        }
        Ok(state.unresolved_failure_id.clone())
    })
    .map_err(|e| rpc_err(-32000, &e.to_string()))?;
    Ok(tool_ok(&json!({
        "resolved": remaining.is_none(),
        "unresolved_failure_id": remaining
    })))
}

async fn tool_memory_update(
    store_override: Option<&std::path::Path>,
    args: &Value,
) -> Result<Value, Value> {
    use crate::redaction::scanner::SecretScanner;
    use crate::redaction::RedactionConfig;
    use crate::state::{with_state_lock, ProjectState};
    let (discovery, _) = open_ctx(store_override).await?;
    let scanner = SecretScanner::new(RedactionConfig::default());
    with_state_lock(&discovery.paths.root, |state| {
        if args
            .get("clear_goal")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            state.intent.goal = None;
        } else if let Some(g) = args.get("goal").and_then(|v| v.as_str()) {
            state.intent.goal = if g.is_empty() {
                None
            } else {
                Some(scanner.redact(g))
            };
        }
        if args
            .get("clear_open")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            state.intent.open_items.clear();
        } else if let Some(items) = args.get("open_items").and_then(|v| v.as_array()) {
            state.intent.open_items = items
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| scanner.redact(s))
                .take(8)
                .collect();
        }
        if let Some(p) = args.get("plan").and_then(|v| v.as_str()) {
            state.intent.plan_summary = if p.is_empty() {
                None
            } else {
                Some(scanner.redact(p))
            };
        }
        if !state.intent.open_items.is_empty() && state.unresolved_failure_id.is_none() {
            state.attention_level = crate::state::AttentionLevel::Continue;
            state.attention_reason = Some("wip".into());
            state.attention_needed = true;
        }
        state.updated_at = chrono::Utc::now();
        Ok(())
    })
    .map_err(|e| rpc_err(-32000, &e.to_string()))?;
    let sticky = ProjectState::load(&discovery.paths.root)
        .map_err(|e| rpc_err(-32000, &e.to_string()))?
        .unwrap_or_default();
    let v = serde_json::to_value(&sticky).map_err(|e| rpc_err(-32000, &e.to_string()))?;
    Ok(tool_ok(&v))
}

async fn tool_doctor(store_override: Option<&std::path::Path>) -> Result<Value, Value> {
    let (discovery, store) = open_ctx(store_override).await?;
    let run_count = if let Some(ref s) = store {
        s.list_runs().await.map(|r| r.len()).unwrap_or(0)
    } else {
        0
    };
    let sticky = crate::state::ProjectState::load(&discovery.paths.root)
        .ok()
        .flatten();
    let continuity_mode = discovery
        .config
        .as_ref()
        .map(|c| c.capture.continuity_from_config().as_str())
        .unwrap_or("off");
    let memory_path = discovery.paths.root.join("MEMORY.json");
    let memory_file_present = memory_path.exists();
    let memory_age_secs = memory_path
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .map(|d| d.as_secs());
    let v = json!({
        "project_root": discovery.project_root,
        "store_db": discovery.paths.db_path,
        "blob_dir": discovery.paths.blob_dir,
        "enabled": discovery.config.as_ref().map(|c| c.enabled).unwrap_or(false),
        "schema_version": SCHEMA_VERSION,
        "run_count": run_count,
        "config": discovery.config,
        "continuity_mode": continuity_mode,
        "memory_file_present": memory_file_present,
        "memory_age_secs": memory_age_secs,
        "claims_active": sticky.as_ref().and_then(|s| s.active_claim.as_ref()).is_some(),
        "unresolved_failure_id": sticky.as_ref().and_then(|s| s.unresolved_failure_id.clone()),
        "attention_level": sticky.as_ref().map(|s| s.attention_level.as_str()).unwrap_or("none"),
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
        assert!(names.contains(&"blackbox_postmortem"));
        // 1.3 T3 debug spine
        assert!(names.contains(&"blackbox_timeline"));
        assert!(names.contains(&"blackbox_anomalies"));
        assert!(names.contains(&"blackbox_fail"));
    }

    #[test]
    fn initialize_has_protocol() {
        let r = initialize_result();
        assert_eq!(r["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(r["serverInfo"]["name"], "blackbox");
    }

    #[tokio::test]
    async fn timeline_and_anomalies_tools_on_emptyish_run() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let blobs = dir.path().join("blobs");
        let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
        let store: std::sync::Arc<dyn TraceStore> = std::sync::Arc::new(store);

        let mut run =
            crate::core::run::Run::new(vec!["true".into()], dir.path().display().to_string());
        run.status = crate::core::run::RunStatus::Succeeded;
        run.exit_code = Some(0);
        store.insert_run(&run).await.unwrap();

        let mut ev = crate::core::event::TraceEvent::new(
            &run.id,
            crate::core::event::EventSource::Terminal,
            "terminal.output",
        );
        ev.sequence = 0;
        ev.metadata
            .insert("preview".into(), serde_json::json!("hello"));
        store.insert_event(&ev).await.unwrap();

        // Bookkeeping should be filtered when semantic=true
        let mut bk = crate::core::event::TraceEvent::new(
            &run.id,
            crate::core::event::EventSource::System,
            "pty.started",
        );
        bk.sequence = 1;
        store.insert_event(&bk).await.unwrap();

        let tl = tool_timeline(
            Some(db.as_path()),
            &json!({ "run_id": run.id, "semantic": true, "limit": 50 }),
        )
        .await
        .unwrap();
        let text = tl["content"][0]["text"].as_str().unwrap();
        let body: Value = serde_json::from_str(text).unwrap();
        assert_eq!(body["run_id"], run.id);
        assert_eq!(body["semantic"], true);
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["kind"], "terminal.output");

        let an = tool_anomalies(Some(db.as_path()), &json!({ "run_id": "latest" }))
            .await
            .unwrap();
        let text = an["content"][0]["text"].as_str().unwrap();
        let body: Value = serde_json::from_str(text).unwrap();
        assert!(body["anomalies"].is_array());
        assert_eq!(body["count"], 0);

        let fail = tool_fail(Some(db.as_path()), &json!({})).await.unwrap();
        let text = fail["content"][0]["text"].as_str().unwrap();
        let body: Value = serde_json::from_str(text).unwrap();
        assert_eq!(body["focus"], "latest");
        assert_eq!(body["failed"], false);
        assert!(body["summary"]["headline"].is_string());
    }
}
