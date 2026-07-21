//! Shared helpers for parsing harness terminal/stream-json output
//! into structured `TraceEvent`s.

use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};
use regex::Regex;
use std::sync::OnceLock;

fn session_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:session[_-]?id|conversation[_-]?id)["'\s:=]+([a-zA-Z0-9_.\-]{8,})"#)
            .expect("session regex")
    })
}

fn tool_use_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:tool[_-]?use|using tool|tool call)[:\s]+[`'"]?([A-Za-z_][A-Za-z0-9_]*)"#,
        )
        .expect("tool_use regex")
    })
}

/// Classify a tool name into a side-effect level.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `tool_side_effect` — see module docs for full workflow.
/// ```
pub fn tool_side_effect(name: &str) -> SideEffect {
    let lower = name.to_lowercase();
    match lower.as_str() {
        "read" | "read_file" | "grep" | "glob" | "search" | "list" | "ls" | "find"
        | "web_search" | "webfetch" | "get" | "cat" | "view" | "stat" => SideEffect::Read,
        "write" | "write_file" | "edit" | "str_replace" | "strreplace" | "create" | "mkdir"
        | "apply_patch" | "notebook_edit" => SideEffect::LocalWrite,
        "bash" | "shell" | "run" | "execute" | "terminal" | "cmd" => SideEffect::Unknown,
        "delete" | "remove" | "rm" => SideEffect::Destructive,
        "browser" | "http" | "curl" | "fetch" | "post" => SideEffect::ExternalWrite,
        _ => SideEffect::Unknown,
    }
}

/// Extract a session id from free-form text, if present.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `extract_session_id` — see module docs for full workflow.
/// ```
pub fn extract_session_id(text: &str) -> Option<String> {
    session_re()
        .captures(text)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

/// Build a tool.call event.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `tool_call_event` — see module docs for full workflow.
/// ```
pub fn tool_call_event(
    run_id: &str,
    tool_name: &str,
    input: Option<serde_json::Value>,
    tool_use_id: Option<&str>,
) -> TraceEvent {
    let mut ev = TraceEvent::new(run_id, EventSource::Tool, "tool.call");
    ev.status = EventStatus::Running;
    ev.side_effect = tool_side_effect(tool_name);
    ev.metadata
        .insert("tool_name".to_string(), serde_json::json!(tool_name));
    if let Some(ref input) = input {
        // Attach lossless command metadata for shell-like tools when possible.
        attach_shell_command_meta(&mut ev, tool_name, input);
        ev.metadata.insert("input".to_string(), input.clone());
    }
    if let Some(id) = tool_use_id {
        ev.metadata
            .insert("tool_use_id".to_string(), serde_json::json!(id));
    }
    ev
}

/// If this is a shell tool with a command string/array in input, attach
/// [`CommandMetadata`] so sandbox/analysis never need whitespace reconstruction.
fn attach_shell_command_meta(ev: &mut TraceEvent, tool_name: &str, input: &serde_json::Value) {
    use crate::core::command::CommandMetadata;

    let lower = tool_name.to_lowercase();
    let is_shell = matches!(
        lower.as_str(),
        "bash" | "shell" | "run" | "execute" | "terminal" | "cmd"
    );
    if !is_shell {
        // Structured argv tools (e.g. some harnesses pass `args` arrays).
        if let Some(arr) = input.get("argv").and_then(|v| v.as_array()).or_else(|| {
            input
                .get("args")
                .and_then(|v| v.as_array())
                .filter(|a| !a.is_empty() && a.iter().all(|x| x.is_string()))
        }) {
            let argv: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if !argv.is_empty() {
                let cwd = input
                    .get("cwd")
                    .or_else(|| input.get("working_directory"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
                CommandMetadata::from_adapter_argv(argv, cwd).apply_to_event(ev);
            }
        }
        return;
    }

    // Prefer structured argv when the harness provides it.
    if let Some(arr) = input
        .get("argv")
        .and_then(|v| v.as_array())
        .or_else(|| input.get("command").and_then(|v| v.as_array()))
        .or_else(|| {
            input
                .get("args")
                .and_then(|v| v.as_array())
                .filter(|a| !a.is_empty() && a.iter().all(|x| x.is_string()))
        })
    {
        let argv: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        if !argv.is_empty() {
            let cwd = input
                .get("cwd")
                .or_else(|| input.get("working_directory"))
                .and_then(|v| v.as_str())
                .map(String::from);
            CommandMetadata::from_adapter_argv(argv, cwd).apply_to_event(ev);
            return;
        }
    }

    // Shell source string — preserve as shell invocation, not whitespace-split argv.
    let shell_src = input
        .get("command")
        .and_then(|v| v.as_str())
        .or_else(|| input.get("cmd").and_then(|v| v.as_str()))
        .or_else(|| input.get("script").and_then(|v| v.as_str()));

    if let Some(src) = shell_src {
        // Infer shell binary from tool name when possible.
        let shell = match lower.as_str() {
            "bash" => Some("bash"),
            "shell" | "run" | "execute" | "terminal" | "cmd" => Some("bash"),
            _ => None,
        };
        CommandMetadata::from_shell_source(src, shell).apply_to_event(ev);
    }
}

/// Build a tool.result event.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `tool_result_event` — see module docs for full workflow.
/// ```
pub fn tool_result_event(
    run_id: &str,
    tool_use_id: Option<&str>,
    output: Option<serde_json::Value>,
    is_error: bool,
) -> TraceEvent {
    let mut ev = TraceEvent::new(run_id, EventSource::Tool, "tool.result");
    ev.status = if is_error {
        EventStatus::Error
    } else {
        EventStatus::Success
    };
    ev.side_effect = SideEffect::None;
    if let Some(id) = tool_use_id {
        ev.metadata
            .insert("tool_use_id".to_string(), serde_json::json!(id));
    }
    if let Some(output) = output {
        // Preview only in metadata. `output_blob` is reserved for content-addressed
        // keys (set by the capture pipeline when payloads are large).
        let preview = match &output {
            serde_json::Value::String(s) if s.len() > 500 => {
                let end = s.floor_char_boundary(500);
                serde_json::json!(format!("{}...", &s[..end]))
            }
            other => other.clone(),
        };
        ev.metadata.insert("output".to_string(), preview);
        // Full string body for mock replay (bounded) — NOT a blob key.
        if let Some(s) = output.as_str() {
            let body = if s.len() <= 8000 {
                s.to_string()
            } else {
                format!("{}…", &s[..s.floor_char_boundary(8000)])
            };
            ev.metadata
                .insert("output_full".to_string(), serde_json::json!(body));
        }
    }
    ev
}

/// Build a harness.session event.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `session_event` — see module docs for full workflow.
/// ```
pub fn session_event(run_id: &str, session_id: &str, harness: &str) -> TraceEvent {
    let mut ev = TraceEvent::new(run_id, EventSource::Harness, "harness.session");
    ev.status = EventStatus::Success;
    ev.side_effect = SideEffect::None;
    ev.metadata
        .insert("session_id".to_string(), serde_json::json!(session_id));
    ev.metadata
        .insert("harness".to_string(), serde_json::json!(harness));
    ev
}

/// Build a harness.assistant (message) event.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `assistant_event` — see module docs for full workflow.
/// ```
pub fn assistant_event(run_id: &str, preview: &str) -> TraceEvent {
    let mut ev = TraceEvent::new(run_id, EventSource::Harness, "harness.assistant");
    ev.status = EventStatus::Success;
    ev.side_effect = SideEffect::None;
    let text = if preview.len() > 400 {
        let end = preview.floor_char_boundary(400);
        format!("{}...", &preview[..end])
    } else {
        preview.to_string()
    };
    ev.metadata
        .insert("preview".to_string(), serde_json::json!(text));
    ev
}

/// Try to parse one NDJSON / stream-json line into events (Claude-style).
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `parse_claude_json_line` — see module docs for full workflow.
/// ```
pub fn parse_claude_json_line(run_id: &str, line: &str) -> Vec<TraceEvent> {
    let line = line.trim();
    if line.is_empty() || !line.starts_with('{') {
        return Vec::new();
    }
    let Ok(val) = serde_json::from_str::<serde_json::Value>(line) else {
        return Vec::new();
    };
    let mut events = Vec::new();

    // Top-level session_id
    if let Some(sid) = val.get("session_id").and_then(|v| v.as_str()) {
        events.push(session_event(run_id, sid, "claude"));
    }

    let typ = val.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match typ {
        "assistant" => {
            if let Some(content) = val.pointer("/message/content").and_then(|c| c.as_array()) {
                for block in content {
                    let btype = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    match btype {
                        "tool_use" => {
                            let name = block
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("unknown");
                            let id = block.get("id").and_then(|i| i.as_str());
                            let input = block.get("input").cloned();
                            events.push(tool_call_event(run_id, name, input, id));
                        }
                        "text" => {
                            if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                                if !text.trim().is_empty() {
                                    events.push(assistant_event(run_id, text));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        "user" => {
            if let Some(content) = val.pointer("/message/content").and_then(|c| c.as_array()) {
                for block in content {
                    if block.get("type").and_then(|t| t.as_str()) == Some("tool_result") {
                        let id = block.get("tool_use_id").and_then(|i| i.as_str());
                        let is_error = block
                            .get("is_error")
                            .and_then(|e| e.as_bool())
                            .unwrap_or(false);
                        let output = block.get("content").cloned();
                        events.push(tool_result_event(run_id, id, output, is_error));
                    }
                }
            }
        }
        "tool_use" | "function_call" => {
            let name = val
                .get("name")
                .or_else(|| val.get("tool_name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");
            let id = val
                .get("id")
                .or_else(|| val.get("tool_use_id"))
                .and_then(|i| i.as_str());
            let input = val.get("input").or_else(|| val.get("arguments")).cloned();
            events.push(tool_call_event(run_id, name, input, id));
        }
        "tool_result" | "function_call_output" => {
            let id = val
                .get("tool_use_id")
                .or_else(|| val.get("call_id"))
                .or_else(|| val.get("id"))
                .and_then(|i| i.as_str());
            let is_error = val
                .get("is_error")
                .and_then(|e| e.as_bool())
                .unwrap_or(false);
            let output = val.get("content").or_else(|| val.get("output")).cloned();
            events.push(tool_result_event(run_id, id, output, is_error));
        }
        "result" => {
            let mut ev = TraceEvent::new(run_id, EventSource::Harness, "harness.result");
            // Check for error indicators before defaulting to Success
            let is_error = val
                .get("is_error")
                .and_then(|e| e.as_bool())
                .unwrap_or(false)
                || val
                    .get("subtype")
                    .and_then(|s| s.as_str())
                    .is_some_and(|s| s.contains("error"));
            ev.status = if is_error {
                EventStatus::Error
            } else {
                EventStatus::Success
            };
            if let Some(r) = val.get("result") {
                ev.metadata.insert("result".to_string(), r.clone());
            }
            // Usage often nested on result messages
            if let Some(usage) = val.get("usage") {
                events.push(usage_event_from_json(run_id, usage));
            }
            events.push(ev);
        }
        "usage" => {
            events.push(usage_event_from_json(run_id, &val));
        }
        // blackbox stream protocol v1 (generic adapters)
        "tool_call" => {
            let name = val
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");
            let id = val.get("id").and_then(|i| i.as_str());
            let input = val.get("input").cloned();
            events.push(tool_call_event(run_id, name, input, id));
        }
        "session" => {
            if let Some(sid) = val.get("session_id").and_then(|s| s.as_str()) {
                events.push(session_event(run_id, sid, "blackbox"));
            }
        }
        "message" => {
            if let Some(text) = val.get("text").and_then(|t| t.as_str()) {
                if !text.trim().is_empty() {
                    events.push(assistant_event(run_id, text));
                }
            }
        }
        _ => {
            // Nested usage object on any type
            if let Some(usage) = val.get("usage") {
                events.push(usage_event_from_json(run_id, usage));
            }
        }
    }

    events
}

/// Build harness.usage from a JSON object with token fields.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `usage_event_from_json` — see module docs for full workflow.
/// ```
pub fn usage_event_from_json(run_id: &str, val: &serde_json::Value) -> TraceEvent {
    let mut ev = TraceEvent::new(run_id, EventSource::Harness, "harness.usage");
    ev.status = EventStatus::Success;
    ev.side_effect = SideEffect::None;
    for key in [
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
    ] {
        if let Some(n) = val.get(key).and_then(|v| v.as_u64()) {
            ev.metadata.insert(key.to_string(), serde_json::json!(n));
        }
    }
    // Also accept input/output short keys when canonical keys missing
    if !ev.metadata.contains_key("input_tokens") {
        if let Some(n) = val.get("input").and_then(|v| v.as_u64()) {
            ev.metadata
                .insert("input_tokens".to_string(), serde_json::json!(n));
        }
    }
    if !ev.metadata.contains_key("output_tokens") {
        if let Some(n) = val.get("output").and_then(|v| v.as_u64()) {
            ev.metadata
                .insert("output_tokens".to_string(), serde_json::json!(n));
        }
    }
    if let Some(m) = val.get("model").and_then(|v| v.as_str()) {
        ev.metadata
            .insert("model".to_string(), serde_json::json!(m));
    }
    ev
}

/// Try to parse one NDJSON line into events (Codex-style).
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `parse_codex_json_line` — see module docs for full workflow.
/// ```
pub fn parse_codex_json_line(run_id: &str, line: &str) -> Vec<TraceEvent> {
    // Codex reuses much of the same stream-json shape; also accept openai-like calls
    let mut events = parse_claude_json_line(run_id, line);
    // Retag session harness name
    for ev in &mut events {
        if ev.kind == "harness.session" {
            ev.metadata
                .insert("harness".to_string(), serde_json::json!("codex"));
        }
    }
    // If parse_claude_json_line already emitted tool.call events for this
    // line, skip Codex-specific tool parsing to avoid duplicates.
    let already_has_tool_call = events.iter().any(|e| e.kind == "tool.call");

    let line = line.trim();
    if line.starts_with('{') && !already_has_tool_call {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            // Codex agent events: item.started / item.completed with tool info
            if let Some(item) = val.get("item") {
                let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if item_type.contains("command") || item_type.contains("tool") {
                    let name = item
                        .get("name")
                        .or_else(|| item.get("command"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("shell");
                    let input = item.get("input").or_else(|| item.get("args")).cloned();
                    events.push(tool_call_event(run_id, name, input, None));
                }
            }
        }
    }
    events
}

/// Free-text fallbacks (non-JSON) for tool mentions and session ids.
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `parse_plaintext` — see module docs for full workflow.
/// ```
pub fn parse_plaintext(run_id: &str, text: &str, harness: &str) -> Vec<TraceEvent> {
    let mut events = Vec::new();
    if let Some(sid) = extract_session_id(text) {
        events.push(session_event(run_id, &sid, harness));
    }
    for cap in tool_use_re().captures_iter(text) {
        if let Some(name) = cap.get(1) {
            events.push(tool_call_event(run_id, name.as_str(), None, None));
        }
    }
    // Common shell/agent banners that imply a tool invocation.
    let lower = text.to_lowercase();
    if let Some(rest) = text
        .strip_prefix("$ ")
        .or_else(|| text.strip_prefix("> "))
        .or_else(|| text.strip_prefix("➜ "))
    {
        if rest.len() > 2 && !rest.starts_with('#') {
            events.push(tool_call_event(
                run_id,
                "Bash",
                Some(serde_json::json!({ "command": rest.trim() })),
                None,
            ));
        }
    }
    if lower.contains("exit code") || lower.contains("exited with code") {
        let mut ev = TraceEvent::new(run_id, EventSource::System, "process.exit_banner");
        ev.status = if lower.contains("exit code 0") || lower.contains("code 0") {
            EventStatus::Success
        } else {
            EventStatus::Error
        };
        ev.metadata
            .insert("message".into(), serde_json::json!(text.trim()));
        events.push(ev);
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::command::{CommandFidelity, CommandMetadata};

    #[test]
    fn parse_claude_tool_use_line() {
        let line = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"tu_1","name":"Read","input":{"file_path":"src/main.rs"}}]}}"#;
        let events = parse_claude_json_line("run-1", line);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "tool.call");
        assert_eq!(events[0].source, EventSource::Tool);
        assert_eq!(
            events[0].metadata.get("tool_name").and_then(|v| v.as_str()),
            Some("Read")
        );
        assert_eq!(events[0].side_effect, SideEffect::Read);
    }

    #[test]
    fn bash_tool_emits_shell_command_meta() {
        let ev = tool_call_event(
            "run-1",
            "Bash",
            Some(serde_json::json!({
                "command": "cat result.json | jq '.items[]'"
            })),
            Some("tu_bash"),
        );
        let meta = CommandMetadata::from_event(&ev).expect("command_meta");
        assert_eq!(
            meta.shell_source.as_deref(),
            Some("cat result.json | jq '.items[]'")
        );
        assert_eq!(meta.fidelity, CommandFidelity::Inferred);
        assert_eq!(meta.argv[0], "bash");
        assert_eq!(meta.argv[1], "-lc");
        assert!(meta.argv[2].contains("jq"));
        // Must not whitespace-split the pipeline into fake argv tokens.
        assert!(!meta.argv.iter().any(|a| a == "|"));
    }

    #[test]
    fn bash_tool_with_argv_array_is_exact() {
        let ev = tool_call_event(
            "run-1",
            "Bash",
            Some(serde_json::json!({
                "command": ["grep", "hello world", "file.txt"]
            })),
            None,
        );
        let meta = CommandMetadata::from_event(&ev).expect("command_meta");
        assert_eq!(meta.fidelity, CommandFidelity::Exact);
        assert!(meta.lossless);
        assert_eq!(meta.argv[1], "hello world");
    }

    #[test]
    fn non_shell_tool_with_args_array() {
        let ev = tool_call_event(
            "run-1",
            "Execute",
            Some(serde_json::json!({
                "args": ["rg", "Session", "src/"],
                "cwd": "/project"
            })),
            None,
        );
        // Execute is treated as shell-like by tool name match
        let meta = CommandMetadata::from_event(&ev);
        // Execute matches shell names → may use shell path; if args used as argv:
        assert!(meta.is_some());
    }

    #[test]
    fn parse_blackbox_protocol_usage_and_tool_call() {
        let usage = r#"{"type":"usage","input_tokens":10,"output_tokens":5,"model":"m"}"#;
        let events = parse_claude_json_line("r", usage);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "harness.usage");
        assert_eq!(
            events[0]
                .metadata
                .get("input_tokens")
                .and_then(|v| v.as_u64()),
            Some(10)
        );

        let call = r#"{"type":"tool_call","id":"1","name":"Bash","input":{"command":"ls"}}"#;
        let events = parse_claude_json_line("r", call);
        assert_eq!(events[0].kind, "tool.call");
        assert_eq!(
            events[0].metadata.get("tool_name").and_then(|v| v.as_str()),
            Some("Bash")
        );
    }

    #[test]
    fn parse_tool_result_line() {
        let line = r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"tu_1","content":"fn main() {}"}]}}"#;
        let events = parse_claude_json_line("run-1", line);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "tool.result");
        assert!(
            events[0].metadata.contains_key("output")
                || events[0].metadata.contains_key("output_full")
        );
        assert!(events[0].output_blob.is_none()); // blob keys assigned by capture pipeline only
    }

    #[test]
    fn extract_session_from_text() {
        let sid = extract_session_id("session_id: abcdefgh-1234-5678");
        assert_eq!(sid.as_deref(), Some("abcdefgh-1234-5678"));
    }

    #[test]
    fn tool_side_effect_read_write() {
        assert_eq!(tool_side_effect("Read"), SideEffect::Read);
        assert_eq!(tool_side_effect("Write"), SideEffect::LocalWrite);
        assert_eq!(tool_side_effect("Bash"), SideEffect::Unknown);
    }
}
