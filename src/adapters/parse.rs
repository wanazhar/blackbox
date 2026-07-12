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
        Regex::new(r#"(?i)(?:tool[_-]?use|using tool|tool call)[:\s]+[`'"]?([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("tool_use regex")
    })
}

/// Classify a tool name into a side-effect level.
pub fn tool_side_effect(name: &str) -> SideEffect {
    let lower = name.to_lowercase();
    match lower.as_str() {
        "read" | "read_file" | "grep" | "glob" | "search" | "list" | "ls" | "find"
        | "web_search" | "webfetch" | "get" | "cat" | "view" | "stat" => SideEffect::Read,
        "write" | "write_file" | "edit" | "str_replace" | "strreplace" | "create"
        | "mkdir" | "apply_patch" | "notebook_edit" => SideEffect::LocalWrite,
        "bash" | "shell" | "run" | "execute" | "terminal" | "cmd" => SideEffect::Unknown,
        "delete" | "remove" | "rm" => SideEffect::Destructive,
        "browser" | "http" | "curl" | "fetch" | "post" => SideEffect::ExternalWrite,
        _ => SideEffect::Unknown,
    }
}

/// Extract a session id from free-form text, if present.
pub fn extract_session_id(text: &str) -> Option<String> {
    session_re()
        .captures(text)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
}

/// Build a tool.call event.
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
    if let Some(input) = input {
        ev.metadata.insert("input".to_string(), input);
    }
    if let Some(id) = tool_use_id {
        ev.metadata
            .insert("tool_use_id".to_string(), serde_json::json!(id));
    }
    ev
}

/// Build a tool.result event.
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
            if let Some(content) = val
                .pointer("/message/content")
                .and_then(|c| c.as_array())
            {
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
            if let Some(content) = val
                .pointer("/message/content")
                .and_then(|c| c.as_array())
            {
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
            let input = val
                .get("input")
                .or_else(|| val.get("arguments"))
                .cloned();
            events.push(tool_call_event(run_id, name, input, id));
        }
        "tool_result" | "function_call_output" => {
            let id = val
                .get("tool_use_id")
                .or_else(|| val.get("call_id"))
                .and_then(|i| i.as_str());
            let is_error = val
                .get("is_error")
                .and_then(|e| e.as_bool())
                .unwrap_or(false);
            let output = val
                .get("content")
                .or_else(|| val.get("output"))
                .cloned();
            events.push(tool_result_event(run_id, id, output, is_error));
        }
        "result" => {
            let mut ev = TraceEvent::new(run_id, EventSource::Harness, "harness.result");
            ev.status = EventStatus::Success;
            if let Some(r) = val.get("result") {
                ev.metadata.insert("result".to_string(), r.clone());
            }
            events.push(ev);
        }
        _ => {}
    }

    events
}

/// Try to parse one NDJSON line into events (Codex-style).
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

    let line = line.trim();
    if line.starts_with('{') {
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
    events
}

#[cfg(test)]
mod tests {
    use super::*;

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
