//! First-class adapters for additional coding harnesses (1.1).
//!
//! Beyond wrap-list ambient capture, these parsers extract structured
//! tool/session events from known CLI output shapes instead of pure PTY soup.

use crate::adapters::harness::HarnessAdapter;
use crate::adapters::parse::{
    parse_claude_json_line, parse_plaintext, session_event, tool_call_event, tool_result_event,
};
use crate::adapters::{LaunchContext, PreparedLaunch, RunContext};
use crate::core::event::TraceEvent;

fn basename_in(command: &[String], names: &[&str]) -> bool {
    command
        .first()
        .and_then(|c| std::path::Path::new(c).file_name())
        .and_then(|n| n.to_str())
        .is_some_and(|b| {
            names
                .iter()
                .any(|n| b.eq_ignore_ascii_case(n) || b.eq_ignore_ascii_case(&format!("{n}.exe")))
        })
}

// ── Aider ───────────────────────────────────────────────────────────

/// Aider CLI — chat + `/run` / tool-like lines; NDJSON when present.
pub struct AiderAdapter;

impl AiderAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AiderAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for AiderAdapter {
    fn id(&self) -> &'static str {
        "aider"
    }

    fn detect(&self, command: &[String]) -> bool {
        basename_in(command, &["aider"])
    }

    fn prepare_launch(
        &self,
        command: &[String],
        context: &LaunchContext,
    ) -> Option<PreparedLaunch> {
        Some(PreparedLaunch {
            command: command.to_vec(),
            environment: context.environment.clone(),
            cwd: context.project_dir.clone(),
        })
    }

    fn parse_output(&self, run_id: &str, chunk: &[u8]) -> Vec<TraceEvent> {
        let text = String::from_utf8_lossy(chunk);
        let mut events = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('{') {
                let mut parsed = parse_claude_json_line(run_id, trimmed);
                for ev in &mut parsed {
                    if ev.kind == "harness.session" {
                        ev.metadata
                            .insert("harness".into(), serde_json::json!("aider"));
                    }
                }
                events.extend(parsed);
                continue;
            }
            // Aider often prints "Applied edit to path" / "Running: …"
            if let Some(rest) = trimmed.strip_prefix("Running:") {
                events.push(tool_call_event(
                    run_id,
                    "Bash",
                    Some(serde_json::json!({ "command": rest.trim() })),
                    None,
                ));
                continue;
            }
            if trimmed.starts_with("Applied edit to ") || trimmed.starts_with("Added ") {
                let path = trimmed.split_whitespace().last().unwrap_or("unknown");
                events.push(tool_call_event(
                    run_id,
                    "Write",
                    Some(serde_json::json!({ "path": path })),
                    None,
                ));
                continue;
            }
            events.extend(parse_plaintext(run_id, trimmed, "aider"));
        }
        events
    }

    fn locate_native_logs(&self, context: &RunContext) -> Vec<String> {
        crate::adapters::native_logs::discover_log_roots("aider", &context.project_dir)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect()
    }
}

// ── Gemini ──────────────────────────────────────────────────────────

/// Google Gemini CLI.
pub struct GeminiAdapter;

impl GeminiAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GeminiAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for GeminiAdapter {
    fn id(&self) -> &'static str {
        "gemini"
    }

    fn detect(&self, command: &[String]) -> bool {
        basename_in(command, &["gemini"])
    }

    fn prepare_launch(
        &self,
        command: &[String],
        context: &LaunchContext,
    ) -> Option<PreparedLaunch> {
        // Prefer machine output when force-json or non-interactive -y/-p style.
        let force = std::env::var("BLACKBOX_FORCE_JSON")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let mut cmd = command.to_vec();
        if force
            && !crate::adapters::launch::has_any_flag(&cmd, &["--output-format", "-o"])
            && !crate::adapters::launch::has_option(&cmd, "--output-format")
        {
            cmd = crate::adapters::launch::ensure_flags(&cmd, &["--output-format", "json"]);
        }
        Some(PreparedLaunch {
            command: cmd,
            environment: context.environment.clone(),
            cwd: context.project_dir.clone(),
        })
    }

    fn parse_output(&self, run_id: &str, chunk: &[u8]) -> Vec<TraceEvent> {
        let text = String::from_utf8_lossy(chunk);
        let mut events = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('{') {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    // Gemini CLI sometimes emits functionCall / tool_call shapes
                    if let Some(fc) = val
                        .get("functionCall")
                        .or_else(|| val.get("function_call"))
                        .or_else(|| val.pointer("/candidates/0/content/parts/0/functionCall"))
                    {
                        let name = fc.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                        let args = fc.get("args").or_else(|| fc.get("arguments")).cloned();
                        events.push(tool_call_event(run_id, name, args, None));
                        continue;
                    }
                }
            }
            events.extend(parse_ndjson_or_plaintext(run_id, line.as_bytes(), "gemini"));
        }
        if events.is_empty() {
            events.extend(parse_ndjson_or_plaintext(run_id, chunk, "gemini"));
        }
        events
    }

    fn locate_native_logs(&self, context: &RunContext) -> Vec<String> {
        crate::adapters::native_logs::discover_log_roots("gemini", &context.project_dir)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect()
    }
}

// ── Cursor ──────────────────────────────────────────────────────────

/// Cursor / cursor-agent CLI.
pub struct CursorAdapter;

impl CursorAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CursorAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for CursorAdapter {
    fn id(&self) -> &'static str {
        "cursor"
    }

    fn detect(&self, command: &[String]) -> bool {
        basename_in(command, &["cursor", "cursor-agent", "cursor-agent-cli"])
    }

    fn prepare_launch(
        &self,
        command: &[String],
        context: &LaunchContext,
    ) -> Option<PreparedLaunch> {
        Some(PreparedLaunch {
            command: command.to_vec(),
            environment: context.environment.clone(),
            cwd: context.project_dir.clone(),
        })
    }

    fn parse_output(&self, run_id: &str, chunk: &[u8]) -> Vec<TraceEvent> {
        let text = String::from_utf8_lossy(chunk);
        let mut events = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('{') {
                // Cursor agent streams may use functionCall / tool_calls shapes
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    if let Some(fc) = val.get("functionCall").or_else(|| val.get("function_call")) {
                        let name = fc.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                        let args = fc.get("args").or_else(|| fc.get("arguments")).cloned();
                        events.push(tool_call_event(run_id, name, args, None));
                        continue;
                    }
                    if val.get("type").and_then(|t| t.as_str()) == Some("tool_result")
                        || val.get("toolResult").is_some()
                    {
                        let id = val
                            .get("tool_use_id")
                            .or_else(|| val.get("id"))
                            .and_then(|i| i.as_str());
                        let out = val
                            .get("result")
                            .or_else(|| val.get("content"))
                            .or_else(|| val.get("toolResult"))
                            .cloned();
                        let is_err = val
                            .get("is_error")
                            .and_then(|e| e.as_bool())
                            .unwrap_or(false);
                        events.push(tool_result_event(run_id, id, out, is_err));
                        continue;
                    }
                }
                let mut parsed = parse_claude_json_line(run_id, trimmed);
                for ev in &mut parsed {
                    if ev.kind == "harness.session" {
                        ev.metadata
                            .insert("harness".into(), serde_json::json!("cursor"));
                    }
                }
                events.extend(parsed);
                continue;
            }
            events.extend(parse_plaintext(run_id, trimmed, "cursor"));
        }
        events
    }

    fn locate_native_logs(&self, context: &RunContext) -> Vec<String> {
        crate::adapters::native_logs::discover_log_roots("cursor", &context.project_dir)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect()
    }
}

// ── OpenCode ────────────────────────────────────────────────────────

pub struct OpenCodeAdapter;

impl OpenCodeAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpenCodeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for OpenCodeAdapter {
    fn id(&self) -> &'static str {
        "opencode"
    }

    fn detect(&self, command: &[String]) -> bool {
        basename_in(command, &["opencode"])
    }

    fn prepare_launch(
        &self,
        command: &[String],
        context: &LaunchContext,
    ) -> Option<PreparedLaunch> {
        Some(PreparedLaunch {
            command: command.to_vec(),
            environment: context.environment.clone(),
            cwd: context.project_dir.clone(),
        })
    }

    fn parse_output(&self, run_id: &str, chunk: &[u8]) -> Vec<TraceEvent> {
        parse_ndjson_or_plaintext(run_id, chunk, "opencode")
    }

    fn locate_native_logs(&self, context: &RunContext) -> Vec<String> {
        crate::adapters::native_logs::discover_log_roots("opencode", &context.project_dir)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect()
    }
}

// ── Grok ────────────────────────────────────────────────────────────

pub struct GrokAdapter;

impl GrokAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GrokAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for GrokAdapter {
    fn id(&self) -> &'static str {
        "grok"
    }

    fn detect(&self, command: &[String]) -> bool {
        basename_in(command, &["grok"])
    }

    fn prepare_launch(
        &self,
        command: &[String],
        context: &LaunchContext,
    ) -> Option<PreparedLaunch> {
        Some(PreparedLaunch {
            command: command.to_vec(),
            environment: context.environment.clone(),
            cwd: context.project_dir.clone(),
        })
    }

    fn parse_output(&self, run_id: &str, chunk: &[u8]) -> Vec<TraceEvent> {
        parse_ndjson_or_plaintext(run_id, chunk, "grok")
    }

    fn locate_native_logs(&self, context: &RunContext) -> Vec<String> {
        crate::adapters::native_logs::discover_log_roots("grok", &context.project_dir)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect()
    }
}

fn parse_ndjson_or_plaintext(run_id: &str, chunk: &[u8], harness: &str) -> Vec<TraceEvent> {
    let text = String::from_utf8_lossy(chunk);
    let mut events = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('{') {
            let mut parsed = parse_claude_json_line(run_id, trimmed);
            for ev in &mut parsed {
                if ev.kind == "harness.session" {
                    ev.metadata
                        .insert("harness".into(), serde_json::json!(harness));
                }
            }
            // Accept top-level session without type
            if parsed.is_empty() {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    if let Some(sid) = val.get("sessionId").or_else(|| val.get("session_id")) {
                        if let Some(s) = sid.as_str() {
                            events.push(session_event(run_id, s, harness));
                        }
                    }
                }
            }
            events.extend(parsed);
        } else {
            events.extend(parse_plaintext(run_id, trimmed, harness));
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::harness::HarnessAdapter;

    #[test]
    fn aider_parses_running_line() {
        let a = AiderAdapter::new();
        let evs = a.parse_output("r1", b"Running: pytest -q\n");
        assert!(evs.iter().any(|e| e.kind == "tool.call"));
        assert_eq!(
            evs[0].metadata.get("tool_name").and_then(|v| v.as_str()),
            Some("Bash")
        );
    }

    #[test]
    fn cursor_parses_function_call() {
        let a = CursorAdapter::new();
        let line = r#"{"functionCall":{"name":"Read","args":{"path":"src/main.rs"}}}"#;
        let evs = a.parse_output("r1", line.as_bytes());
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "tool.call");
        assert_eq!(
            evs[0].metadata.get("tool_name").and_then(|v| v.as_str()),
            Some("Read")
        );
    }

    #[test]
    fn gemini_detect() {
        assert!(GeminiAdapter::new().detect(&["gemini".into(), "chat".into()]));
        assert!(!GeminiAdapter::new().detect(&["claude".into()]));
    }
}
