//! Claude Code hooks → Blackbox native ingest reference integration (1.9).
//!
//! Maps Claude Code hook event payloads to [`crate::native`] envelopes so a
//! session can be recorded without PTY process wrapping.
//!
//! # Coverage
//!
//! See [`ClaudeHooksCoverage`] and `docs/guide/native-integrations.md`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::conformance::ConformanceLevel;
use crate::native::{IngestOp, NativeIngestEnvelope};
use crate::security::{ActionFingerprint, DecisionKind, SecurityDecision};

/// Declared conformance level for this reference integration.
pub const CLAUDE_HOOKS_CONFORMANCE_LEVEL: ConformanceLevel = ConformanceLevel::Recorder;

/// Coverage declaration for the Claude Code hooks adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeHooksCoverage {
    /// Integration id.
    pub id: String,
    /// Human name.
    pub name: String,
    /// Conformance level claimed.
    pub conformance_level: String,
    /// Hook events supported.
    pub supported_hooks: Vec<String>,
    /// Known failure modes.
    pub failure_modes: Vec<String>,
    /// Performance notes.
    pub performance: Vec<String>,
    /// Unsupported capabilities (honest).
    pub unsupported: Vec<String>,
}

impl Default for ClaudeHooksCoverage {
    fn default() -> Self {
        Self {
            id: "claude-code-hooks".into(),
            name: "Claude Code hooks reference adapter".into(),
            conformance_level: CLAUDE_HOOKS_CONFORMANCE_LEVEL.as_str().into(),
            supported_hooks: vec![
                "SessionStart".into(),
                "SessionEnd".into(),
                "PreToolUse".into(),
                "PostToolUse".into(),
                "PermissionRequest".into(),
                "Stop".into(),
            ],
            failure_modes: vec![
                "hook_timeout_drops_event".into(),
                "malformed_hook_json_rejected".into(),
                "missing_session_id_uses_generated_run".into(),
            ],
            performance: vec![
                "qualification_500_events_p99_lt_100ms_debug_in_memory".into(),
                "ndjson_line_limit_1MiB".into(),
            ],
            unsupported: vec![
                "full_pty_terminal_bytes".into(),
                "kernel_process_tree".into(),
                "forensic_pack_generation_in_hook_path".into(),
            ],
        }
    }
}

/// Stateless mapper from Claude hook JSON to native ingest envelopes.
#[derive(Debug, Default)]
pub struct ClaudeHooksAdapter {
    /// Fixed producer tag.
    pub producer: String,
}

impl ClaudeHooksAdapter {
    /// Create adapter.
    pub fn new() -> Self {
        Self {
            producer: "claude-code-hooks".into(),
        }
    }

    /// Coverage declaration.
    pub fn coverage(&self) -> ClaudeHooksCoverage {
        ClaudeHooksCoverage::default()
    }

    /// Map a Claude Code hook payload to zero or more ingest envelopes.
    ///
    /// Expected loose shape (Claude hooks vary by version):
    /// ```json
    /// {
    ///   "hook_event_name": "PreToolUse",
    ///   "session_id": "...",
    ///   "tool_name": "Bash",
    ///   "tool_input": {},
    ///   "permission_mode": "default"
    /// }
    /// ```
    pub fn map_hook(
        &self,
        run_id: &str,
        hook: &Value,
        seq: u64,
    ) -> Result<Vec<NativeIngestEnvelope>, String> {
        let event_name = hook
            .get("hook_event_name")
            .or_else(|| hook.get("event"))
            .or_else(|| hook.get("type"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing hook_event_name".to_string())?;

        let session = hook
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or(run_id);

        let mut out = Vec::new();
        match event_name {
            "SessionStart" | "session_start" => {
                out.push(
                    NativeIngestEnvelope::new(
                        IngestOp::StartRun,
                        format!("claude-session-{session}"),
                    )
                    .with_payload(json!({
                        "run_id": run_id,
                        "session_id": session,
                        "adapter": "claude",
                        "command": ["claude"],
                        "cwd": hook.get("cwd").and_then(|v| v.as_str()).unwrap_or("."),
                        "name": format!("claude-session-{session}"),
                    }))
                    .with_producer(&self.producer),
                );
            }
            "SessionEnd" | "Stop" | "session_end" | "stop" => {
                let code = hook.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                out.push(
                    NativeIngestEnvelope::new(
                        IngestOp::FinishRun,
                        format!("claude-end-{session}-{seq}"),
                    )
                    .with_run_id(run_id)
                    .with_payload(json!({"exit_code": code}))
                    .with_producer(&self.producer),
                );
            }
            "PreToolUse" | "pre_tool_use" => {
                let tool = hook
                    .get("tool_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let input = hook.get("tool_input").cloned().unwrap_or(json!({}));
                out.push(
                    NativeIngestEnvelope::new(
                        IngestOp::RecordTool,
                        format!("claude-pretool-{session}-{seq}"),
                    )
                    .with_run_id(run_id)
                    .with_payload(json!({
                        "tool_name": tool,
                        "input": input,
                        "status": "running",
                        "kind": "tool.call"
                    }))
                    .with_producer(&self.producer),
                );
                // Permission / security decision when present.
                if let Some(perm) = hook
                    .get("permission_decision")
                    .or_else(|| hook.get("permission"))
                {
                    let decision = map_permission(perm);
                    let fp = ActionFingerprint::tool(tool, Some(input));
                    let sec = SecurityDecision::builder("harness", decision, fp.hash())
                        .action(fp)
                        .run_id(run_id)
                        .build();
                    out.push(
                        NativeIngestEnvelope::new(
                            IngestOp::RecordSecurityDecision,
                            format!("claude-perm-{session}-{seq}"),
                        )
                        .with_run_id(run_id)
                        .with_payload(serde_json::to_value(&sec).unwrap_or(json!({})))
                        .with_producer(&self.producer),
                    );
                }
            }
            "PostToolUse" | "post_tool_use" => {
                let tool = hook
                    .get("tool_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let output = hook
                    .get("tool_response")
                    .or_else(|| hook.get("tool_output"));
                out.push(
                    NativeIngestEnvelope::new(
                        IngestOp::RecordTool,
                        format!("claude-posttool-{session}-{seq}"),
                    )
                    .with_run_id(run_id)
                    .with_payload(json!({
                        "tool_name": tool,
                        "output": output,
                        "status": "success",
                        "kind": "tool.result"
                    }))
                    .with_producer(&self.producer),
                );
            }
            "PermissionRequest" | "permission_request" => {
                out.push(
                    NativeIngestEnvelope::new(
                        IngestOp::RecordApproval,
                        format!("claude-permreq-{session}-{seq}"),
                    )
                    .with_run_id(run_id)
                    .with_payload(json!({
                        "approved": hook.get("approved").and_then(|v| v.as_bool()).unwrap_or(false),
                        "actor": "user"
                    }))
                    .with_producer(&self.producer),
                );
            }
            other => {
                out.push(
                    NativeIngestEnvelope::new(
                        IngestOp::RecordEvent,
                        format!("claude-hook-{session}-{seq}"),
                    )
                    .with_run_id(run_id)
                    .with_payload(json!({
                        "kind": format!("hook.{other}"),
                        "source": "harness",
                        "status": "success",
                        "metadata": {"raw_hook": hook}
                    }))
                    .with_producer(&self.producer),
                );
            }
        }
        Ok(out)
    }
}

fn map_permission(v: &Value) -> DecisionKind {
    match v.as_str().unwrap_or("").to_ascii_lowercase().as_str() {
        "allow" | "approved" | "yes" => DecisionKind::Allow,
        "deny" | "blocked" | "no" => DecisionKind::Deny,
        "warn" => DecisionKind::Warn,
        "ask" | "require_approval" => DecisionKind::RequireApproval,
        _ => {
            if v.get("allow").and_then(|x| x.as_bool()) == Some(true) {
                DecisionKind::Allow
            } else if v.get("deny").and_then(|x| x.as_bool()) == Some(true) {
                DecisionKind::Deny
            } else {
                DecisionKind::Unknown
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::NativeRecorder;
    use crate::storage::store::InMemoryStore;
    use crate::storage::TraceStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn session_lifecycle_via_hooks() {
        let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
        let rec = NativeRecorder::new(store.clone());
        let adapter = ClaudeHooksAdapter::new();
        let run_id = "run-claude-1";

        let start = json!({
            "hook_event_name": "SessionStart",
            "session_id": "sess-1",
            "cwd": "/tmp/proj"
        });
        for env in adapter.map_hook(run_id, &start, 0).unwrap() {
            rec.apply_envelope(env).await.unwrap();
        }
        // start_run may have used payload run_id
        let runs = store.list_runs().await.unwrap();
        assert_eq!(runs.len(), 1);
        let rid = runs[0].id.clone();

        let pre = json!({
            "hook_event_name": "PreToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "permission_decision": "allow"
        });
        for env in adapter.map_hook(&rid, &pre, 1).unwrap() {
            rec.apply_envelope(env).await.unwrap();
        }

        let post = json!({
            "hook_event_name": "PostToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_response": {"ok": true}
        });
        for env in adapter.map_hook(&rid, &post, 2).unwrap() {
            rec.apply_envelope(env).await.unwrap();
        }

        let end = json!({
            "hook_event_name": "SessionEnd",
            "session_id": "sess-1",
            "exit_code": 0
        });
        for env in adapter.map_hook(&rid, &end, 3).unwrap() {
            rec.apply_envelope(env).await.unwrap();
        }

        let events = store.get_events(&rid).await.unwrap();
        assert!(events.iter().any(|e| e.kind == "tool.call"));
        assert!(events.iter().any(|e| e.kind == "security.decision"));
        assert!(events.iter().any(|e| e.kind == "run.ended"));

        let cov = adapter.coverage();
        assert_eq!(cov.conformance_level, "recorder");
        assert!(!cov.unsupported.is_empty());
    }
}
