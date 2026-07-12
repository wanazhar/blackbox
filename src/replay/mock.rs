use std::collections::{HashMap, HashSet};

use crate::core::event::{EventSource, TraceEvent};
use crate::core::run::Run;
use crate::replay::{events_from, ReplayEngine, ReplayOutcome};

/// Mock replay — known tool calls return their recorded outputs.
///
/// Builds an index of `tool.call` / `tool.result` pairs from the
/// recorded trace and re-emits them as a mock transcript without
/// touching the filesystem.
///
/// Handles native-log-only traces (no PTY tool stream) and prefers
/// `output_full` / `output` metadata over blob keys.
pub struct MockReplay;

impl MockReplay {
    /// Index tool results by tool_use_id for pairing with calls.
    fn result_index(events: &[TraceEvent]) -> HashMap<String, &TraceEvent> {
        let mut map: HashMap<String, &TraceEvent> = HashMap::new();
        for ev in events {
            if ev.kind == "tool.result" {
                if let Some(id) = ev
                    .metadata
                    .get("tool_use_id")
                    .and_then(|v| v.as_str())
                {
                    // Prefer richer results if duplicates exist
                    let replace = match map.get(id) {
                        None => true,
                        Some(prev) => result_richness(ev) > result_richness(prev),
                    };
                    if replace {
                        map.insert(id.to_string(), ev);
                    }
                }
            }
        }
        map
    }

    /// Dedupe tool.call events (PTY + native log may both have fired).
    fn unique_tool_calls(events: &[TraceEvent]) -> Vec<&TraceEvent> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for ev in events {
            if ev.kind != "tool.call" && !(ev.source == EventSource::Tool && ev.kind != "tool.result")
            {
                continue;
            }
            if ev.kind == "tool.result" {
                continue;
            }
            let key = ev
                .metadata
                .get("tool_use_id")
                .and_then(|v| v.as_str())
                .map(|s| format!("id:{s}"))
                .unwrap_or_else(|| {
                    format!(
                        "nm:{}:{}",
                        ev.metadata
                            .get("tool_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?"),
                        ev.sequence
                    )
                });
            if seen.insert(key) {
                out.push(ev);
            }
        }
        out
    }

    fn output_preview(event: &TraceEvent) -> String {
        if let Some(full) = event.metadata.get("output_full").and_then(|v| v.as_str()) {
            return truncate(full, 400);
        }
        if let Some(out) = event.metadata.get("output") {
            return match out {
                serde_json::Value::String(s) => truncate(s, 400),
                other => truncate(&other.to_string(), 400),
            };
        }
        if let Some(preview) = event.metadata.get("preview").and_then(|v| v.as_str()) {
            return truncate(preview, 400);
        }
        // output_blob is a content-addressed key, not inline text
        if let Some(key) = event.output_blob.as_deref() {
            let short = &key[..12.min(key.len())];
            return format!("(output blob {short})");
        }
        "(no output recorded)".to_string()
    }

    fn input_preview(event: &TraceEvent) -> String {
        event
            .metadata
            .get("input")
            .map(|v| truncate(&v.to_string(), 200))
            .or_else(|| {
                event
                    .metadata
                    .get("args")
                    .map(|v| truncate(&v.to_string(), 200))
            })
            .or_else(|| {
                event
                    .metadata
                    .get("command")
                    .map(|v| truncate(&v.to_string(), 200))
            })
            .unwrap_or_else(|| "(no input)".to_string())
    }
}

fn result_richness(ev: &TraceEvent) -> u8 {
    let mut score = 0u8;
    if ev.metadata.contains_key("output_full") {
        score += 3;
    }
    if ev.metadata.contains_key("output") {
        score += 2;
    }
    if ev.output_blob.is_some() {
        score += 1;
    }
    score
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..s.floor_char_boundary(max)])
    }
}

#[async_trait::async_trait]
impl ReplayEngine for MockReplay {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn start(
        &mut self,
        run: &Run,
        events: &[TraceEvent],
        from_event_id: Option<&str>,
    ) -> anyhow::Result<ReplayOutcome> {
        let slice = events_from(events, from_event_id);
        let results = Self::result_index(slice);
        let tool_calls = Self::unique_tool_calls(slice);

        // Ordered results without id — consume in order for unpaired calls
        let orphan_results: Vec<&TraceEvent> = slice
            .iter()
            .filter(|e| e.kind == "tool.result")
            .filter(|e| {
                e.metadata
                    .get("tool_use_id")
                    .and_then(|v| v.as_str())
                    .map(|id| !results.contains_key(id))
                    .unwrap_or(true)
            })
            .collect();
        let mut orphan_idx = 0usize;

        println!("═══ Mock tool replay ═══");
        println!(
            "Run {}  {} unique tool call(s)  {} result(s) indexed",
            &run.id[..8.min(run.id.len())],
            tool_calls.len(),
            results.len()
        );
        println!("{}", "─".repeat(72));

        let mut mocked = 0usize;
        let mut with_output = 0usize;
        for (i, event) in tool_calls.iter().enumerate() {
            let tool_name = event
                .metadata
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let tool_use_id = event
                .metadata
                .get("tool_use_id")
                .and_then(|v| v.as_str());
            let input = Self::input_preview(event);
            let from_native = event.metadata.contains_key("native_log");

            let result_ev = tool_use_id
                .and_then(|id| results.get(id).copied())
                .or_else(|| {
                    // Order-based pairing for results without ids
                    if orphan_idx < orphan_results.len() {
                        let r = orphan_results[orphan_idx];
                        orphan_idx += 1;
                        Some(r)
                    } else {
                        None
                    }
                });

            let output = result_ev
                .map(Self::output_preview)
                .unwrap_or_else(|| {
                    if event.metadata.contains_key("output")
                        || event.metadata.contains_key("output_full")
                    {
                        Self::output_preview(event)
                    } else {
                        "(no recorded result)".to_string()
                    }
                });
            if !output.starts_with("(no recorded") {
                with_output += 1;
            }

            println!(
                "[{}] {}  id={}{}",
                i + 1,
                tool_name,
                tool_use_id.unwrap_or("-"),
                if from_native { "  [native-log]" } else { "" }
            );
            println!("    input : {}", input);
            println!("    output: {}", output);
            println!(
                "    side  : {:?}  status: {:?}",
                event.side_effect,
                result_ev.map(|e| &e.status).unwrap_or(&event.status)
            );

            tracing::info!(
                seq = event.sequence,
                tool = tool_name,
                input = %input,
                output = %output,
                "mock: tool call replayed"
            );
            mocked += 1;
        }

        let summary = if mocked == 0 {
            "no tool events in trace — nothing to mock".to_string()
        } else {
            format!(
                "returned recorded outputs for {}/{} tool call(s); filesystem unchanged",
                with_output, mocked
            )
        };
        println!("─── {} ───", summary);

        Ok(ReplayOutcome::Mocked {
            tool_count: mocked,
            summary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus, SideEffect};

    fn tool_call(id: &str, name: &str, input: &str) -> TraceEvent {
        let mut ev = TraceEvent::new("run-1", EventSource::Tool, "tool.call");
        ev.status = EventStatus::Running;
        ev.side_effect = SideEffect::Read;
        ev.metadata
            .insert("tool_name".into(), serde_json::json!(name));
        ev.metadata
            .insert("tool_use_id".into(), serde_json::json!(id));
        ev.metadata
            .insert("input".into(), serde_json::json!({ "path": input }));
        ev
    }

    fn tool_result(id: &str, body: &str) -> TraceEvent {
        let mut ev = TraceEvent::new("run-1", EventSource::Tool, "tool.result");
        ev.status = EventStatus::Success;
        ev.metadata
            .insert("tool_use_id".into(), serde_json::json!(id));
        ev.metadata
            .insert("output".into(), serde_json::json!(body));
        ev.metadata
            .insert("output_full".into(), serde_json::json!(body));
        ev
    }

    #[tokio::test]
    async fn mock_pairs_call_and_result() {
        let run = Run::new(vec!["claude".into()], "/tmp".into());
        let events = vec![
            tool_call("t1", "Read", "src/main.rs"),
            tool_result("t1", "fn main() {}"),
        ];
        let mut engine = MockReplay;
        let outcome = engine.start(&run, &events, None).await.unwrap();
        match outcome {
            ReplayOutcome::Mocked { tool_count, .. } => assert_eq!(tool_count, 1),
            other => panic!("unexpected {:?}", other),
        }
    }

    #[tokio::test]
    async fn mock_dedupes_duplicate_calls() {
        let run = Run::new(vec!["claude".into()], "/tmp".into());
        let a = tool_call("t1", "Bash", "ls");
        let mut b = tool_call("t1", "Bash", "ls");
        b.id = uuid::Uuid::new_v4().to_string();
        b.metadata
            .insert("native_log".into(), serde_json::json!("x"));
        let events = vec![a, b, tool_result("t1", "ok")];
        let mut engine = MockReplay;
        let outcome = engine.start(&run, &events, None).await.unwrap();
        match outcome {
            ReplayOutcome::Mocked { tool_count, .. } => assert_eq!(tool_count, 1),
            other => panic!("unexpected {:?}", other),
        }
    }
}
