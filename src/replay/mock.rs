use std::collections::HashMap;

use crate::core::event::{EventSource, TraceEvent};
use crate::core::run::Run;
use crate::replay::{events_from, ReplayEngine, ReplayOutcome};

/// Mock replay — known tool calls return their recorded outputs.
///
/// Builds an index of `tool.call` / `tool.result` pairs from the
/// recorded trace and re-emits them as a mock transcript without
/// touching the filesystem.
pub struct MockReplay;

impl MockReplay {
    /// Index tool results by tool_use_id for pairing with calls.
    fn result_index(events: &[TraceEvent]) -> HashMap<String, &TraceEvent> {
        let mut map = HashMap::new();
        for ev in events {
            if ev.kind == "tool.result" {
                if let Some(id) = ev
                    .metadata
                    .get("tool_use_id")
                    .and_then(|v| v.as_str())
                {
                    map.insert(id.to_string(), ev);
                }
            }
        }
        map
    }

    fn output_preview(event: &TraceEvent) -> String {
        if let Some(blob) = event.output_blob.as_deref() {
            return truncate(blob, 200);
        }
        if let Some(out) = event.metadata.get("output") {
            return truncate(&out.to_string(), 200);
        }
        "(no output recorded)".to_string()
    }

    fn input_preview(event: &TraceEvent) -> String {
        event
            .metadata
            .get("input")
            .map(|v| truncate(&v.to_string(), 120))
            .or_else(|| {
                event
                    .metadata
                    .get("args")
                    .map(|v| truncate(&v.to_string(), 120))
            })
            .unwrap_or_else(|| "(no input)".to_string())
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
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

        let tool_calls: Vec<&TraceEvent> = slice
            .iter()
            .filter(|e| e.source == EventSource::Tool && e.kind == "tool.call")
            .collect();

        // Also include tool events that only have source Tool without kind filter
        // as fallback for older traces
        let tool_calls = if tool_calls.is_empty() {
            slice
                .iter()
                .filter(|e| e.source == EventSource::Tool)
                .collect()
        } else {
            tool_calls
        };

        println!("═══ Mock tool replay ═══");
        println!(
            "Run {}  {} tool call(s)",
            &run.id[..8.min(run.id.len())],
            tool_calls.len()
        );
        println!("{}", "─".repeat(72));

        let mut mocked = 0usize;
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

            let result_ev = tool_use_id.and_then(|id| results.get(id).copied());
            let output = result_ev
                .map(Self::output_preview)
                .unwrap_or_else(|| {
                    // Fall back to output on the call event itself
                    if event.output_blob.is_some() || event.metadata.contains_key("output") {
                        Self::output_preview(event)
                    } else {
                        "(no recorded result)".to_string()
                    }
                });

            println!(
                "[{}] {}  id={}",
                i + 1,
                tool_name,
                tool_use_id.unwrap_or("-")
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
            format!("returned recorded outputs for {} tool call(s); filesystem unchanged", mocked)
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
        ev.output_blob = Some(body.to_string());
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
}
