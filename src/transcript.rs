//! Rebuild human-readable terminal transcripts from stored events/blobs.

use crate::core::blob::BlobReference;
use crate::core::event::TraceEvent;
use crate::storage::TraceStore;

/// Reconstruct plain-text terminal output for a run from `terminal.output` events.
pub async fn rebuild_terminal_transcript(
    store: &dyn TraceStore,
    events: &[TraceEvent],
) -> anyhow::Result<String> {
    let mut out = String::new();
    let mut term_events: Vec<&TraceEvent> = events
        .iter()
        .filter(|e| e.kind == "terminal.output")
        .collect();
    term_events.sort_by_key(|e| e.sequence);

    for ev in term_events {
        if let Some(key) = ev.output_blob.as_deref() {
            if let Some(bref) = BlobReference::try_new(key.to_string(), 0) {
                match store.load_blob(&bref).await {
                    Ok(data) => {
                        out.push_str(&String::from_utf8_lossy(&data));
                    }
                    Err(_) => {
                        // Fall back to preview
                        if let Some(p) = ev.metadata.get("preview").and_then(|v| v.as_str()) {
                            out.push_str(p);
                            if !p.ends_with('\n') {
                                out.push('\n');
                            }
                        }
                    }
                }
            } else {
                // Invalid blob key — fall back to preview
                if let Some(p) = ev.metadata.get("preview").and_then(|v| v.as_str()) {
                    out.push_str(p);
                    if !p.ends_with('\n') {
                        out.push('\n');
                    }
                }
            }
        } else if let Some(p) = ev.metadata.get("preview").and_then(|v| v.as_str()) {
            out.push_str(p);
            if !p.ends_with('\n') {
                out.push('\n');
            }
        } else if let Some(p) = ev.metadata.get("normalized").and_then(|v| v.as_str()) {
            // Legacy events
            out.push_str(p);
        }
    }
    Ok(out)
}

/// Compact tool-call transcript (name + input preview).
pub fn rebuild_tool_transcript(events: &[TraceEvent]) -> String {
    let mut lines = Vec::new();
    for ev in events {
        if ev.kind != "tool.call" {
            continue;
        }
        let name = ev
            .metadata
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let input = ev
            .metadata
            .get("input")
            .map(|v| {
                let s = v.to_string();
                if s.len() > 120 {
                    let end = s.floor_char_boundary(120);
                    format!("{}…", &s[..end])
                } else {
                    s
                }
            })
            .unwrap_or_default();
        lines.push(format!("[{}] {} {}", ev.sequence, name, input));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};
    use crate::storage::sqlite::SqliteStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn rebuilds_from_blobs() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = crate::core::run::Run::new(vec!["echo".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();

        let blob = store.store_blob(b"line one\nline two\n").await.unwrap();
        let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        ev.status = EventStatus::Success;
        ev.sequence = 1;
        ev.output_blob = Some(blob.key);
        store.insert_event(&ev).await.unwrap();

        let events = store.get_events(&run.id).await.unwrap();
        let text = rebuild_terminal_transcript(store.as_ref(), &events)
            .await
            .unwrap();
        assert!(text.contains("line one"));
        assert!(text.contains("line two"));
    }
}
