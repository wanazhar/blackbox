use crate::core::event::TraceEvent;
use crate::core::run::Run;

/// Export a run and its events as JSON Lines.
///
/// Each line is a self-contained JSON object. The first line is the run
/// metadata, followed by one line per event. This format is streamable
/// and can be processed line-by-line without loading the full file.
pub fn export_jsonl(run: &Run, events: &[TraceEvent], redact: bool) -> anyhow::Result<String> {
    let mut lines = Vec::new();

    // Run metadata line
    let mut run_json = serde_json::to_value(run)?;
    if redact {
        redact_run(&mut run_json);
    }
    lines.push(serde_json::to_string(&run_json)?);

    // Event lines
    for event in events {
        let mut event_json = serde_json::to_value(event)?;
        if redact {
            redact_event(&mut event_json);
        }
        lines.push(serde_json::to_string(&event_json)?);
    }

    Ok(lines.join("\n") + "\n")
}

fn redact_run(val: &mut serde_json::Value) {
    if let Some(obj) = val.as_object_mut() {
        // Redact cwd to show only the basename
        if let Some(cwd) = obj.get("cwd").and_then(|v| v.as_str()) {
            let basename = std::path::Path::new(cwd)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "(redacted)".to_string());
            obj.insert("cwd".to_string(), serde_json::json!(basename));
        }
    }
}

fn redact_event(val: &mut serde_json::Value) {
    if let Some(obj) = val.as_object_mut() {
        // Remove raw terminal output which may contain secrets
        if let Some(meta) = obj.get_mut("metadata").and_then(|v| v.as_object_mut()) {
            meta.remove("raw");
            if meta.contains_key("diff_preview") {
                meta.insert("diff_preview".to_string(), serde_json::json!("[REDACTED]"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};
    use chrono::Utc;

    #[test]
    fn jsonl_export_basic() {
        let run = Run {
            id: "test-123".to_string(),
            name: Some("test run".to_string()),
            command: vec!["echo".to_string(), "hello".to_string()],
            cwd: "/tmp/test".to_string(),
            project_dir: "/tmp/test".to_string(),
            tags: vec!["ci".to_string()],
            notes: None,
            status: crate::core::run::RunStatus::Succeeded,
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            exit_code: Some(0),
            parent_run_id: None,
            next_sequence: 1,
        };

        let mut event = TraceEvent::new("test-123", EventSource::Terminal, "terminal.output");
        event.status = EventStatus::Success;

        let output = export_jsonl(&run, &[event], false).unwrap();
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 2, "should have run + 1 event line");

        // First line should be valid JSON with run id
        let run_val: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(run_val["id"], "test-123");

        // Second line should be valid JSON with event kind
        let event_val: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(event_val["kind"], "terminal.output");
    }

    #[test]
    fn jsonl_export_redacted() {
        let run = Run {
            id: "test-456".to_string(),
            name: None,
            command: vec!["bash".to_string()],
            cwd: "/home/user/project/src".to_string(),
            project_dir: "/home/user/project".to_string(),
            tags: vec![],
            notes: None,
            status: crate::core::run::RunStatus::Succeeded,
            started_at: Utc::now(),
            ended_at: None,
            exit_code: Some(0),
            parent_run_id: None,
            next_sequence: 0,
        };

        let output = export_jsonl(&run, &[], true).unwrap();
        let run_val: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        // CWD should be redacted to just the basename
        assert_eq!(run_val["cwd"], "src");
    }
}
