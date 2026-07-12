use crate::core::event::TraceEvent;
use crate::core::run::Run;

/// Export a run and its events as a self-contained HTML document.
///
/// The output includes embedded CSS and requires no external resources.
/// Status values are color-coded for quick visual scanning.
pub fn export_html(
    run: &Run,
    events: &[TraceEvent],
    redact: bool,
) -> anyhow::Result<String> {
    let run_json = {
        let mut v = serde_json::to_value(run)?;
        if redact {
            redact_run(&mut v);
        }
        v
    };

    let command = run_json["command"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();

    let status_str = run_json["status"].as_str().unwrap_or("unknown");
    let status_class = match status_str {
        "Succeeded" => "status-success",
        "Failed" => "status-error",
        "Running" => "status-running",
        "Pending" => "status-pending",
        _ => "",
    };

    let cwd = run_json["cwd"].as_str().unwrap_or("");
    let started = run_json["started_at"].as_str().unwrap_or("");
    let ended = run_json["ended_at"].as_str().unwrap_or("--");
    let exit_code = run_json["exit_code"]
        .as_i64()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "--".to_string());

    // Duration
    let duration = if let (Some(s), Some(e)) = (
        run_json["started_at"].as_str(),
        run_json["ended_at"].as_str(),
    ) {
        match (s.parse::<chrono::DateTime<chrono::Utc>>(), e.parse::<chrono::DateTime<chrono::Utc>>())
        {
            (Ok(start), Ok(end)) => {
                let ms = (end - start).num_milliseconds();
                format_duration(ms)
            }
            _ => "--".to_string(),
        }
    } else {
        "--".to_string()
    };

    let mut event_rows = String::new();
    for event in events {
        let mut ev_json = serde_json::to_value(event)?;
        if redact {
            redact_event(&mut ev_json);
        }

        let time = ev_json["started_at"].as_str().unwrap_or("");
        let seq = ev_json["sequence"].as_u64().unwrap_or(0);
        let source = ev_json["source"].as_str().unwrap_or("");
        let kind = ev_json["kind"].as_str().unwrap_or("");
        let ev_status = ev_json["status"].as_str().unwrap_or("unknown");
        let side_effect = ev_json["side_effect"].as_str().unwrap_or("");

        let ev_status_class = match ev_status {
            "Success" => "status-success",
            "Error" => "status-error",
            "Running" => "status-running",
            "Pending" => "status-pending",
            _ => "",
        };

        event_rows.push_str(&format!(
            r#"        <tr>
          <td>{time}</td>
          <td class="num">{seq}</td>
          <td>{source}</td>
          <td>{kind}</td>
          <td><span class="badge {ev_status_class}">{ev_status}</span></td>
          <td>{side_effect}</td>
        </tr>
"#,
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blackbox Export — {run_id}</title>
<style>
  :root {{
    --bg: #fafafa;
    --fg: #1a1a1a;
    --border: #ddd;
    --muted: #666;
    --green: #16a34a;
    --red: #dc2626;
    --yellow: #ca8a04;
    --blue: #2563eb;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: var(--bg);
    color: var(--fg);
    padding: 2rem;
    line-height: 1.5;
  }}
  h1 {{
    font-size: 1.5rem;
    margin-bottom: 0.25rem;
  }}
  .run-id {{
    font-family: monospace;
    font-size: 0.85rem;
    color: var(--muted);
    margin-bottom: 1.5rem;
  }}
  .meta {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
    padding: 1rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: #fff;
  }}
  .meta-item {{ display: flex; flex-direction: column; }}
  .meta-label {{
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin-bottom: 0.15rem;
  }}
  .meta-value {{ font-size: 0.95rem; font-weight: 500; }}
  h2 {{
    font-size: 1.15rem;
    margin-bottom: 0.75rem;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88rem;
    background: #fff;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }}
  th, td {{
    padding: 0.5rem 0.75rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  th {{
    background: #f3f4f6;
    font-weight: 600;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover {{ background: #f9fafb; }}
  .num {{ font-family: monospace; text-align: right; }}
  .badge {{
    display: inline-block;
    padding: 0.15em 0.5em;
    border-radius: 4px;
    font-size: 0.82rem;
    font-weight: 600;
  }}
  .status-success {{ background: #dcfce7; color: var(--green); }}
  .status-error {{ background: #fee2e2; color: var(--red); }}
  .status-running {{ background: #fef9c3; color: var(--yellow); }}
  .status-pending {{ background: #e0e7ff; color: var(--blue); }}
  .empty {{ color: var(--muted); font-style: italic; padding: 1.5rem; text-align: center; }}
</style>
</head>
<body>
  <h1>Run Export</h1>
  <div class="run-id">{run_id}</div>

  <div class="meta">
    <div class="meta-item">
      <span class="meta-label">Command</span>
      <span class="meta-value">{command}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Status</span>
      <span class="meta-value"><span class="badge {status_class}">{status_str}</span></span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Working Directory</span>
      <span class="meta-value">{cwd}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Started</span>
      <span class="meta-value">{started}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Ended</span>
      <span class="meta-value">{ended}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Duration</span>
      <span class="meta-value">{duration}</span>
    </div>
    <div class="meta-item">
      <span class="meta-label">Exit Code</span>
      <span class="meta-value">{exit_code}</span>
    </div>
  </div>

  <h2>Events ({num_events})</h2>
  {table}
</body>
</html>"#,
        run_id = run.id,
        command = html_escape(&command),
        status_str = status_str,
        status_class = status_class,
        cwd = html_escape(cwd),
        started = started,
        ended = ended,
        duration = duration,
        exit_code = exit_code,
        num_events = events.len(),
        table = if events.is_empty() {
            r#"<div class="empty">No events recorded.</div>"#.to_string()
        } else {
            format!(
                r#"  <table>
    <thead>
      <tr>
        <th>Time</th>
        <th style="text-align:right">Seq</th>
        <th>Source</th>
        <th>Kind</th>
        <th>Status</th>
        <th>Side Effect</th>
      </tr>
    </thead>
    <tbody>
{event_rows}    </tbody>
  </table>"#,
                event_rows = event_rows
            )
        },
    );

    Ok(html)
}

fn format_duration(ms: i64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        let mins = ms / 60_000;
        let secs = (ms % 60_000) / 1000;
        format!("{}m {}s", mins, secs)
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn redact_run(val: &mut serde_json::Value) {
    if let Some(obj) = val.as_object_mut() {
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
        if let Some(meta) = obj.get_mut("metadata").and_then(|v| v.as_object_mut()) {
            meta.remove("raw");
            if meta.contains_key("diff_preview") {
                meta.insert(
                    "diff_preview".to_string(),
                    serde_json::json!("[REDACTED]"),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};
    use chrono::Utc;

    fn make_run() -> Run {
        Run {
            id: "run-abc123".into(),
            name: None,
            command: vec!["cargo".into(), "test".into()],
            cwd: "/home/user/project".into(),
            project_dir: "/home/user/project".into(),
            tags: vec![],
            notes: None,
            status: crate::core::run::RunStatus::Succeeded,
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            exit_code: Some(0),
            parent_run_id: None,
            next_sequence: 1,
        }
    }

    fn make_event(seq: u64, status: EventStatus) -> TraceEvent {
        TraceEvent {
            id: format!("evt-{}", seq),
            run_id: "run-abc123".into(),
            parent_event_id: None,
            sequence: seq,
            source: EventSource::Terminal,
            kind: "command".into(),
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            duration_ms: Some(100),
            status,
            side_effect: crate::core::event::SideEffect::None,
            input_blob: None,
            output_blob: None,
            error_blob: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn html_export_produces_valid_structure() {
        let run = make_run();
        let events = vec![make_event(1, EventStatus::Success)];
        let html = export_html(&run, &events, false).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("run-abc123"));
        assert!(html.contains("cargo test"));
        assert!(html.contains("status-success"));
        assert!(html.contains("Events (1)"));
        assert!(html.contains("</table>"));
    }

    #[test]
    fn html_export_empty_events() {
        let run = make_run();
        let html = export_html(&run, &[], false).unwrap();

        assert!(html.contains("Events (0)"));
        assert!(html.contains("No events recorded."));
        assert!(!html.contains("<table>"));
    }

    #[test]
    fn html_export_redacted() {
        let run = make_run();
        let events = vec![make_event(1, EventStatus::Success)];
        let html = export_html(&run, &events, true).unwrap();

        // cwd should be redacted to basename only
        assert!(html.contains("project"));
        assert!(!html.contains("/home/user/project"));
    }

    #[test]
    fn html_escape_works() {
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
    }

    #[test]
    fn format_duration_variants() {
        assert_eq!(format_duration(500), "500ms");
        assert_eq!(format_duration(1500), "1.5s");
        assert_eq!(format_duration(65000), "1m 5s");
    }
}
