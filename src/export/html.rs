use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::transcript::rebuild_tool_transcript;

/// Export a run and its events as a self-contained HTML document.
///
/// Includes tool summary, event table with detail column, client-side
/// filter, and a light/dark theme via prefers-color-scheme.
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
    let notes = run_json["notes"].as_str().unwrap_or("");

    let duration = if let (Some(s), Some(e)) = (
        run_json["started_at"].as_str(),
        run_json["ended_at"].as_str(),
    ) {
        match (
            s.parse::<chrono::DateTime<chrono::Utc>>(),
            e.parse::<chrono::DateTime<chrono::Utc>>(),
        ) {
            (Ok(start), Ok(end)) => format_duration((end - start).num_milliseconds()),
            _ => "--".to_string(),
        }
    } else {
        "--".to_string()
    };

    let tool_count = events.iter().filter(|e| e.kind == "tool.call").count();
    let error_count = events
        .iter()
        .filter(|e| matches!(e.status, crate::core::event::EventStatus::Error))
        .count();
    let tools_section = {
        let body = rebuild_tool_transcript(events);
        if body.is_empty() {
            r#"<p class="empty">No tool.call events.</p>"#.to_string()
        } else {
            format!(
                r#"<pre class="tools">{}</pre>"#,
                html_escape(&body)
            )
        }
    };

    let mut event_rows = String::new();
    for event in events {
        let mut ev_json = serde_json::to_value(event)?;
        if redact {
            redact_event(&mut ev_json);
        }

        let time = ev_json["started_at"].as_str().unwrap_or("");
        // shorten time to HH:MM:SS
        let time_short = if time.len() >= 19 {
            &time[11..19]
        } else {
            time
        };
        let seq = ev_json["sequence"].as_u64().unwrap_or(0);
        let source = ev_json["source"].as_str().unwrap_or("");
        let kind = ev_json["kind"].as_str().unwrap_or("");
        let ev_status = ev_json["status"].as_str().unwrap_or("unknown");
        let side_effect = ev_json["side_effect"].as_str().unwrap_or("");

        let detail = event_detail(&ev_json);

        let ev_status_class = match ev_status {
            "Success" => "status-success",
            "Error" => "status-error",
            "Running" => "status-running",
            "Pending" => "status-pending",
            _ => "",
        };

        let row_class = if kind.starts_with("tool.") {
            "row-tool"
        } else if ev_status == "Error" {
            "row-error"
        } else {
            ""
        };

        event_rows.push_str(&format!(
            r#"        <tr class="{row_class}" data-kind="{kind_l}" data-source="{source_l}" data-status="{status_l}">
          <td class="mono">{time}</td>
          <td class="num">{seq}</td>
          <td>{source}</td>
          <td class="kind">{kind}</td>
          <td><span class="badge {ev_status_class}">{ev_status}</span></td>
          <td class="muted">{side}</td>
          <td class="detail">{detail}</td>
        </tr>
"#,
            time = html_escape(time_short),
            seq = seq,
            source = html_escape(source),
            kind = html_escape(kind),
            kind_l = html_escape(&kind.to_lowercase()),
            source_l = html_escape(&source.to_lowercase()),
            status_l = html_escape(&ev_status.to_lowercase()),
            ev_status = html_escape(ev_status),
            ev_status_class = ev_status_class,
            side = html_escape(side_effect),
            detail = html_escape(&detail),
            row_class = row_class,
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blackbox — {run_id_short}</title>
<style>
  :root {{
    --bg: #f6f7f9;
    --card: #ffffff;
    --fg: #111827;
    --border: #e5e7eb;
    --muted: #6b7280;
    --green: #15803d;
    --red: #b91c1c;
    --yellow: #a16207;
    --blue: #1d4ed8;
    --tool: #eff6ff;
    --error-bg: #fef2f2;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #0b0f14;
      --card: #121820;
      --fg: #e5e7eb;
      --border: #1f2937;
      --muted: #9ca3af;
      --green: #4ade80;
      --red: #f87171;
      --yellow: #facc15;
      --blue: #60a5fa;
      --tool: #0f1c2e;
      --error-bg: #2a1215;
    }}
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--fg);
    padding: 1.5rem clamp(1rem, 3vw, 2.5rem);
    line-height: 1.5;
  }}
  h1 {{ font-size: 1.35rem; font-weight: 700; }}
  h2 {{ font-size: 1.05rem; margin: 1.5rem 0 0.6rem; }}
  .run-id {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.8rem; color: var(--muted); margin: 0.2rem 0 1rem; }}
  .meta {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 0.85rem;
    margin-bottom: 1.25rem;
    padding: 1rem;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: var(--card);
  }}
  .meta-label {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }}
  .meta-value {{ font-size: 0.92rem; font-weight: 500; word-break: break-word; }}
  .stats {{ display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1rem; }}
  .stat {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 0.25rem 0.75rem;
    font-size: 0.82rem;
    color: var(--muted);
  }}
  .stat strong {{ color: var(--fg); }}
  .toolbar {{
    display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center;
    margin: 0.5rem 0 0.75rem;
  }}
  .toolbar input, .toolbar select {{
    background: var(--card);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.4rem 0.65rem;
    font-size: 0.88rem;
  }}
  .toolbar input {{ min-width: min(280px, 100%); flex: 1; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.84rem;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }}
  th, td {{
    padding: 0.45rem 0.65rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  th {{
    background: color-mix(in srgb, var(--card) 80%, var(--border));
    font-weight: 600;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--muted);
    position: sticky;
    top: 0;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover {{ filter: brightness(0.98); }}
  .row-tool {{ background: var(--tool); }}
  .row-error {{ background: var(--error-bg); }}
  .num {{ font-family: ui-monospace, Menlo, monospace; text-align: right; }}
  .mono {{ font-family: ui-monospace, Menlo, monospace; font-size: 0.8rem; white-space: nowrap; }}
  .kind {{ font-family: ui-monospace, Menlo, monospace; font-size: 0.8rem; }}
  .detail {{ color: var(--muted); max-width: 28rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .muted {{ color: var(--muted); }}
  .badge {{
    display: inline-block;
    padding: 0.12em 0.45em;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 600;
  }}
  .status-success {{ background: color-mix(in srgb, var(--green) 18%, transparent); color: var(--green); }}
  .status-error {{ background: color-mix(in srgb, var(--red) 18%, transparent); color: var(--red); }}
  .status-running {{ background: color-mix(in srgb, var(--yellow) 18%, transparent); color: var(--yellow); }}
  .status-pending {{ background: color-mix(in srgb, var(--blue) 18%, transparent); color: var(--blue); }}
  .empty {{ color: var(--muted); font-style: italic; padding: 1rem; }}
  pre.tools {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.85rem 1rem;
    overflow-x: auto;
    font-size: 0.82rem;
    font-family: ui-monospace, Menlo, monospace;
  }}
  footer {{ margin-top: 2rem; color: var(--muted); font-size: 0.75rem; }}
  .hidden {{ display: none !important; }}
</style>
</head>
<body>
  <h1>{title}</h1>
  <div class="run-id">{run_id}</div>

  <div class="meta">
    <div><div class="meta-label">Command</div><div class="meta-value">{command}</div></div>
    <div><div class="meta-label">Status</div><div class="meta-value"><span class="badge {status_class}">{status_str}</span></div></div>
    <div><div class="meta-label">Cwd</div><div class="meta-value">{cwd}</div></div>
    <div><div class="meta-label">Started</div><div class="meta-value">{started}</div></div>
    <div><div class="meta-label">Ended</div><div class="meta-value">{ended}</div></div>
    <div><div class="meta-label">Duration</div><div class="meta-value">{duration}</div></div>
    <div><div class="meta-label">Exit</div><div class="meta-value">{exit_code}</div></div>
    {notes_block}
  </div>

  <div class="stats">
    <span class="stat"><strong>{num_events}</strong> events</span>
    <span class="stat"><strong>{tool_count}</strong> tools</span>
    <span class="stat"><strong>{error_count}</strong> errors</span>
  </div>

  <h2>Tools</h2>
  {tools_section}

  <h2>Timeline</h2>
  <div class="toolbar">
    <input id="filter" type="search" placeholder="Filter kind / source / detail…" autocomplete="off">
    <select id="srcFilter">
      <option value="">All sources</option>
      <option>Tool</option>
      <option>Terminal</option>
      <option>Filesystem</option>
      <option>Git</option>
      <option>Process</option>
      <option>System</option>
      <option>Harness</option>
    </select>
  </div>
  {table}

  <footer>Generated by blackbox · self-contained HTML report</footer>
  <script>
    const q = document.getElementById('filter');
    const src = document.getElementById('srcFilter');
    const rows = [...document.querySelectorAll('tbody tr')];
    function apply() {{
      const term = (q.value || '').toLowerCase();
      const source = (src.value || '').toLowerCase();
      for (const r of rows) {{
        const hay = r.innerText.toLowerCase();
        const okTerm = !term || hay.includes(term);
        const okSrc = !source || (r.dataset.source || '') === source;
        r.classList.toggle('hidden', !(okTerm && okSrc));
      }}
    }}
    q.addEventListener('input', apply);
    src.addEventListener('change', apply);
  </script>
</body>
</html>"#,
        title = html_escape(run.name.as_deref().unwrap_or("Run export")),
        run_id = html_escape(&run.id),
        run_id_short = html_escape(&run.id[..8.min(run.id.len())]),
        command = html_escape(&command),
        status_str = html_escape(status_str),
        status_class = status_class,
        cwd = html_escape(cwd),
        started = html_escape(started),
        ended = html_escape(ended),
        duration = duration,
        exit_code = html_escape(&exit_code),
        notes_block = if notes.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div><div class="meta-label">Notes</div><div class="meta-value">{}</div></div>"#,
                html_escape(notes)
            )
        },
        num_events = events.len(),
        tool_count = tool_count,
        error_count = error_count,
        tools_section = tools_section,
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
        <th>Effect</th>
        <th>Detail</th>
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

fn event_detail(ev_json: &serde_json::Value) -> String {
    // Read from the serialized+redacted JSON value, not the raw event,
    // so secrets removed by redaction are never surfaced.
    let meta = ev_json.get("metadata");
    if let Some(p) = meta
        .and_then(|m| m.get("preview"))
        .and_then(|v| v.as_str())
    {
        return p.replace('\n', "⏎");
    }
    if let Some(n) = meta
        .and_then(|m| m.get("tool_name"))
        .and_then(|v| v.as_str())
    {
        let input = meta
            .and_then(|m| m.get("input"))
            .map(|v| {
                let s = v.to_string();
                if s.len() > 80 {
                    let end = s.floor_char_boundary(80);
                    format!("{}…", &s[..end])
                } else {
                    s
                }
            })
            .unwrap_or_default();
        return format!("{n} {input}");
    }
    if let Some(p) = meta
        .and_then(|m| m.get("path"))
        .and_then(|v| v.as_str())
    {
        return p.to_string();
    }
    if let Some(c) = meta.and_then(|m| m.get("exit_code")) {
        return format!("exit={c}");
    }
    String::new()
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
        .replace('\'', "&#x27;")
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
            name: Some("demo".into()),
            command: vec!["cargo".into(), "test".into()],
            cwd: "/home/user/project".into(),
            project_dir: "/home/user/project".into(),
            tags: vec![],
            notes: Some("adapter:generic".into()),
            status: crate::core::run::RunStatus::Succeeded,
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            exit_code: Some(0),
            parent_run_id: None,
            next_sequence: 1,
        }
    }

    fn make_event(seq: u64, status: EventStatus) -> TraceEvent {
        let mut ev = TraceEvent {
            id: format!("evt-{}", seq),
            run_id: "run-abc123".into(),
            parent_event_id: None,
            sequence: seq,
            source: EventSource::Terminal,
            kind: "terminal.output".into(),
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            duration_ms: Some(100),
            status,
            side_effect: crate::core::event::SideEffect::None,
            input_blob: None,
            output_blob: None,
            error_blob: None,
            metadata: std::collections::HashMap::new(),
        };
        ev.metadata
            .insert("preview".into(), serde_json::json!("hello world"));
        ev
    }

    #[test]
    fn html_export_produces_valid_structure() {
        let run = make_run();
        let mut tool = make_event(2, EventStatus::Running);
        tool.source = EventSource::Tool;
        tool.kind = "tool.call".into();
        tool.metadata
            .insert("tool_name".into(), serde_json::json!("Bash"));
        let events = vec![make_event(1, EventStatus::Success), tool];
        let html = export_html(&run, &events, false).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("run-abc123"));
        assert!(html.contains("cargo test"));
        assert!(html.contains("status-success"));
        assert!(html.contains("Tools"));
        assert!(html.contains("Bash"));
        assert!(html.contains("filter"));
        assert!(html.contains("</table>"));
        assert!(html.contains("prefers-color-scheme"));
    }

    #[test]
    fn html_export_empty_events() {
        let run = make_run();
        let html = export_html(&run, &[], false).unwrap();
        assert!(html.contains("No events recorded.") || html.contains("0 events"));
        assert!(html.contains("No tool.call events"));
    }

    #[test]
    fn html_export_redacted() {
        let run = make_run();
        let events = vec![make_event(1, EventStatus::Success)];
        let html = export_html(&run, &events, true).unwrap();
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
