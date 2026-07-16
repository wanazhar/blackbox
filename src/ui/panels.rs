//! Derived panel data for the daily-driver TUI.
//!
//! Pure functions over `Run` + events so the TUI stays thin and testable.

use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};
use crate::core::run::Run;

/// One display line for a content panel (with optional event id for Enter).
#[derive(Debug, Clone)]
pub struct PanelLine {
    pub text: String,
    pub event_id: Option<String>,
}

/// Header summary always visible at the top of the TUI.
#[derive(Debug, Clone, Default)]
pub struct RunHeader {
    pub name: String,
    pub short_id: String,
    pub status: String,
    pub adapter: String,
    pub duration: String,
    pub capture_quality: String,
    pub files_changed: usize,
    pub failure_count: usize,
    pub side_effect_risk: String,
    pub mode: String,
}

/// Build header fields from a run and its events.
pub fn build_header(run: &Run, events: &[TraceEvent]) -> RunHeader {
    let duration = run
        .duration_ms
        .or_else(|| {
            run.ended_at
                .map(|e| (e - run.started_at).num_milliseconds().max(0) as u64)
        })
        .map(|ms| {
            if ms >= 60_000 {
                format!("{:.1}m", ms as f64 / 60_000.0)
            } else {
                format!("{:.1}s", ms as f64 / 1000.0)
            }
        })
        .unwrap_or_else(|| "—".into());

    let adapter = run
        .adapter
        .clone()
        .or_else(|| {
            run.notes.as_ref().and_then(|n| {
                n.split(';')
                    .find_map(|p| p.trim().strip_prefix("adapter:"))
                    .map(|s| s.trim().to_string())
            })
        })
        .unwrap_or_else(|| "unknown".into());

    let mode = if run
        .notes
        .as_deref()
        .map(|n| n.contains("observe-only"))
        .unwrap_or(false)
    {
        "observe-only".into()
    } else if run
        .notes
        .as_deref()
        .map(|n| n.contains("continuity") || n.contains("memory"))
        .unwrap_or(false)
    {
        "continuity".into()
    } else {
        "record".into()
    };

    let (quality, _) = coverage_summary(events);
    let files_changed = file_change_lines(events).len();
    let failure_count = failure_lines(events).len();
    let side_effect_risk = side_effect_risk_label(events);

    RunHeader {
        name: run
            .name
            .clone()
            .unwrap_or_else(|| run.command.first().cloned().unwrap_or_else(|| "run".into())),
        short_id: run.id.chars().take(8).collect(),
        status: format!("{:?}", run.status),
        adapter,
        duration,
        capture_quality: quality,
        files_changed,
        failure_count,
        side_effect_risk,
        mode,
    }
}

/// Timeline lines (all events, bookkeeping optionally filtered).
pub fn timeline_lines(events: &[TraceEvent], hide_bookkeeping: bool) -> Vec<PanelLine> {
    events
        .iter()
        .filter(|ev| {
            if !hide_bookkeeping {
                return true;
            }
            !ev.kind.contains("observer")
                && ev.kind != "capture.coverage"
                && !ev.kind.starts_with("process.resource")
        })
        .map(|ev| {
            let time = ev.started_at.format("%H:%M:%S").to_string();
            let tool = ev
                .metadata
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let extra = if tool.is_empty() {
                String::new()
            } else {
                format!(" {tool}")
            };
            PanelLine {
                text: format!(
                    "{time}  seq={:<5} {:?}  {}{}",
                    ev.sequence, ev.status, ev.kind, extra
                ),
                event_id: Some(ev.id.clone()),
            }
        })
        .collect()
}

/// Process / process-tree related events.
pub fn process_lines(events: &[TraceEvent]) -> Vec<PanelLine> {
    let mut lines = Vec::new();
    for ev in events {
        let is_process = ev.source == EventSource::Process || ev.kind.starts_with("process.");
        if !is_process {
            continue;
        }
        if ev.kind.contains("observer") || ev.kind.starts_with("process.resource") {
            continue;
        }
        let pid = ev
            .metadata
            .get("pid")
            .and_then(|v| v.as_u64())
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".into());
        let ppid = ev
            .metadata
            .get("ppid")
            .and_then(|v| v.as_u64())
            .map(|p| format!(" ppid={p}"))
            .unwrap_or_default();
        let cmd = command_preview(ev);
        lines.push(PanelLine {
            text: format!(
                "pid={pid}{ppid}  {}  {}",
                ev.kind.trim_start_matches("process."),
                cmd
            ),
            event_id: Some(ev.id.clone()),
        });
    }
    if lines.is_empty() {
        lines.push(PanelLine {
            text: "(no process-tree events — Linux /proc capture or process layer inactive)"
                .into(),
            event_id: None,
        });
    }
    lines
}

/// Filesystem change events.
pub fn file_change_lines(events: &[TraceEvent]) -> Vec<PanelLine> {
    let mut lines = Vec::new();
    for ev in events {
        if ev.source != EventSource::Filesystem {
            continue;
        }
        if ev.kind.contains("observer") || ev.kind.contains("snapshot") {
            continue;
        }
        let path = ev
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        lines.push(PanelLine {
            text: format!("{}  {path}", short_kind(&ev.kind)),
            event_id: Some(ev.id.clone()),
        });
    }
    lines
}

/// Failures and warnings.
pub fn failure_lines(events: &[TraceEvent]) -> Vec<PanelLine> {
    let mut lines = Vec::new();
    for ev in events {
        let is_err = ev.status == EventStatus::Error
            || ev
                .metadata
                .get("exit_code")
                .and_then(|v| v.as_i64())
                .map(|c| c != 0)
                .unwrap_or(false)
            || ev.kind.contains("error")
            || ev.kind == "analysis.failure_to_fix";
        if !is_err {
            continue;
        }
        let msg = ev
            .metadata
            .get("message")
            .or_else(|| ev.metadata.get("error_message"))
            .or_else(|| ev.metadata.get("stderr"))
            .or_else(|| ev.metadata.get("error_message"))
            .and_then(|v| v.as_str())
            .unwrap_or(ev.kind.as_str());
        let msg = truncate(msg, 100);
        lines.push(PanelLine {
            text: format!("seq={}  {}  {msg}", ev.sequence, ev.kind),
            event_id: Some(ev.id.clone()),
        });
    }
    // Also surface retry/waste analysis
    for ev in events {
        if ev.kind == "analysis.retry_waste" {
            let detail = ev
                .metadata
                .get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or("repeated work");
            lines.push(PanelLine {
                text: format!("retry/waste: {detail}"),
                event_id: Some(ev.id.clone()),
            });
        }
    }
    lines
}

/// External / destructive / local-write side effects.
pub fn side_effect_lines(events: &[TraceEvent]) -> Vec<PanelLine> {
    let mut lines = Vec::new();
    for ev in events {
        match ev.side_effect {
            SideEffect::LocalWrite | SideEffect::ExternalWrite | SideEffect::Destructive => {
                let detail = command_preview(ev);
                lines.push(PanelLine {
                    text: format!(
                        "seq={}  {:?}  {}  {detail}",
                        ev.sequence, ev.side_effect, ev.kind
                    ),
                    event_id: Some(ev.id.clone()),
                });
            }
            _ => {}
        }
    }
    if lines.is_empty() {
        // Distinguish absence from unavailable network capture.
        let network_note = events
            .iter()
            .find(|e| e.kind == "capture.coverage")
            .and_then(|e| e.metadata.get("coverage"))
            .and_then(|c| c.get("surfaces"))
            .and_then(|s| s.as_array())
            .and_then(|arr| {
                arr.iter().find(|s| {
                    s.get("name").and_then(|n| n.as_str()) == Some("network")
                })
            })
            .and_then(|s| s.get("status").and_then(|st| st.as_str()))
            .unwrap_or("unknown");
        lines.push(PanelLine {
            text: format!(
                "(no local-write/external/destructive side effects observed; network={network_note})"
            ),
            event_id: None,
        });
    }
    lines
}

/// Capture quality / coverage surfaces.
pub fn coverage_lines(events: &[TraceEvent]) -> Vec<PanelLine> {
    let mut lines = Vec::new();
    if let Some(ev) = events.iter().find(|e| e.kind == "capture.coverage") {
        if let Some(cov) = ev.metadata.get("coverage") {
            if let Some(score) = cov.get("quality_score").and_then(|v| v.as_u64()) {
                lines.push(PanelLine {
                    text: format!("quality score: {score}%"),
                    event_id: Some(ev.id.clone()),
                });
            }
            if let Some(total) = cov.get("total_events").and_then(|v| v.as_u64()) {
                lines.push(PanelLine {
                    text: format!("total capture events: {total}"),
                    event_id: None,
                });
            }
            if let Some(surfaces) = cov.get("surfaces").and_then(|v| v.as_array()) {
                for s in surfaces {
                    let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let status = s
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let count = s.get("events_count").and_then(|v| v.as_u64()).unwrap_or(0);
                    let note = s
                        .get("note")
                        .and_then(|v| v.as_str())
                        .map(|n| format!(" [{n}]"))
                        .unwrap_or_default();
                    lines.push(PanelLine {
                        text: format!("{name}: status={status} events={count}{note}"),
                        event_id: None,
                    });
                }
            }
            if let Some(notes) = cov.get("notes").and_then(|v| v.as_array()) {
                for n in notes {
                    if let Some(s) = n.as_str() {
                        if s.starts_with("quality_score:") {
                            continue;
                        }
                        lines.push(PanelLine {
                            text: format!("note: {s}"),
                            event_id: None,
                        });
                    }
                }
            }
        }
    }
    if lines.is_empty() {
        lines.push(PanelLine {
            text: "(no capture.coverage event for this run)".into(),
            event_id: None,
        });
    }
    lines
}

/// Replay preflight summary lines (honest guarantees).
pub fn replay_preflight_lines(events: &[TraceEvent]) -> Vec<PanelLine> {
    use crate::core::command::CommandMetadata;

    let mut exact = 0usize;
    let mut lossy = 0usize;
    let mut shell = 0usize;
    for ev in events {
        if let Some(meta) = CommandMetadata::from_event(ev) {
            if meta.fidelity.is_safe_for_sandbox() {
                exact += 1;
            } else if !meta.argv.is_empty() || meta.shell_source.is_some() {
                lossy += 1;
            }
            if meta
                .argv
                .first()
                .map(|a| {
                    let base = std::path::Path::new(a)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(a);
                    matches!(base, "sh" | "bash" | "dash" | "zsh" | "fish" | "ksh")
                })
                .unwrap_or(false)
            {
                shell += 1;
            }
        }
    }
    vec![
        PanelLine {
            text: "Replay is not deterministic LLM re-run. Modes:".into(),
            event_id: None,
        },
        PanelLine {
            text: "  Timeline playback  — no execution (default show)".into(),
            event_id: None,
        },
        PanelLine {
            text: "  Recorded tool playback — blackbox replay --mock-tools".into(),
            event_id: None,
        },
        PanelLine {
            text: format!(
                "  Sandbox re-execution — blackbox replay --sandbox  (exact={exact} lossy={lossy} shell={shell} blocked)"
            ),
            event_id: None,
        },
        PanelLine {
            text: "  Live re-execution — blackbox replay --live  (DANGEROUS)".into(),
            event_id: None,
        },
        PanelLine {
            text: "  Forked continuation — blackbox fork <run> --launch".into(),
            event_id: None,
        },
        PanelLine {
            text: "Lossy argv and shell interpreters are blocked under sandbox.".into(),
            event_id: None,
        },
    ]
}

/// Help / keymap.
pub fn help_lines() -> Vec<PanelLine> {
    [
        "j/k or ↓/↑   move selection",
        "Tab          cycle Runs ↔ Content",
        "Enter        inspect selected item / load run",
        "t            Timeline",
        "o            Processes (process tree events)",
        "f            Files changed",
        "e            Failures / warnings",
        "x            Side effects (write/destructive)",
        "c            Capture quality",
        "p            Postmortem narrative",
        "h            Handoff / resume hints",
        "r            Replay guarantees (preflight)",
        "d            Diff hint (CLI: blackbox diff)",
        "/            Filter timeline (toggle bookkeeping)",
        "?            This help",
        "q / Esc      quit",
    ]
    .into_iter()
    .map(|s| PanelLine {
        text: s.into(),
        event_id: None,
    })
    .collect()
}

fn coverage_summary(events: &[TraceEvent]) -> (String, Option<u8>) {
    if let Some(ev) = events.iter().find(|e| e.kind == "capture.coverage") {
        if let Some(score) = ev
            .metadata
            .get("coverage")
            .and_then(|c| c.get("quality_score"))
            .and_then(|v| v.as_u64())
        {
            return (format!("{score}%"), Some(score as u8));
        }
    }
    ("n/a".into(), None)
}

fn side_effect_risk_label(events: &[TraceEvent]) -> String {
    let mut destructive = 0usize;
    let mut external = 0usize;
    let mut local = 0usize;
    for ev in events {
        match ev.side_effect {
            SideEffect::Destructive => destructive += 1,
            SideEffect::ExternalWrite => external += 1,
            SideEffect::LocalWrite => local += 1,
            _ => {}
        }
    }
    if destructive > 0 {
        format!("destructive×{destructive}")
    } else if external > 0 {
        format!("external×{external}")
    } else if local > 0 {
        format!("local-write×{local}")
    } else {
        "none observed".into()
    }
}

fn command_preview(ev: &TraceEvent) -> String {
    if let Some(argv) = ev.metadata.get("argv").and_then(|v| v.as_array()) {
        let parts: Vec<&str> = argv.iter().filter_map(|v| v.as_str()).take(6).collect();
        if !parts.is_empty() {
            return truncate(&parts.join(" "), 80);
        }
    }
    if let Some(s) = ev.metadata.get("command").and_then(|v| v.as_str()) {
        return truncate(s, 80);
    }
    if let Some(arr) = ev.metadata.get("command").and_then(|v| v.as_array()) {
        let parts: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).take(6).collect();
        if !parts.is_empty() {
            return truncate(&parts.join(" "), 80);
        }
    }
    if let Some(tool) = ev.metadata.get("tool_name").and_then(|v| v.as_str()) {
        return tool.to_string();
    }
    String::new()
}

fn short_kind(kind: &str) -> &str {
    kind.rsplit('.').next().unwrap_or(kind)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let end = s.floor_char_boundary(max.saturating_sub(1));
        format!("{}…", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};
    use crate::core::run::{Run, RunStatus};

    fn sample_run() -> Run {
        let mut r = Run::new(vec!["claude".into()], "/tmp".into());
        r.name = Some("fix-auth".into());
        r.status = RunStatus::Succeeded;
        r.adapter = Some("claude".into());
        r.duration_ms = Some(90_000);
        r.notes = Some("observe-only; adapter:claude".into());
        r
    }

    fn ev(kind: &str, source: EventSource, status: EventStatus) -> TraceEvent {
        let mut e = TraceEvent::new("run-1", source, kind);
        e.status = status;
        e
    }

    #[test]
    fn header_shows_observe_only_and_adapter() {
        let run = sample_run();
        let h = build_header(&run, &[]);
        assert_eq!(h.mode, "observe-only");
        assert_eq!(h.adapter, "claude");
        assert!(h.duration.contains('m') || h.duration.contains('s'));
        assert_eq!(h.name, "fix-auth");
    }

    #[test]
    fn process_lines_include_argv() {
        let mut e = ev(
            "process.exec",
            EventSource::Process,
            EventStatus::Success,
        );
        e.metadata
            .insert("pid".into(), serde_json::json!(42));
        e.metadata.insert(
            "argv".into(),
            serde_json::json!(["grep", "hello world", "f.txt"]),
        );
        let lines = process_lines(&[e]);
        assert!(lines[0].text.contains("grep"));
        assert!(lines[0].text.contains("hello world"));
    }

    #[test]
    fn failure_lines_catch_errors() {
        let mut e = ev("tool.result", EventSource::Tool, EventStatus::Error);
        e.metadata
            .insert("message".into(), serde_json::json!("boom"));
        let lines = failure_lines(&[e]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].text.contains("boom"));
    }

    #[test]
    fn side_effect_empty_notes_network() {
        let lines = side_effect_lines(&[]);
        assert!(lines[0].text.contains("no local-write"));
    }

    #[test]
    fn coverage_lines_from_event() {
        let mut e = ev("capture.coverage", EventSource::System, EventStatus::Success);
        e.metadata.insert(
            "coverage".into(),
            serde_json::json!({
                "quality_score": 72,
                "total_events": 10,
                "surfaces": [{"name":"pty","status":"complete","events_count":5,"enabled":true}],
                "notes": []
            }),
        );
        let lines = coverage_lines(&[e]);
        assert!(lines.iter().any(|l| l.text.contains("72%")));
        assert!(lines.iter().any(|l| l.text.contains("pty")));
    }

    #[test]
    fn destructive_risk_label() {
        let mut e = ev("tool.call", EventSource::Tool, EventStatus::Success);
        e.side_effect = SideEffect::Destructive;
        let h = build_header(&sample_run(), &[e]);
        assert!(h.side_effect_risk.contains("destructive"));
    }
}
