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

/// Process / process-tree related events, preferring an ASCII tree when possible.
pub fn process_lines(events: &[TraceEvent]) -> Vec<PanelLine> {
    let mut lines = Vec::new();

    // Prefer reconstructed tree (exact argv preserved in display quoting).
    let roots = crate::core::process_tree::rebuild_from_events(events);
    if !roots.is_empty() {
        let forest = crate::core::process_tree::ProcessNode::format_forest(&roots);
        lines.push(PanelLine {
            text: format!(
                "Process tree ({} node{})",
                roots.iter().map(|r| r.count_nodes()).sum::<usize>(),
                if roots.iter().map(|r| r.count_nodes()).sum::<usize>() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            event_id: None,
        });
        for line in forest.lines() {
            lines.push(PanelLine {
                text: line.to_string(),
                event_id: None,
            });
        }
        lines.push(PanelLine {
            text: "─".repeat(40),
            event_id: None,
        });
        lines.push(PanelLine {
            text: "Events:".into(),
            event_id: None,
        });
    }

    let mut event_lines = 0usize;
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
        event_lines += 1;
    }
    if event_lines == 0 && roots.is_empty() {
        lines.push(PanelLine {
            text: "(no process-tree events — Linux /proc capture or process layer inactive)"
                .into(),
            event_id: None,
        });
    }
    lines
}

/// Trajectory diff lines for comparing two runs in the TUI.
pub fn trajectory_diff_lines(
    diff: &crate::trajectory::TrajectoryDiffView,
) -> Vec<PanelLine> {
    let mut lines = Vec::new();
    lines.push(PanelLine {
        text: format!(
            "Trajectory: {} vs {}  (common prefix {})",
            &diff.run_a[..8.min(diff.run_a.len())],
            &diff.run_b[..8.min(diff.run_b.len())],
            diff.common_prefix_len
        ),
        event_id: None,
    });
    if !diff.explanation.is_empty() {
        // Wrap explanation into short lines for the panel.
        let mut rest = diff.explanation.as_str();
        while !rest.is_empty() {
            let end = rest.floor_char_boundary(90.min(rest.len()));
            let chunk = &rest[..end];
            lines.push(PanelLine {
                text: format!("  {chunk}"),
                event_id: None,
            });
            rest = rest[end..].trim_start();
        }
    }
    if !diff.next_hint.is_empty() {
        lines.push(PanelLine {
            text: format!("Next: {}", diff.next_hint),
            event_id: None,
        });
    }
    if let Some(ref div) = diff.first_divergence {
        lines.push(PanelLine {
            text: format!("First divergence at index {}", div.index),
            event_id: None,
        });
        if let Some(ref a) = div.a {
            lines.push(PanelLine {
                text: format!("  A: seq={} {}", a.sequence, a.label),
                event_id: None,
            });
        }
        if let Some(ref b) = div.b {
            lines.push(PanelLine {
                text: format!("  B: seq={} {}", b.sequence, b.label),
                event_id: None,
            });
        }
    } else {
        lines.push(PanelLine {
            text: "No divergence — trajectories share full semantic prefix".into(),
            event_id: None,
        });
    }
    if !diff.files_only_a.is_empty() {
        lines.push(PanelLine {
            text: format!(
                "Files only A: {}",
                diff.files_only_a.iter().take(6).cloned().collect::<Vec<_>>().join(", ")
            ),
            event_id: None,
        });
    }
    if !diff.files_only_b.is_empty() {
        lines.push(PanelLine {
            text: format!(
                "Files only B: {}",
                diff.files_only_b.iter().take(6).cloned().collect::<Vec<_>>().join(", ")
            ),
            event_id: None,
        });
    }
    if !diff.prefix.is_empty() {
        lines.push(PanelLine {
            text: format!("Shared prefix ({} steps):", diff.prefix.len()),
            event_id: None,
        });
        for step in diff.prefix.iter().take(20) {
            lines.push(PanelLine {
                text: format!("  = seq={} {}", step.sequence, step.label),
                event_id: None,
            });
        }
        if diff.prefix.len() > 20 {
            lines.push(PanelLine {
                text: format!("  … {} more", diff.prefix.len() - 20),
                event_id: None,
            });
        }
    }
    if !diff.only_a.is_empty() {
        lines.push(PanelLine {
            text: format!("Only in A ({}):", diff.only_a.len()),
            event_id: None,
        });
        for step in diff.only_a.iter().take(15) {
            lines.push(PanelLine {
                text: format!("  - seq={} {}", step.sequence, step.label),
                event_id: None,
            });
        }
    }
    if !diff.only_b.is_empty() {
        lines.push(PanelLine {
            text: format!("Only in B ({}):", diff.only_b.len()),
            event_id: None,
        });
        for step in diff.only_b.iter().take(15) {
            lines.push(PanelLine {
                text: format!("  + seq={} {}", step.sequence, step.label),
                event_id: None,
            });
        }
    }
    lines.push(PanelLine {
        text: "CLI: blackbox diff <a> <b> --trajectory".into(),
        event_id: None,
    });
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

/// Rich failure panel: story headline, next action, anomalies, then error events.
///
/// Used by TUI Failures mode as the primary debugger surface.
pub fn failure_story_lines(
    run: &Run,
    events: &[TraceEvent],
    summary: Option<&crate::summary::SummaryView>,
) -> Vec<PanelLine> {
    let mut lines = Vec::new();
    let short: String = run.id.chars().take(8).collect();

    lines.push(PanelLine {
        text: format!(
            "══ Failure story · {} · {:?} · exit={:?} ══",
            short, run.status, run.exit_code
        ),
        event_id: None,
    });

    if let Some(s) = summary {
        if !s.headline.is_empty() {
            lines.push(PanelLine {
                text: format!("Story: {}", s.headline),
                event_id: None,
            });
        }
        if !s.next_action.is_empty() {
            lines.push(PanelLine {
                text: format!("Next:  {}", s.next_action),
                event_id: None,
            });
        }
        if !s.evidence.is_empty() {
            lines.push(PanelLine {
                text: "Evidence:".into(),
                event_id: None,
            });
            for e in s.evidence.iter().take(8) {
                let mut t = format!("  · [{}] {}", e.role, truncate(&e.detail, 80));
                if let Some(seq) = e.sequence {
                    t.push_str(&format!(" seq={seq}"));
                }
                lines.push(PanelLine {
                    text: t,
                    event_id: e.event_id.clone(),
                });
            }
        }
        if !s.anomalies.is_empty() {
            lines.push(PanelLine {
                text: "Anomalies:".into(),
                event_id: None,
            });
            for a in s.anomalies.iter().take(10) {
                lines.push(PanelLine {
                    text: format!("  ! [{}|{}] {}", a.severity, a.kind, truncate(&a.detail, 90)),
                    event_id: a.event_id.clone(),
                });
            }
        }
        if !s.turning_points.is_empty() {
            lines.push(PanelLine {
                text: "Turning points:".into(),
                event_id: None,
            });
            for p in s.turning_points.iter().take(8) {
                lines.push(PanelLine {
                    text: format!("  → [{}] {}", p.kind, truncate(&p.detail, 90)),
                    event_id: p.event_id.clone(),
                });
            }
        }
        if !s.failure_fix_chains.is_empty() {
            lines.push(PanelLine {
                text: "Fix chains:".into(),
                event_id: None,
            });
            for c in s.failure_fix_chains.iter().take(5) {
                lines.push(PanelLine {
                    text: format!(
                        "  × {} → files:{}",
                        truncate(&c.error_message, 50),
                        if c.files_changed.is_empty() {
                            "—".into()
                        } else {
                            c.files_changed.iter().take(3).cloned().collect::<Vec<_>>().join(",")
                        }
                    ),
                    event_id: Some(c.error_event_id.clone()),
                });
            }
        }
        lines.push(PanelLine {
            text: "── Error events ──".into(),
            event_id: None,
        });
    } else {
        // No summary: still surface live anomalies from events
        let anoms = crate::analysis::detect_anomalies(events);
        if !anoms.is_empty() {
            lines.push(PanelLine {
                text: "Anomalies:".into(),
                event_id: None,
            });
            for a in anoms.iter().take(10) {
                lines.push(PanelLine {
                    text: format!("  ! [{}|{}] {}", a.severity, a.kind, truncate(&a.detail, 90)),
                    event_id: a.event_id.clone(),
                });
            }
        }
    }

    let errs = failure_lines(events);
    if errs.is_empty() {
        lines.push(PanelLine {
            text: "(no error-status events — check anomalies / postmortem)".into(),
            event_id: None,
        });
    } else {
        lines.extend(errs.into_iter().take(40));
    }

    lines.push(PanelLine {
        text: format!(
            "CLI: blackbox postmortem {short} · blackbox timeline {short} --semantic · p=postmortem"
        ),
        event_id: None,
    });
    lines
}

/// Anomaly-only panel lines (also folded into Failures).
pub fn anomaly_lines(events: &[TraceEvent]) -> Vec<PanelLine> {
    let anoms = crate::analysis::detect_anomalies(events);
    if anoms.is_empty() {
        return vec![PanelLine {
            text: "(no anomalies — no tool loops, destructive actions, token spikes, or long silences)".into(),
            event_id: None,
        }];
    }
    let mut lines = vec![PanelLine {
        text: format!("Anomalies ({})", anoms.len()),
        event_id: None,
    }];
    for a in anoms {
        lines.push(PanelLine {
            text: format!(
                "[{}|{}] {}{}",
                a.severity,
                a.kind,
                truncate(&a.detail, 100),
                a.sequence
                    .map(|s| format!(" seq={s}"))
                    .unwrap_or_default()
            ),
            event_id: a.event_id,
        });
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
        "e            Failure story (headline, evidence, anomalies)",
        "a            Anomalies only (loops, destructive, tokens…)",
        "x            Side effects (write/destructive)",
        "c            Capture quality",
        "p            Postmortem narrative",
        "h            Handoff / resume hints",
        "r            Replay guarantees (preflight)",
        "d            Diff vs previous run (trajectory LCP)",
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
        e.metadata
            .insert("ppid".into(), serde_json::json!(0));
        e.metadata.insert(
            "argv".into(),
            serde_json::json!(["grep", "hello world", "f.txt"]),
        );
        let lines = process_lines(&[e]);
        let joined = lines
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("grep"), "{joined}");
        assert!(joined.contains("hello world"), "{joined}");
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
    fn failure_story_includes_anomalies() {
        let run = sample_run();
        let mut events = Vec::new();
        for i in 0..6 {
            let mut e = ev("tool.call", EventSource::Tool, EventStatus::Success);
            e.sequence = i;
            e.metadata
                .insert("tool_name".into(), serde_json::json!("Bash"));
            e.metadata
                .insert("input".into(), serde_json::json!({ "command": "cargo test" }));
            events.push(e);
        }
        let lines = failure_story_lines(&run, &events, None);
        assert!(
            lines.iter().any(|l| l.text.contains("tool_loop") || l.text.contains("Anomal")),
            "expected loop anomaly in story: {:?}",
            lines.iter().map(|l| &l.text).collect::<Vec<_>>()
        );
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
