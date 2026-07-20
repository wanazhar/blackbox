//! End-of-run rollup: coverage, warnings, writer health (1.5 U1).
//!
//! Recomputable from store events + writer health without a live PTY.

use crate::capture::coverage::{adapter_tool_drought, CaptureCoverage, RunCoverageSignals};
use crate::config::NativeLogScope;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::run::Run;
use crate::pipeline::WriterHealth;

/// Inputs required to recompute end-of-run coverage for an existing run.
pub struct RollupInputs<'a> {
    pub run: &'a Run,
    pub events: &'a [TraceEvent],
    pub writer_health: WriterHealth,
    pub merge_lag: u64,
    pub merge_send_failures: u64,
    pub native_log_scope: NativeLogScope,
}

/// Derived coverage event + optional warning events (not yet persisted).
pub struct RollupOutput {
    pub coverage: CaptureCoverage,
    pub coverage_event: TraceEvent,
    pub warning_events: Vec<TraceEvent>,
    pub capture_lag_note: Option<String>,
    pub session_adapter_guess: Option<String>,
}

/// Build coverage and warning events from a stored event window.
///
/// Safe to call after recovery to re-emit or recompute coverage for a run.
pub fn build_coverage_events(input: RollupInputs<'_>) -> RollupOutput {
    let all_events = input.events;
    let run = input.run;

    let pty_events = all_events
        .iter()
        .filter(|e| e.source == EventSource::Terminal)
        .count() as u64;
    let process_events = all_events
        .iter()
        .filter(|e| e.source == EventSource::Process)
        .count() as u64;
    let git_events = all_events
        .iter()
        .filter(|e| e.source == EventSource::Git)
        .count() as u64;
    let fs_events = all_events
        .iter()
        .filter(|e| e.source == EventSource::Filesystem)
        .count() as u64;
    let env_events = all_events
        .iter()
        .filter(|e| e.kind == "environment.captured")
        .count() as u64;
    let native_log_events = all_events
        .iter()
        .filter(|e| {
            e.metadata.contains_key("native_log")
                || e.kind.starts_with("native.")
                || e.kind.starts_with("native_log.")
                || e.metadata
                    .get("source")
                    .and_then(|v| v.as_str())
                    .map(|s| s.contains("native"))
                    .unwrap_or(false)
        })
        .count() as u64;

    let structured_fails = crate::capture::health::failed_layers_from_events(all_events);
    let layer_failed = |name: &str| structured_fails.iter().any(|(l, _)| l == name);
    let layer_err_src = |src: EventSource| {
        all_events.iter().any(|e| {
            e.source == src
                && (e.status == EventStatus::Error
                    || e.kind.contains("failed")
                    || e.kind.contains("error"))
        })
    };

    let health = &input.writer_health;
    let mut capture_lag_note = health.soft_warning();
    if input.merge_lag > 0 || input.merge_send_failures > 0 {
        let merge_msg = format!(
            "capture merge lag samples={} send_failures={}",
            input.merge_lag, input.merge_send_failures
        );
        capture_lag_note = Some(match capture_lag_note {
            Some(w) => format!("{w}; {merge_msg}"),
            None => merge_msg,
        });
    }

    let tool_call_count = all_events.iter().filter(|e| e.kind == "tool.call").count() as u64;
    let adapter_guess = run
        .adapter
        .clone()
        .or_else(|| {
            run.notes.as_deref().and_then(|n| {
                n.split(';')
                    .find_map(|p| p.trim().strip_prefix("adapter:"))
                    .map(|s| s.to_string())
            })
        })
        .or_else(|| {
            Some(
                crate::adapters::detect::detect_adapter(&run.command)
                    .id()
                    .to_string(),
            )
        });

    let duration_ms = run
        .duration_ms
        .or_else(|| {
            run.ended_at
                .zip(Some(run.started_at))
                .map(|(e, s)| (e - s).num_milliseconds().max(0) as u64)
        })
        .or_else(|| {
            Some(
                (chrono::Utc::now() - run.started_at)
                    .num_milliseconds()
                    .max(0) as u64,
            )
        });

    let git_not_a_repo = all_events.iter().any(|e| e.kind == "git.not_a_repo");
    let process_observer_started = all_events
        .iter()
        .any(|e| e.kind == "process.observer.started");
    let process_root_spawned = all_events.iter().any(|e| e.kind == "process.spawned");
    let process_tree_snapshot = all_events
        .iter()
        .any(|e| e.kind == "process.tree.snapshot");
    let process_observer_stopped = all_events
        .iter()
        .any(|e| e.kind == "process.observer.stopped");
    let process_backend = all_events
        .iter()
        .find(|e| e.kind == "process.observer.started")
        .and_then(|e| {
            e.metadata
                .get("process_tree_backend")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });

    let native_logs_disabled = matches!(input.native_log_scope, NativeLogScope::Off);
    let native_logs_not_applicable = !native_logs_disabled
        && adapter_guess
            .as_deref()
            .map(|id| id.eq_ignore_ascii_case("generic"))
            .unwrap_or(false);

    let coverage = CaptureCoverage::from_run_signals(RunCoverageSignals {
        pty_events,
        process_events,
        git_events,
        fs_events,
        env_events,
        process_tree_available: true,
        native_log_events: Some(native_log_events),
        process_failed: layer_failed("process") || layer_err_src(EventSource::Process),
        pty_failed: layer_failed("pty") || layer_err_src(EventSource::Terminal),
        git_failed: layer_failed("git") || layer_err_src(EventSource::Git),
        fs_failed: layer_failed("filesystem") || layer_err_src(EventSource::Filesystem),
        capture_lag_note: capture_lag_note.clone(),
        tool_call_count,
        adapter_id: adapter_guess.clone(),
        duration_ms,
        total_events_window: all_events.len() as u64,
        git_not_a_repo,
        native_logs_not_applicable,
        native_logs_disabled,
        process_observer_started,
        process_root_spawned,
        process_tree_snapshot,
        process_observer_stopped,
        process_backend,
    });

    let mut cov_ev = TraceEvent::new(&run.id, EventSource::System, "capture.coverage");
    cov_ev.status = EventStatus::Success;
    cov_ev.metadata.insert(
        "coverage".to_string(),
        serde_json::to_value(&coverage).unwrap_or_default(),
    );
    cov_ev.metadata.insert(
        "total_events".to_string(),
        serde_json::json!(coverage.total_events),
    );
    let mut writer_health = serde_json::json!({
        "events_written": health.events_written,
        "events_deduped": health.events_deduped,
        "slow_writes": health.slow_writes,
        "max_write_ms": health.max_write_ms,
        "batched": health.batch.is_some(),
    });
    if let Some(ref b) = health.batch {
        writer_health["batch"] = serde_json::json!({
            "events_enqueued": b.events_enqueued,
            "events_flushed": b.events_flushed,
            "batches": b.batches,
            "barriers": b.barriers,
            "max_batch_size": b.max_batch_size,
            "max_flush_ms": b.max_flush_ms,
            "queue_high_water": b.queue_high_water,
            "write_failures": b.write_failures,
            "pending": b.pending,
        });
    }
    cov_ev
        .metadata
        .insert("writer_health".to_string(), writer_health);

    let mut bp = serde_json::json!({
        "merge_lag_samples": input.merge_lag,
        "merge_send_failures": input.merge_send_failures,
        "policy": "no_silent_drops_on_merge; lag samples count blocked sends ≥50ms; batch queue applies backpressure",
    });
    if let Some(ref b) = health.batch {
        bp["batch_queue_high_water"] = serde_json::json!(b.queue_high_water);
        bp["batch_write_failures"] = serde_json::json!(b.write_failures);
    }
    cov_ev.metadata.insert("backpressure".to_string(), bp);
    if let Some(ref a) = adapter_guess {
        cov_ev
            .metadata
            .insert("adapter".into(), serde_json::json!(a));
    }
    cov_ev
        .metadata
        .insert("tool_call_count".into(), serde_json::json!(tool_call_count));

    let mut warning_events = Vec::new();
    if let Some(msg) = adapter_tool_drought(&RunCoverageSignals {
        tool_call_count,
        adapter_id: adapter_guess.clone(),
        duration_ms,
        total_events_window: all_events.len() as u64,
        ..Default::default()
    }) {
        let mut warn = TraceEvent::new(&run.id, EventSource::System, "capture.warning");
        warn.status = EventStatus::Error;
        warn.metadata
            .insert("warning".into(), serde_json::json!("adapter_drought"));
        warn.metadata
            .insert("message".into(), serde_json::json!(msg));
        warning_events.push(warn);
    }

    if let Some(ref lag) = capture_lag_note {
        let mut warn = TraceEvent::new(&run.id, EventSource::System, "capture.warning");
        warn.status = EventStatus::Error;
        warn.metadata
            .insert("kind".into(), serde_json::json!("capture_lag"));
        warn.metadata
            .insert("message".into(), serde_json::json!(lag));
        warning_events.push(warn);
        warning_events.push(crate::capture::health::layer_lag(&run.id, "merge", lag));
    }

    RollupOutput {
        coverage,
        coverage_event: cov_ev,
        warning_events,
        capture_lag_note,
        session_adapter_guess: adapter_guess,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::run::Run;

    #[test]
    fn rollup_from_empty_events() {
        let run = Run::new(vec!["true".into()], "/tmp".into());
        let out = build_coverage_events(RollupInputs {
            run: &run,
            events: &[],
            writer_health: WriterHealth::default(),
            merge_lag: 0,
            merge_send_failures: 0,
            native_log_scope: NativeLogScope::Project,
        });
        assert_eq!(out.coverage_event.kind, "capture.coverage");
    }
}
