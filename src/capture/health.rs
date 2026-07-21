//! Structured capture-layer health events.
//!
//! Every layer should emit `capture.layer.*` events so coverage and doctor
//! report failures from first-class signals rather than log scraping.

use crate::core::event::{EventSource, EventStatus, TraceEvent};

/// Build a layer lifecycle event.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `layer_event` — see module docs for full workflow.
/// ```
pub fn layer_event(
    run_id: &str,
    layer: &str,
    phase: &str, // started | healthy | failed | stopped | lag
    status: EventStatus,
    detail: Option<&str>,
) -> TraceEvent {
    let kind = format!("capture.layer.{phase}");
    let mut ev = TraceEvent::new(run_id, EventSource::System, &kind);
    ev.status = status;
    ev.metadata.insert("layer".into(), serde_json::json!(layer));
    ev.metadata.insert("phase".into(), serde_json::json!(phase));
    if let Some(d) = detail {
        ev.metadata.insert("detail".into(), serde_json::json!(d));
        ev.metadata.insert("message".into(), serde_json::json!(d));
    }
    ev
}

/// Layer started.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `layer_started` — see module docs for full workflow.
/// ```
pub fn layer_started(run_id: &str, layer: &str) -> TraceEvent {
    layer_event(run_id, layer, "started", EventStatus::Success, None)
}

/// Layer failed.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `layer_failed` — see module docs for full workflow.
/// ```
pub fn layer_failed(run_id: &str, layer: &str, detail: &str) -> TraceEvent {
    layer_event(run_id, layer, "failed", EventStatus::Error, Some(detail))
}

/// Layer stopped.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `layer_stopped` — see module docs for full workflow.
/// ```
pub fn layer_stopped(run_id: &str, layer: &str, detail: Option<&str>) -> TraceEvent {
    layer_event(run_id, layer, "stopped", EventStatus::Success, detail)
}

/// Layer lag.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `layer_lag` — see module docs for full workflow.
/// ```
pub fn layer_lag(run_id: &str, layer: &str, detail: &str) -> TraceEvent {
    layer_event(run_id, layer, "lag", EventStatus::Error, Some(detail))
}

/// Infer per-layer failure from structured health events (preferred).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `failed_layers_from_events` — see module docs for full workflow.
/// ```
pub fn failed_layers_from_events(events: &[TraceEvent]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for ev in events {
        if ev.kind != "capture.layer.failed" && ev.kind != "capture.layer.lag" {
            continue;
        }
        let layer = ev
            .metadata
            .get("layer")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let detail = ev
            .metadata
            .get("detail")
            .or_else(|| ev.metadata.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("failed")
            .to_string();
        if !out.iter().any(|(l, _)| l == &layer) {
            out.push((layer, detail));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_layers_extracted() {
        let mut events = vec![
            layer_started("r", "pty"),
            layer_failed("r", "filesystem", "watcher died"),
            layer_stopped("r", "pty", None),
        ];
        events.push(layer_lag("r", "process", "poll backlog"));
        let failed = failed_layers_from_events(&events);
        assert_eq!(failed.len(), 2);
        assert!(failed
            .iter()
            .any(|(l, d)| l == "filesystem" && d.contains("watcher")));
        assert!(failed.iter().any(|(l, _)| l == "process"));
    }
}
