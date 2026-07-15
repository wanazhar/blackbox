//! Failure-to-fix correlation pass.
//!
//! Connects errors with subsequent file changes and retries to identify
//! causal repair chains in a run trace.

use std::collections::HashMap;

use crate::analysis::AnalysisPass;
use crate::core::event::{Confidence, EventSource, EventStatus, TraceEvent};

/// A single failure-to-fix correlation chain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FailureFixChain {
    /// The error event that triggered the chain.
    pub error_event_id: String,
    /// The error message or kind.
    pub error_message: String,
    /// File changes that occurred after the error (as fix attempts).
    pub files_changed: Vec<String>,
    /// Whether a retry occurred after the file changes.
    pub retry_occurred: bool,
    /// Whether the retry was successful.
    pub retry_successful: Option<bool>,
    /// Confidence in the correlation.
    pub confidence: Confidence,
}

/// Correlates errors with subsequent file modifications and retries.
pub struct FailureFixCorrelator;

impl Default for FailureFixCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl FailureFixCorrelator {
    pub fn new() -> Self {
        Self
    }

    /// Find failure-to-fix chains in a batch of events.
    ///
    /// Scans for:
    /// 1. Error events (tool failures, process errors)
    /// 2. File changes that follow within a window
    /// 3. Retry attempts (same tool call after file changes)
    /// 4. Success signals after retries
    pub fn find_chains(&self, events: &[TraceEvent]) -> Vec<FailureFixChain> {
        let mut chains = Vec::new();
        let error_window_ms = 30_000;

        let error_indices: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.status == EventStatus::Error
                    || e.metadata
                        .get("exit_code")
                        .and_then(|v| v.as_i64())
                        .map(|c| c != 0)
                        .unwrap_or(false)
            })
            .map(|(i, _)| i)
            .collect();

        for &err_idx in &error_indices {
            let error_event = &events[err_idx];
            let error_time = error_event.started_at;

            let error_message = error_event
                .metadata
                .get("message")
                .or_else(|| error_event.metadata.get("error_message"))
                .or_else(|| error_event.metadata.get("stderr"))
                .and_then(|v| v.as_str())
                .map(|s| {
                    if s.len() > 200 {
                        format!("{}...", &s[..s.floor_char_boundary(200)])
                    } else {
                        s.to_string()
                    }
                })
                .unwrap_or_else(|| format!("{:?}", error_event.status));
            // Collect file changes after the error (within 30s window)
            let mut files_changed: Vec<String> = Vec::new();
            let mut retry_occurred = false;
            let mut retry_successful: Option<bool> = None;
            let mut latest_fs_time = error_time;

            for j in (err_idx + 1)..events.len() {
                let ev = &events[j];
                let gap = ev
                    .started_at
                    .signed_duration_since(error_time)
                    .num_milliseconds();

                if gap > error_window_ms as i64 {
                    break;
                }

                if ev.source == EventSource::Filesystem
                    && !ev.kind.contains("observer")
                    && !ev.kind.contains("snapshot")
                {
                    if let Some(path) = ev.metadata.get("path").and_then(|v| v.as_str()) {
                        if !files_changed.iter().any(|f| f == path) {
                            files_changed.push(path.to_string());
                        }
                    }
                    if ev.started_at > latest_fs_time {
                        latest_fs_time = ev.started_at;
                    }
                }

                if ev.kind == "tool.call" && !files_changed.is_empty() {
                    let call_gap = ev
                        .started_at
                        .signed_duration_since(latest_fs_time)
                        .num_milliseconds();
                    if call_gap >= 0 && call_gap < error_window_ms as i64 {
                        retry_occurred = true;
                        for after in events.iter().skip(j + 1).take(20) {
                            if after.kind == "tool.result" && after.status == EventStatus::Success {
                                retry_successful = Some(true);
                                break;
                            }
                            if after.kind == "tool.result" && after.status == EventStatus::Error {
                                retry_successful = Some(false);
                            }
                        }
                    }
                }
            }

            if !files_changed.is_empty() || retry_occurred {
                let confidence = if retry_successful == Some(true) {
                    Confidence::Confirmed
                } else if retry_occurred {
                    Confidence::StronglyCorrelated
                } else {
                    Confidence::WeaklyCorrelated
                };

                chains.push(FailureFixChain {
                    error_event_id: error_event.id.clone(),
                    error_message,
                    files_changed,
                    retry_occurred,
                    retry_successful,
                    confidence,
                });
            }
        }

        chains
    }
}

#[async_trait::async_trait]
impl AnalysisPass for FailureFixCorrelator {
    fn name(&self) -> &'static str {
        "failure_fix"
    }

    async fn analyze(&self, events: &[TraceEvent]) -> anyhow::Result<Vec<TraceEvent>> {
        let chains = self.find_chains(events);
        let mut derived = Vec::with_capacity(chains.len());

        for chain in &chains {
            let mut meta = HashMap::new();
            meta.insert(
                "error_event_id".to_string(),
                serde_json::Value::String(chain.error_event_id.clone()),
            );
            meta.insert(
                "error_message".to_string(),
                serde_json::Value::String(chain.error_message.clone()),
            );
            meta.insert(
                "files_changed".to_string(),
                serde_json::to_value(&chain.files_changed).unwrap_or_default(),
            );
            meta.insert(
                "retry_occurred".to_string(),
                serde_json::Value::Bool(chain.retry_occurred),
            );
            if let Some(success) = chain.retry_successful {
                meta.insert(
                    "retry_successful".to_string(),
                    serde_json::Value::Bool(success),
                );
            }
            meta.insert(
                "confidence".to_string(),
                serde_json::Value::String(format!("{:?}", chain.confidence)),
            );

            let mut ev = TraceEvent::new(
                events.first().map(|e| e.run_id.as_str()).unwrap_or(""),
                EventSource::System,
                "analysis.failure_to_fix",
            );
            ev.metadata = meta;
            ev.status = EventStatus::Success;
            derived.push(ev);
        }

        Ok(derived)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn make_event(
        kind: &str,
        source: EventSource,
        status: EventStatus,
        meta: Vec<(&str, serde_json::Value)>,
        started_at: chrono::DateTime<Utc>,
    ) -> TraceEvent {
        let mut ev = TraceEvent::new("run-1", source, kind);
        ev.status = status;
        for (k, v) in meta {
            ev.metadata.insert(k.to_string(), v);
        }
        ev.started_at = started_at;
        ev
    }

    #[test]
    fn empty_events_no_chains() {
        let corr = FailureFixCorrelator::new();
        let chains = corr.find_chains(&[]);
        assert!(chains.is_empty());
    }

    #[test]
    fn no_errors_no_chains() {
        let t0 = Utc::now();
        let ev = make_event(
            "tool.call",
            EventSource::Tool,
            EventStatus::Success,
            vec![("tool_name", serde_json::json!("Bash"))],
            t0,
        );
        let chains = FailureFixCorrelator::new().find_chains(&[ev]);
        assert!(chains.is_empty());
    }

    #[test]
    fn error_with_file_change_creates_chain() {
        let t0 = Utc::now();
        let err = make_event(
            "tool.result",
            EventSource::Tool,
            EventStatus::Error,
            vec![("message", serde_json::json!("compilation error"))],
            t0,
        );
        let file_change = make_event(
            "filesystem.modified",
            EventSource::Filesystem,
            EventStatus::Success,
            vec![("path", serde_json::json!("src/main.rs"))],
            t0 + Duration::milliseconds(500),
        );
        let chains = FailureFixCorrelator::new().find_chains(&[err, file_change]);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].files_changed, vec!["src/main.rs"]);
    }

    #[test]
    fn error_with_retry_success_creates_confirmed_chain() {
        let t0 = Utc::now();
        let err = make_event(
            "tool.result",
            EventSource::Tool,
            EventStatus::Error,
            vec![("message", serde_json::json!("error"))],
            t0,
        );
        let file_change = make_event(
            "filesystem.modified",
            EventSource::Filesystem,
            EventStatus::Success,
            vec![("path", serde_json::json!("src/lib.rs"))],
            t0 + Duration::milliseconds(500),
        );
        let retry = make_event(
            "tool.call",
            EventSource::Tool,
            EventStatus::Success,
            vec![("tool_name", serde_json::json!("Bash"))],
            t0 + Duration::milliseconds(1000),
        );
        let success = make_event(
            "tool.result",
            EventSource::Tool,
            EventStatus::Success,
            vec![],
            t0 + Duration::milliseconds(1500),
        );
        let chains = FailureFixCorrelator::new().find_chains(&[err, file_change, retry, success]);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].confidence, Confidence::Confirmed);
        assert_eq!(chains[0].retry_successful, Some(true));
    }

    #[test]
    fn error_outside_window_ignored() {
        let t0 = Utc::now();
        let err = make_event(
            "tool.result",
            EventSource::Tool,
            EventStatus::Error,
            vec![],
            t0,
        );
        let late_change = make_event(
            "filesystem.modified",
            EventSource::Filesystem,
            EventStatus::Success,
            vec![("path", serde_json::json!("x.rs"))],
            t0 + Duration::milliseconds(35_000),
        );
        let chains = FailureFixCorrelator::new().find_chains(&[err, late_change]);
        assert_eq!(chains.len(), 0);
    }
}
