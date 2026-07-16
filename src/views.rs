//! Shared serde view types for CLI `--json` and (later) serve HTTP.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};
use crate::core::run::{Run, RunStatus};

fn short_id(id: &str) -> String {
    id[..8.min(id.len())].to_string()
}

// ── runs ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct RunsView {
    pub runs: Vec<RunSummaryView>,
}

#[derive(Debug, Serialize)]
pub struct RunSummaryView {
    pub id: String,
    pub short_id: String,
    pub name: Option<String>,
    pub status: RunStatus,
    pub exit_code: Option<i32>,
    pub command: Vec<String>,
    pub cwd: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_count: Option<usize>,
}

impl RunSummaryView {
    pub fn from_run(run: &Run) -> Self {
        Self {
            id: run.id.clone(),
            short_id: short_id(&run.id),
            name: run.name.clone(),
            status: run.status.clone(),
            exit_code: run.exit_code,
            command: run.command.clone(),
            cwd: run.cwd.clone(),
            started_at: run.started_at,
            ended_at: run.ended_at,
            tags: run.tags.clone(),
            event_count: None,
        }
    }
}

// ── show ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ShowView {
    pub run: Run,
    pub event_count: usize,
    pub checkpoint_count: usize,
    pub tool_calls: Vec<ToolCallSummary>,
    pub error_event_count: usize,
    pub structured_error_count: usize,
    pub filesystem_event_count: usize,
    pub resume: ResumeView,
    pub hints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_transcript: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_transcript: Option<String>,
    /// Capture coverage when a `capture.coverage` event exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_coverage: Option<serde_json::Value>,
    /// Reconstructed process tree forest (ASCII + node counts) when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_tree: Option<ProcessTreeShowView>,
}

#[derive(Debug, Serialize)]
pub struct ProcessTreeShowView {
    pub root_count: usize,
    pub node_count: usize,
    pub ascii: String,
}

#[derive(Debug, Serialize)]
pub struct ToolCallSummary {
    pub sequence: u64,
    pub tool_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResumeView {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
}

// ── timeline ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TimelineView {
    pub run_id: String,
    pub semantic: bool,
    pub events: Vec<TimelineEventView>,
    pub truncated: bool,
    pub total_matched: usize,
}

#[derive(Debug, Serialize)]
pub struct TimelineEventView {
    pub id: String,
    pub sequence: u64,
    pub source: EventSource,
    pub kind: String,
    pub status: EventStatus,
    pub side_effect: SideEffect,
    pub started_at: DateTime<Utc>,
    pub duration_ms: Option<u64>,
    pub detail: String,
    pub metadata_preview: HashMap<String, serde_json::Value>,
}

impl TimelineEventView {
    pub fn from_event(ev: &TraceEvent, detail: String) -> Self {
        // Cap metadata for JSON agents (keys only + short values)
        let mut metadata_preview = HashMap::new();
        for (k, v) in ev.metadata.iter().take(12) {
            let clipped = match v {
                serde_json::Value::String(s) if s.len() > 120 => {
                    let end = s.floor_char_boundary(120);
                    serde_json::Value::String(format!("{}…", &s[..end]))
                }
                other => other.clone(),
            };
            metadata_preview.insert(k.clone(), clipped);
        }
        Self {
            id: ev.id.clone(),
            sequence: ev.sequence,
            source: ev.source.clone(),
            kind: ev.kind.clone(),
            status: ev.status.clone(),
            side_effect: ev.side_effect.clone(),
            started_at: ev.started_at,
            duration_ms: ev.duration_ms,
            detail,
            metadata_preview,
        }
    }
}

// ── inspect ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct InspectView {
    pub run_id: String,
    pub event: TraceEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_text: Option<String>,
}

// ── analyze ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AnalyzeView {
    pub run_id: String,
    pub derived_count: usize,
    pub structured_errors: Vec<StructuredErrorView>,
    pub by_kind: HashMap<String, usize>,
    pub samples: Vec<DerivedSampleView>,
    pub persisted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StructuredErrorView {
    pub sequence: u64,
    pub error_type: String,
    pub message: String,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct DerivedSampleView {
    pub kind: String,
    pub sequence: u64,
    pub side_effect: SideEffect,
    pub detail: String,
}

// ── search ────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct SearchView {
    pub query: String,
    pub hits: Vec<SearchHitView>,
    pub truncated: bool,
    pub backend: String,
    pub max_runs_scanned: usize,
}

#[derive(Debug, Serialize)]
pub struct SearchHitView {
    pub run_id: String,
    pub short_run_id: String,
    pub event_id: Option<String>,
    pub score: f64,
    pub kind: String,
    pub sequence: Option<u64>,
    pub snippet: String,
}

// ── stats ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct StatsView {
    pub db_path: String,
    pub blob_dir: String,
    pub run_count: usize,
    pub tagged_run_count: usize,
    pub by_status: HashMap<String, usize>,
    pub by_adapter: HashMap<String, usize>,
    pub sample_run_count: usize,
    pub total_events: usize,
    pub total_tool_calls: usize,
    pub total_errors: usize,
    /// Average events per sampled run (WS6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_events_per_run: Option<f64>,
    /// Average blob bytes per run when run_count > 0 (WS6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_blob_bytes_per_run: Option<f64>,
    pub top_kinds: Vec<(String, usize)>,
    pub blob_files: usize,
    pub blob_bytes: u64,
    /// SQLite file size when available (1.1 A4).
    pub db_bytes: Option<u64>,
    pub total_storage_bytes: Option<u64>,
    pub storage_warning: Option<String>,
}

// ── doctor ────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DoctorView {
    pub version: String,
    pub schema_version: u32,
    pub db_path: String,
    pub blob_dir: String,
    pub db_exists: bool,
    pub blob_dir_exists: bool,
    pub project_root: String,
    pub store_size_bytes: Option<u64>,
    /// Best-effort sum of files under blob dir (1.1 A4).
    pub blob_bytes: Option<u64>,
    pub blob_files: Option<usize>,
    /// db + blobs when both known.
    pub total_storage_bytes: Option<u64>,
    /// Soft warning when storage is large (human + agents).
    pub storage_warning: Option<String>,
    pub run_count: Option<usize>,
    pub running_count: Option<usize>,
    pub fts5: String,
    pub secrets_clean: Option<bool>,
    pub config: DoctorConfigView,
    pub shell_integration_hint: String,
    pub blackbox_on_path: bool,
    // 1.2 memory plane (M7)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuity_mode: Option<String>,
    /// Hard observe-only mode (no launch mutation / continuity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observe_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_file_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_age_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unresolved_failure_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attention_level: Option<String>,
    /// Soft daily-driver readiness (0–100) for ambient trust.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_driver_score: Option<u8>,
    /// True when score ≥ 80 and no hard trust blockers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_driver_ready: Option<bool>,
    /// Human reasons affecting the score (soft).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub daily_driver_notes: Vec<String>,
    /// Last run capture quality score when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_capture_quality: Option<u8>,
}

#[derive(Debug, Serialize)]
pub struct DoctorConfigView {
    pub present: bool,
    pub enabled: Option<bool>,
    pub wrap: Option<Vec<String>>,
    pub retention: Option<DoctorRetentionView>,
}

#[derive(Debug, Serialize)]
pub struct DoctorRetentionView {
    pub keep_runs: u32,
    pub max_age_days: Option<u32>,
    pub auto_apply: bool,
}
