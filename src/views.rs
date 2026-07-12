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
    pub top_kinds: Vec<(String, usize)>,
    pub blob_files: usize,
    pub blob_bytes: u64,
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
    pub run_count: Option<usize>,
    pub running_count: Option<usize>,
    pub fts5: String,
    pub secrets_clean: Option<bool>,
    pub config: DoctorConfigView,
    pub shell_integration_hint: String,
    pub blackbox_on_path: bool,
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
}
