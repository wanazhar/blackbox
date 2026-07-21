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
/// `RunsView` value.
pub struct RunsView {
    /// Runs.
    pub runs: Vec<RunSummaryView>,
}

#[derive(Debug, Serialize)]
/// `RunSummaryView` value.
pub struct RunSummaryView {
    /// Unique identifier.
    pub id: String,
    /// Short id.
    pub short_id: String,
    /// Display name.
    pub name: Option<String>,
    /// Status value.
    pub status: RunStatus,
    /// Process exit code, if known.
    pub exit_code: Option<i32>,
    /// Command argv.
    pub command: Vec<String>,
    /// Working directory.
    pub cwd: String,
    /// Start timestamp.
    pub started_at: DateTime<Utc>,
    /// End timestamp, if finished.
    pub ended_at: Option<DateTime<Utc>>,
    /// Associated tags.
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Event count.
    pub event_count: Option<usize>,
}

impl RunSummaryView {
    /// Build from run.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_run` — see module docs for full workflow.
    /// ```
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
/// `ShowView` value.
pub struct ShowView {
    /// Run.
    pub run: Run,
    /// Event count.
    pub event_count: usize,
    /// Checkpoint count.
    pub checkpoint_count: usize,
    /// Tool calls.
    pub tool_calls: Vec<ToolCallSummary>,
    /// Error event count.
    pub error_event_count: usize,
    /// Structured error count.
    pub structured_error_count: usize,
    /// Filesystem event count.
    pub filesystem_event_count: usize,
    /// Resume.
    pub resume: ResumeView,
    /// Hints.
    pub hints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Tool transcript.
    pub tool_transcript: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Terminal transcript.
    pub terminal_transcript: Option<String>,
    /// Capture coverage when a `capture.coverage` event exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_coverage: Option<serde_json::Value>,
    /// Reconstructed process tree forest (ASCII + node counts) when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_tree: Option<ProcessTreeShowView>,
}

#[derive(Debug, Serialize)]
/// `ProcessTreeShowView` value.
pub struct ProcessTreeShowView {
    /// Root count.
    pub root_count: usize,
    /// Node count.
    pub node_count: usize,
    /// Ascii.
    pub ascii: String,
}

#[derive(Debug, Serialize)]
/// `ToolCallSummary` value.
pub struct ToolCallSummary {
    /// Monotonic sequence number within the run.
    pub sequence: u64,
    /// Tool name.
    pub tool_name: String,
}

#[derive(Debug, Clone, Serialize)]
/// `ResumeView` value.
pub struct ResumeView {
    /// Available.
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Command argv.
    pub command: Option<Vec<String>>,
}

// ── timeline ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
/// `TimelineView` value.
pub struct TimelineView {
    /// Owning run id.
    pub run_id: String,
    /// Semantic.
    pub semantic: bool,
    /// Events.
    pub events: Vec<TimelineEventView>,
    /// Truncated.
    pub truncated: bool,
    /// Total matched.
    pub total_matched: usize,
}

#[derive(Debug, Serialize)]
/// `TimelineEventView` value.
pub struct TimelineEventView {
    /// Unique identifier.
    pub id: String,
    /// Monotonic sequence number within the run.
    pub sequence: u64,
    /// Event source.
    pub source: EventSource,
    /// Event or item kind string.
    pub kind: String,
    /// Status value.
    pub status: EventStatus,
    /// Side effect.
    pub side_effect: SideEffect,
    /// Start timestamp.
    pub started_at: DateTime<Utc>,
    /// Duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// Detail.
    pub detail: String,
    /// Metadata preview.
    pub metadata_preview: HashMap<String, serde_json::Value>,
}

impl TimelineEventView {
    /// Build from event.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_event` — see module docs for full workflow.
    /// ```
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
/// `InspectView` value.
pub struct InspectView {
    /// Owning run id.
    pub run_id: String,
    /// Event.
    pub event: TraceEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Blob text.
    pub blob_text: Option<String>,
}

// ── analyze ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
/// `AnalyzeView` value.
pub struct AnalyzeView {
    /// Owning run id.
    pub run_id: String,
    /// Derived count.
    pub derived_count: usize,
    /// Structured errors.
    pub structured_errors: Vec<StructuredErrorView>,
    /// By kind.
    pub by_kind: HashMap<String, usize>,
    /// Samples.
    pub samples: Vec<DerivedSampleView>,
    /// Persisted.
    pub persisted: bool,
}

#[derive(Debug, Clone, Serialize)]
/// `StructuredErrorView` value.
pub struct StructuredErrorView {
    /// Monotonic sequence number within the run.
    pub sequence: u64,
    /// Error type.
    pub error_type: String,
    /// Message.
    pub message: String,
    /// File.
    pub file: Option<String>,
    /// Line.
    pub line: Option<u32>,
}

#[derive(Debug, Serialize)]
/// `DerivedSampleView` value.
pub struct DerivedSampleView {
    /// Event or item kind string.
    pub kind: String,
    /// Monotonic sequence number within the run.
    pub sequence: u64,
    /// Side effect.
    pub side_effect: SideEffect,
    /// Detail.
    pub detail: String,
}

// ── search ────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
/// `SearchView` value.
pub struct SearchView {
    /// Query.
    pub query: String,
    /// Hits.
    pub hits: Vec<SearchHitView>,
    /// Truncated.
    pub truncated: bool,
    /// Backend.
    pub backend: String,
    /// Max runs scanned.
    pub max_runs_scanned: usize,
}

#[derive(Debug, Serialize)]
/// `SearchHitView` value.
pub struct SearchHitView {
    /// Owning run id.
    pub run_id: String,
    /// Short run id.
    pub short_run_id: String,
    /// Event id.
    pub event_id: Option<String>,
    /// Score.
    pub score: f64,
    /// Event or item kind string.
    pub kind: String,
    /// Monotonic sequence number within the run.
    pub sequence: Option<u64>,
    /// Snippet.
    pub snippet: String,
}

// ── stats ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
/// `StatsView` value.
pub struct StatsView {
    /// Db path.
    pub db_path: String,
    /// Blob dir.
    pub blob_dir: String,
    /// Run count.
    pub run_count: usize,
    /// Tagged run count.
    pub tagged_run_count: usize,
    /// By status.
    pub by_status: HashMap<String, usize>,
    /// By adapter.
    pub by_adapter: HashMap<String, usize>,
    /// Sample run count.
    pub sample_run_count: usize,
    /// Total events.
    pub total_events: usize,
    /// Total tool calls.
    pub total_tool_calls: usize,
    /// Total errors.
    pub total_errors: usize,
    /// Average events per sampled run (WS6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_events_per_run: Option<f64>,
    /// Average blob bytes per run when run_count > 0 (WS6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_blob_bytes_per_run: Option<f64>,
    /// Top kinds.
    pub top_kinds: Vec<(String, usize)>,
    /// Blob files.
    pub blob_files: usize,
    /// Blob bytes.
    pub blob_bytes: u64,
    /// SQLite file size when available (1.1 A4).
    pub db_bytes: Option<u64>,
    /// Total storage bytes.
    pub total_storage_bytes: Option<u64>,
    /// Storage warning.
    pub storage_warning: Option<String>,
}

// ── doctor ────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
/// `DoctorView` value.
pub struct DoctorView {
    /// Version string or number.
    pub version: String,
    /// Schema version.
    pub schema_version: u32,
    /// Db path.
    pub db_path: String,
    /// Blob dir.
    pub blob_dir: String,
    /// Db exists.
    pub db_exists: bool,
    /// Blob dir exists.
    pub blob_dir_exists: bool,
    /// Project root.
    pub project_root: String,
    /// Store size bytes.
    pub store_size_bytes: Option<u64>,
    /// Best-effort sum of files under blob dir (1.1 A4).
    pub blob_bytes: Option<u64>,
    /// Blob files.
    pub blob_files: Option<usize>,
    /// db + blobs when both known.
    pub total_storage_bytes: Option<u64>,
    /// Soft warning when storage is large (human + agents).
    pub storage_warning: Option<String>,
    /// Run count.
    pub run_count: Option<usize>,
    /// Running count.
    pub running_count: Option<usize>,
    /// Fts5.
    pub fts5: String,
    /// Secrets clean.
    pub secrets_clean: Option<bool>,
    /// Config.
    pub config: DoctorConfigView,
    /// Shell integration hint.
    pub shell_integration_hint: String,
    /// Blackbox on path.
    pub blackbox_on_path: bool,
    // 1.2 memory plane (M7)
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Continuity mode.
    pub continuity_mode: Option<String>,
    /// Hard observe-only mode (no launch mutation / continuity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observe_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Memory file present.
    pub memory_file_present: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Memory age secs.
    pub memory_age_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Claims active.
    pub claims_active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Unresolved failure id.
    pub unresolved_failure_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Attention level.
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
    /// Whether hard recorder neutrality (no child-visible BLACKBOX_* inject) is supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorder_neutrality_supported: Option<bool>,
    /// Nest guard implementation note (1.4 N1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nest_guard: Option<String>,
}

#[derive(Debug, Serialize)]
/// `DoctorConfigView` value.
pub struct DoctorConfigView {
    /// Present.
    pub present: bool,
    /// Enabled.
    pub enabled: Option<bool>,
    /// Wrap.
    pub wrap: Option<Vec<String>>,
    /// Retention.
    pub retention: Option<DoctorRetentionView>,
}

#[derive(Debug, Serialize)]
/// `DoctorRetentionView` value.
pub struct DoctorRetentionView {
    /// Keep runs.
    pub keep_runs: u32,
    /// Max age days.
    pub max_age_days: Option<u32>,
    /// Auto apply.
    pub auto_apply: bool,
}
