use std::time::Instant;

use tracing;

use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::terminal::{TerminalRecorder, TerminalSegment};

/// Maximum number of segments a RawRecorder will retain.
/// When exceeded, the oldest segments are dropped with a warning.
/// M-16: This cap prevents unbounded memory growth during long-running
/// sessions.  At 10_000 segments with an average segment size of a few
/// KiB, worst-case memory is well under 100 MiB — acceptable for a
/// local CLI tool.  The cap is intentionally conservative.
const MAX_SEGMENTS: usize = 10_000;

/// Raw terminal I/O recorder.
///
/// Captures every byte written to and read from the PTY,
/// storing both the raw stream and derived timestamps.
/// Normalization is handled by the caller pipeline (run.rs),
/// not here — this avoids double-normalization.
pub struct RawRecorder {
    run_id: Option<String>,
    segments: Vec<TerminalSegment>,
    start: Option<Instant>,
}

impl RawRecorder {
    pub fn new() -> Self {
        Self {
            run_id: None,
            segments: Vec::new(),
            start: None,
        }
    }

    /// Drop oldest segments when we exceed the cap, logging a warning.
    fn evict_if_over_limit(&mut self) {
        if self.segments.len() > MAX_SEGMENTS {
            let excess = self.segments.len() - MAX_SEGMENTS;
            self.segments.drain(..excess);
            tracing::warn!(
                dropped = excess,
                remaining = self.segments.len(),
                "RawRecorder segment cap exceeded; dropped oldest segments"
            );
        }
    }

    /// Number of recorded segments.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Total raw bytes recorded.
    pub fn total_bytes(&self) -> usize {
        self.segments.iter().map(|s| s.raw_data.len()).sum()
    }
}

impl Default for RawRecorder {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl TerminalRecorder for RawRecorder {
    async fn start(&mut self, run_id: &str) -> anyhow::Result<()> {
        self.run_id = Some(run_id.to_string());
        self.segments.clear();
        self.start = Some(Instant::now());
        Ok(())
    }

    async fn write_input(&mut self, data: &[u8]) -> anyhow::Result<()> {
        // Record user keystrokes as zero-length-normalized segments tagged in metadata
        // via a terminal.input event at stop time if needed. For now just track bytes.
        let offset_ms = self
            .start
            .map(|s| s.elapsed().as_millis() as u64)
            .unwrap_or(0);
        let seg = TerminalSegment {
            offset_ms,
            raw_data: data.to_vec(),
            normalized_text: String::new(), // input is not normalized
        };
        self.segments.push(seg);
        self.evict_if_over_limit();
        Ok(())
    }

    async fn record_output(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let offset_ms = self
            .start
            .map(|s| s.elapsed().as_millis() as u64)
            .unwrap_or(0);
        // NOTE: Normalization is done by the caller (run.rs) which has access to
        // the full pipeline. We store raw data here only.
        let seg = TerminalSegment {
            offset_ms,
            raw_data: data.to_vec(),
            normalized_text: String::new(),
        };
        self.segments.push(seg);
        self.evict_if_over_limit();
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<Vec<TraceEvent>> {
        let mut events = Vec::new();
        if let Some(run_id) = &self.run_id {
            let mut ev = TraceEvent::new(run_id, EventSource::Terminal, "terminal.recording");
            ev.status = EventStatus::Success;
            ev.metadata.insert(
                "segments".to_string(),
                serde_json::json!(self.segments.len()),
            );
            ev.metadata.insert(
                "bytes".to_string(),
                serde_json::json!(self.total_bytes()),
            );
            events.push(ev);
        }
        Ok(events)
    }
}

