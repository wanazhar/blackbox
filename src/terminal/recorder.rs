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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_starts_empty() {
        let r = RawRecorder::new();
        assert_eq!(r.segment_count(), 0);
        assert_eq!(r.total_bytes(), 0);
    }

    #[tokio::test]
    async fn start_sets_run_id() {
        let mut r = RawRecorder::new();
        r.start("run-1").await.unwrap();
        assert_eq!(r.run_id, Some("run-1".into()));
        assert!(r.start.is_some());
    }

    #[tokio::test]
    async fn record_output_adds_segment() {
        let mut r = RawRecorder::new();
        r.start("run-1").await.unwrap();
        r.record_output(b"hello").await.unwrap();
        assert_eq!(r.segment_count(), 1);
        assert_eq!(r.total_bytes(), 5);
        assert_eq!(r.segments[0].raw_data, b"hello");
    }

    #[tokio::test]
    async fn write_input_adds_segment() {
        let mut r = RawRecorder::new();
        r.start("run-1").await.unwrap();
        r.write_input(b"user typed this").await.unwrap();
        assert_eq!(r.segment_count(), 1);
        assert_eq!(r.total_bytes(), 15);
    }

    #[tokio::test]
    async fn multiple_records_increment_counts() {
        let mut r = RawRecorder::new();
        r.start("run-1").await.unwrap();
        r.record_output(b"a").await.unwrap();
        r.record_output(b"bc").await.unwrap();
        r.record_output(b"def").await.unwrap();
        assert_eq!(r.segment_count(), 3);
        assert_eq!(r.total_bytes(), 6);
    }

    #[tokio::test]
    async fn stop_before_start_returns_empty() {
        let mut r = RawRecorder::new();
        let events = r.stop().await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn stop_returns_metadata_event() {
        let mut r = RawRecorder::new();
        r.start("run-1").await.unwrap();
        r.record_output(b"data").await.unwrap();
        let events = r.stop().await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "terminal.recording");
        assert_eq!(events[0].metadata.get("segments").unwrap(), 1);
        assert_eq!(events[0].metadata.get("bytes").unwrap(), 4);
    }

    #[tokio::test]
    async fn eviction_removes_oldest_on_overflow() {
        let mut r = RawRecorder::new();
        r.start("run-1").await.unwrap();
        // Fill up to MAX_SEGMENTS then add one more
        for i in 0..MAX_SEGMENTS + 1 {
            r.record_output(&[i as u8]).await.unwrap();
        }
        assert!(r.segment_count() <= MAX_SEGMENTS);
        // Oldest segment should be gone; newest should remain
        let first_remaining = r.segments.first().unwrap();
        assert_eq!(first_remaining.raw_data[0], 1); // index 0 evicted, index 1 is now first
    }

    #[tokio::test]
    async fn start_clears_previous_segments() {
        let mut r = RawRecorder::new();
        r.start("run-1").await.unwrap();
        r.record_output(b"old data").await.unwrap();
        assert_eq!(r.segment_count(), 1);
        // Restart should clear
        r.start("run-2").await.unwrap();
        assert_eq!(r.segment_count(), 0);
        assert_eq!(r.run_id, Some("run-2".into()));
    }
}

