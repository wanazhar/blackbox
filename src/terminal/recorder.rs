use std::time::Instant;

use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::terminal::{TerminalRecorder, TerminalSegment};

/// Maximum number of recent segments retained for debug sampling.
/// Default mode is counters-only (no raw retention) to keep RAM low.
const MAX_SAMPLE_SEGMENTS: usize = 8;
/// Max bytes kept per sample segment (prefix only).
const MAX_SAMPLE_BYTES: usize = 256;

/// Raw terminal I/O recorder (lightweight).
///
/// Default: **counters only** — does not retain full PTY history in RAM.
/// Optional sample ring keeps a few tiny prefixes for debugging if enabled.
///
/// Persistence of terminal content is the coalescer → blob path in `run.rs`,
/// not this recorder. Keeping full raw streams here previously cost tens of
/// MiB on long sessions with no product benefit (stop only emitted counts).
pub struct RawRecorder {
    run_id: Option<String>,
    segment_count: u64,
    total_bytes: u64,
    /// Optional tiny sample ring (empty unless `retain_samples`).
    samples: Vec<TerminalSegment>,
    retain_samples: bool,
    start: Option<Instant>,
}

impl RawRecorder {
    pub fn new() -> Self {
        Self {
            run_id: None,
            segment_count: 0,
            total_bytes: 0,
            samples: Vec::new(),
            retain_samples: false,
            start: None,
        }
    }

    /// Enable tiny sample retention (debug only; still capped).
    pub fn with_samples(mut self) -> Self {
        self.retain_samples = true;
        self
    }

    fn push_sample(&mut self, data: &[u8], offset_ms: u64) {
        if !self.retain_samples {
            return;
        }
        let end = data.len().min(MAX_SAMPLE_BYTES);
        self.samples.push(TerminalSegment {
            offset_ms,
            raw_data: data[..end].to_vec(),
            normalized_text: String::new(),
        });
        if self.samples.len() > MAX_SAMPLE_SEGMENTS {
            let excess = self.samples.len() - MAX_SAMPLE_SEGMENTS;
            self.samples.drain(..excess);
        }
    }

    /// Number of recorded segments (logical count, not retained samples).
    pub fn segment_count(&self) -> usize {
        self.segment_count as usize
    }

    /// Total raw bytes observed.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes as usize
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
        self.segment_count = 0;
        self.total_bytes = 0;
        self.samples.clear();
        self.start = Some(Instant::now());
        Ok(())
    }

    async fn write_input(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let offset_ms = self
            .start
            .map(|s| s.elapsed().as_millis() as u64)
            .unwrap_or(0);
        self.segment_count = self.segment_count.saturating_add(1);
        self.total_bytes = self.total_bytes.saturating_add(data.len() as u64);
        self.push_sample(data, offset_ms);
        Ok(())
    }

    async fn record_output(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let offset_ms = self
            .start
            .map(|s| s.elapsed().as_millis() as u64)
            .unwrap_or(0);
        self.segment_count = self.segment_count.saturating_add(1);
        self.total_bytes = self.total_bytes.saturating_add(data.len() as u64);
        self.push_sample(data, offset_ms);
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<Vec<TraceEvent>> {
        let mut events = Vec::new();
        if let Some(run_id) = &self.run_id {
            let mut ev = TraceEvent::new(run_id, EventSource::Terminal, "terminal.recording");
            ev.status = EventStatus::Success;
            ev.metadata.insert(
                "segments".to_string(),
                serde_json::json!(self.segment_count),
            );
            ev.metadata
                .insert("bytes".to_string(), serde_json::json!(self.total_bytes));
            ev.metadata.insert(
                "samples_retained".to_string(),
                serde_json::json!(self.samples.len()),
            );
            events.push(ev);
        }
        // Drop samples after stop to free any residual RAM.
        self.samples.clear();
        self.samples.shrink_to_fit();
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
    async fn record_output_counts_without_retaining_full_body() {
        let mut r = RawRecorder::new();
        r.start("run-1").await.unwrap();
        r.record_output(b"hello").await.unwrap();
        assert_eq!(r.segment_count(), 1);
        assert_eq!(r.total_bytes(), 5);
        // Default: no sample retention → low RAM
        assert!(r.samples.is_empty());
    }

    #[tokio::test]
    async fn write_input_counts() {
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
        r.record_output(b"bb").await.unwrap();
        r.record_output(b"ccc").await.unwrap();
        assert_eq!(r.segment_count(), 3);
        assert_eq!(r.total_bytes(), 6);
    }

    #[tokio::test]
    async fn samples_capped_when_enabled() {
        let mut r = RawRecorder::new().with_samples();
        r.start("run-1").await.unwrap();
        for i in 0..20 {
            r.record_output(format!("chunk-{i}").as_bytes()).await.unwrap();
        }
        assert_eq!(r.segment_count(), 20);
        assert!(r.samples.len() <= MAX_SAMPLE_SEGMENTS);
    }

    #[tokio::test]
    async fn eviction_removes_oldest_on_overflow() {
        // Back-compat name: sample ring drops oldest when over cap.
        let mut r = RawRecorder::new().with_samples();
        r.start("run-1").await.unwrap();
        for i in 0..(MAX_SAMPLE_SEGMENTS + 5) {
            r.record_output(&[i as u8]).await.unwrap();
        }
        assert_eq!(r.samples.len(), MAX_SAMPLE_SEGMENTS);
    }

    #[tokio::test]
    async fn stop_returns_metadata_event() {
        let mut r = RawRecorder::new();
        r.start("run-1").await.unwrap();
        r.record_output(b"x").await.unwrap();
        let events = r.stop().await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "terminal.recording");
        assert_eq!(
            events[0]
                .metadata
                .get("segments")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    #[tokio::test]
    async fn stop_before_start_returns_empty() {
        let mut r = RawRecorder::new();
        let events = r.stop().await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn start_clears_previous_segments() {
        let mut r = RawRecorder::new();
        r.start("run-1").await.unwrap();
        r.record_output(b"old").await.unwrap();
        r.start("run-2").await.unwrap();
        assert_eq!(r.segment_count(), 0);
        assert_eq!(r.total_bytes(), 0);
    }
}
