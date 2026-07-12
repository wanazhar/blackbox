use std::time::Instant;

use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::terminal::ansi::AnsiNormalizer;
use crate::terminal::{TerminalRecorder, TerminalSegment};

/// Raw terminal I/O recorder.
///
/// Captures every byte written to and read from the PTY,
/// storing both the raw stream and derived timestamps.
/// Output is normalized through `AnsiNormalizer` so segments
/// carry both raw and clean text.
pub struct RawRecorder {
    run_id: Option<String>,
    segments: Vec<TerminalSegment>,
    start: Option<Instant>,
    normalizer: AnsiNormalizer,
}

impl RawRecorder {
    pub fn new() -> Self {
        Self {
            run_id: None,
            segments: Vec::new(),
            start: None,
            normalizer: AnsiNormalizer::new(),
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
        Ok(())
    }

    async fn record_output(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let offset_ms = self
            .start
            .map(|s| s.elapsed().as_millis() as u64)
            .unwrap_or(0);
        let normalized_text = self.normalizer.normalize(data);
        let seg = TerminalSegment {
            offset_ms,
            raw_data: data.to_vec(),
            normalized_text,
        };
        self.segments.push(seg);
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

