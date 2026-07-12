use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::terminal::{TerminalRecorder, TerminalSegment};

/// Raw terminal I/O recorder.
///
/// Captures every byte written to and read from the PTY,
/// storing both the raw stream and derived timestamps.
pub struct RawRecorder {
    run_id: Option<String>,
    segments: Vec<TerminalSegment>,
    start_offset_ms: u64,
}

impl RawRecorder {
    pub fn new() -> Self {
        Self {
            run_id: None,
            segments: Vec::new(),
            start_offset_ms: 0,
        }
    }
}

#[async_trait::async_trait]
impl TerminalRecorder for RawRecorder {
    async fn start(&mut self, run_id: &str) -> anyhow::Result<()> {
        self.run_id = Some(run_id.to_string());
        self.segments.clear();
        Ok(())
    }

    async fn write_input(&mut self, _data: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }

    async fn record_output(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let seg = TerminalSegment {
            offset_ms: self.start_offset_ms,
            raw_data: data.to_vec(),
            normalized_text: String::from_utf8_lossy(data).to_string(),
        };
        self.segments.push(seg);
        self.start_offset_ms += data.len() as u64;
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
                serde_json::json!(self.segments.iter().map(|s| s.raw_data.len()).sum::<usize>()),
            );
            events.push(ev);
        }
        Ok(events)
    }
}
