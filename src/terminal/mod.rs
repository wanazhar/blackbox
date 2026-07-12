pub mod ansi;
pub mod coalesce;
pub mod recorder;

use crate::core::event::TraceEvent;

/// Terminal recording dimensions.
///
/// The terminal layer stores both raw PTY byte streams and
/// derived plain-text transcripts, because interactive
/// applications redraw screens and a raw dump may not
/// resemble what the user saw.
#[derive(Debug, Clone)]
pub struct TerminalDimensions {
    pub rows: u16,
    pub cols: u16,
}

/// A segment of terminal output with timing.
#[derive(Debug, Clone)]
pub struct TerminalSegment {
    /// Monotonic timestamp offset in milliseconds from run start
    pub offset_ms: u64,
    /// Raw bytes written to the terminal
    pub raw_data: Vec<u8>,
    /// Normalized text derived from ANSI processing
    pub normalized_text: String,
}

/// Terminal recorder trait.
///
/// Implementations must record all terminal I/O and emit events
/// for both raw and normalized representations.
#[async_trait::async_trait]
pub trait TerminalRecorder: Send + 'static {
    /// Start recording terminal I/O for a run.
    async fn start(&mut self, run_id: &str) -> anyhow::Result<()>;

    /// Write data to the terminal (stdin from user).
    async fn write_input(&mut self, data: &[u8]) -> anyhow::Result<()>;

    /// Record output received from the PTY (stdout/stderr).
    async fn record_output(&mut self, data: &[u8]) -> anyhow::Result<()>;

    /// Stop recording and flush any buffered data.
    async fn stop(&mut self) -> anyhow::Result<Vec<TraceEvent>>;
}
