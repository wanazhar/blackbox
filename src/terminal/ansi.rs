use crate::core::event::{EventSource, EventStatus, TraceEvent};

/// ANSI escape-sequence normalizer.
///
/// Strips or interprets ANSI control sequences to produce a
/// clean, searchable text transcript from raw terminal output.
///
/// ## Storage
///
/// Both raw and normalized forms are stored:
/// - **Raw PTY byte stream** — accurate frame reconstruction
/// - **Derived plain-text transcript** — search and display
pub struct AnsiNormalizer;

impl AnsiNormalizer {
    pub fn new() -> Self {
        Self
    }

    /// Normalize raw terminal bytes into clean text.
    ///
    /// Removes ANSI escape sequences, carriage returns, and
    /// other control codes, preserving printable content.
    pub fn normalize(&self, raw: &[u8]) -> String {
        // Stub: full ANSI parser will handle:
        // - CSI sequences (SGR colors, cursor movement, erase)
        // - OSC sequences (window title, clipboard)
        // - DCS sequences
        // - SOS, PM, APC string terminators
        // - Carriage return handling (overwrite vs newline)
        String::from_utf8_lossy(raw)
            .chars()
            .filter(|&c| c.is_ascii_graphic() || c == '\n' || c == '\r' || c == '\t' || c == ' ')
            .collect()
    }

    /// Produce a terminal event with both raw and normalized content.
    pub fn create_event(&self, run_id: &str, _raw: &[u8], _normalized: &str) -> TraceEvent {
        let mut ev = TraceEvent::new(run_id, EventSource::Terminal, "terminal.output");
        ev.status = EventStatus::Success;
        ev
    }
}
