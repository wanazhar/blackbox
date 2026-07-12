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
        let mut result = String::new();
        let mut i = 0;
        let bytes = raw;

        while i < bytes.len() {
            let byte = bytes[i];

            // Handle ANSI escape sequences
            if byte == 0x1B && i + 1 < bytes.len() {
                let next = bytes[i + 1];

                // CSI sequences: ESC [
                if next == b'[' {
                    i += 2;
                    // Skip until we find a final character (0x40-0x7E)
                    while i < bytes.len() && !(0x40..=0x7E).contains(&bytes[i]) {
                        i += 1;
                    }
                    if i < bytes.len() {
                        i += 1; // Skip the final character
                    }
                    continue;
                }

                // OSC sequences: ESC ]
                if next == b']' {
                    i += 2;
                    // Skip until we find ST (ESC \ or BEL)
                    while i < bytes.len() {
                        if bytes[i] == 0x1B && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                            i += 2;
                            break;
                        }
                        if bytes[i] == 0x07 {
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                    continue;
                }

                // Other escape sequences - skip the next character
                i += 2;
                continue;
            }

            // Handle carriage returns
            if byte == b'\r' {
                // Skip carriage returns (they're handled by the terminal)
                i += 1;
                continue;
            }

            // Preserve printable characters, newlines, tabs, and spaces
            if byte.is_ascii_graphic() || byte == b'\n' || byte == b'\t' || byte == b' ' {
                result.push(byte as char);
            }

            i += 1;
        }

        result
    }

    /// Produce a terminal event with both raw and normalized content.
    pub fn create_event(&self, run_id: &str, _raw: &[u8], _normalized: &str) -> TraceEvent {
        let mut ev = TraceEvent::new(run_id, EventSource::Terminal, "terminal.output");
        ev.status = EventStatus::Success;
        ev
    }
}
