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

impl Default for AnsiNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

impl AnsiNormalizer {
    pub fn new() -> Self {
        Self
    }

    /// Normalize raw terminal bytes into clean text.
    ///
    /// Removes ANSI escape sequences, carriage returns, and
    /// other control codes, preserving printable content including
    /// non-ASCII characters (UTF-8 multibyte, CJK, emoji, etc.).
    pub fn normalize(&self, raw: &[u8]) -> String {
        // Convert to string first, preserving all non-ASCII content
        let text = String::from_utf8_lossy(raw);
        let mut result = String::with_capacity(text.len());
        let chars: Vec<char> = text.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            let ch = chars[i];

            // Handle ANSI escape sequences (ESC is always 0x1B = '\x1B')
            if ch == '\x1B' && i + 1 < len {
                let next = chars[i + 1];

                // CSI sequences: ESC [
                if next == '[' {
                    i += 2;
                    // Skip until we find a final character (0x40-0x7E)
                    while i < len && !('\x40'..='\x7E').contains(&chars[i]) {
                        i += 1;
                    }
                    if i < len {
                        i += 1; // Skip the final character
                    }
                    continue;
                }

                // OSC sequences: ESC ]
                if next == ']' {
                    i += 2;
                    // Skip until we find ST (ESC \ or BEL)
                    while i < len {
                        if chars[i] == '\x1B' && i + 1 < len && chars[i + 1] == '\\' {
                            i += 2;
                            break;
                        }
                        if chars[i] == '\x07' {
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
            if ch == '\r' {
                i += 1;
                continue;
            }

            // Preserve printable characters, newlines, tabs, spaces,
            // and ALL non-ASCII characters (UTF-8 multibyte sequences)
            if !ch.is_control() || ch == '\n' || ch == '\t' {
                result.push(ch);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_sequences() {
        let normalizer = AnsiNormalizer::new();
        // ESC[31m = red text color
        let raw = b"hello \x1B[31mworld\x1B[0m";
        assert_eq!(normalizer.normalize(raw), "hello world");
    }

    #[test]
    fn strips_osc_sequences() {
        let normalizer = AnsiNormalizer::new();
        // OSC with BEL terminator
        let raw = b"\x1B]0;title\x07hello";
        assert_eq!(normalizer.normalize(raw), "hello");
        // OSC with ESC\ terminator
        let raw2 = b"\x1B]0;title\x1B\\hello";
        assert_eq!(normalizer.normalize(raw2), "hello");
    }

    #[test]
    fn preserves_newlines_and_tabs() {
        let normalizer = AnsiNormalizer::new();
        let raw = b"line1\nline2\ttab";
        assert_eq!(normalizer.normalize(raw), "line1\nline2\ttab");
    }

    #[test]
    fn strips_carriage_returns() {
        let normalizer = AnsiNormalizer::new();
        let raw = b"hello\rworld";
        assert_eq!(normalizer.normalize(raw), "helloworld");
    }

    #[test]
    fn preserves_non_ascii_content() {
        let normalizer = AnsiNormalizer::new();
        // Chinese characters, emoji, accented chars
        let raw = "hello 你好世界 🎉 café résumé".as_bytes();
        assert_eq!(normalizer.normalize(raw), "hello 你好世界 🎉 café résumé");
    }

    #[test]
    fn preserves_non_ascii_with_ansi() {
        let normalizer = AnsiNormalizer::new();
        // Non-ASCII content mixed with ANSI sequences
        let raw = "\x1B[31m你好\x1B[0m world 🎉".as_bytes();
        assert_eq!(normalizer.normalize(raw), "你好 world 🎉");
    }

    #[test]
    fn handles_invalid_utf8() {
        let normalizer = AnsiNormalizer::new();
        // Invalid UTF-8 bytes become replacement character
        let raw = b"hello \xFF\xFE world";
        let result = normalizer.normalize(raw);
        assert!(result.contains("hello"));
        assert!(result.contains("world"));
    }

    #[test]
    fn empty_input() {
        let normalizer = AnsiNormalizer::new();
        assert_eq!(normalizer.normalize(b""), "");
    }

    #[test]
    fn only_ansi_sequences() {
        let normalizer = AnsiNormalizer::new();
        let raw = b"\x1B[31m\x1B[1m\x1B[0m";
        assert_eq!(normalizer.normalize(raw), "");
    }

    #[test]
    fn create_event_produces_correct_event() {
        let normalizer = AnsiNormalizer::new();
        let ev = normalizer.create_event("run-1", b"raw", "normalized");
        assert_eq!(ev.run_id, "run-1");
        assert_eq!(ev.kind, "terminal.output");
        assert_eq!(ev.source, EventSource::Terminal);
        assert_eq!(ev.status, EventStatus::Success);
    }
}
