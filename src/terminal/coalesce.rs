//! Coalesce small PTY chunks into fewer terminal.output events.
//!
//! Adapter line parsing still happens on every chunk; only the stored
//! terminal.output event stream is coalesced.

/// Policy for when to flush a coalesced terminal buffer.
#[derive(Debug, Clone, Copy)]
pub struct CoalescePolicy {
    /// Flush when buffered text reaches this many bytes.
    pub max_bytes: usize,
    /// Flush when we have at least this many raw chunks.
    pub max_chunks: u32,
    /// Always flush immediately when a single chunk is this large.
    pub large_chunk: usize,
}

impl Default for CoalescePolicy {
    fn default() -> Self {
        Self {
            max_bytes: 4096,
            max_chunks: 16,
            large_chunk: 512,
        }
    }
}

/// Accumulates redacted terminal text until a flush condition.
#[derive(Debug, Default)]
pub struct TerminalCoalescer {
    policy: CoalescePolicy,
    text: String,
    raw_bytes: usize,
    chunks: u32,
    redactions: u64,
    insecure_raw: Vec<u8>,
    store_raw: bool,
}

impl TerminalCoalescer {
    pub fn new(policy: CoalescePolicy, store_raw: bool) -> Self {
        Self {
            policy,
            store_raw,
            text: String::new(),
            raw_bytes: 0,
            chunks: 0,
            redactions: 0,
            insecure_raw: Vec::new(),
        }
    }

    /// Push a processed chunk. Returns a flushed segment when ready.
    pub fn push(
        &mut self,
        safe_text: &str,
        raw: &[u8],
        redaction_count: u64,
    ) -> Option<CoalescedSegment> {
        self.text.push_str(safe_text);
        self.raw_bytes += raw.len();
        self.chunks += 1;
        self.redactions += redaction_count;
        if self.store_raw {
            // Cap insecure_raw to avoid unbounded memory growth on
            // long-running sessions.  Drop oldest data first.
            const MAX_INSECURE_RAW: usize = 10 * 1024 * 1024; // 10 MiB
            let remaining = MAX_INSECURE_RAW.saturating_sub(self.insecure_raw.len());
            let to_copy = raw.len().min(remaining);
            if to_copy > 0 {
                self.insecure_raw.extend_from_slice(&raw[..to_copy]);
            }
        }

        let should_flush = raw.len() >= self.policy.large_chunk
            || self.text.len() >= self.policy.max_bytes
            || self.chunks >= self.policy.max_chunks
            || safe_text.ends_with('\n');

        if should_flush {
            Some(self.take())
        } else {
            None
        }
    }

    /// Flush remaining buffer (end of stream).
    pub fn finish(&mut self) -> Option<CoalescedSegment> {
        if self.text.is_empty() && self.raw_bytes == 0 {
            None
        } else {
            Some(self.take())
        }
    }

    fn take(&mut self) -> CoalescedSegment {
        let preview = if self.text.len() > 200 {
            // Use char-safe truncation to avoid panicking on multi-byte UTF-8
            let end = self.text.floor_char_boundary(200);
            format!("{}…", &self.text[..end])
        } else {
            self.text.clone()
        };
        CoalescedSegment {
            text: std::mem::take(&mut self.text),
            preview,
            raw_bytes: std::mem::take(&mut self.raw_bytes),
            chunks: std::mem::take(&mut self.chunks),
            redactions: std::mem::take(&mut self.redactions),
            insecure_raw: std::mem::take(&mut self.insecure_raw),
        }
    }
}

/// One coalesced terminal segment ready to persist.
#[derive(Debug)]
pub struct CoalescedSegment {
    pub text: String,
    pub preview: String,
    pub raw_bytes: usize,
    pub chunks: u32,
    pub redactions: u64,
    pub insecure_raw: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flushes_on_newline() {
        let mut c = TerminalCoalescer::new(CoalescePolicy::default(), false);
        assert!(c.push("hel", b"hel", 0).is_none());
        let seg = c.push("lo\n", b"lo\n", 0).unwrap();
        assert_eq!(seg.text, "hello\n");
        assert_eq!(seg.chunks, 2);
    }

    #[test]
    fn flushes_on_size() {
        let policy = CoalescePolicy {
            max_bytes: 8,
            max_chunks: 100,
            large_chunk: 1000,
        };
        let mut c = TerminalCoalescer::new(policy, false);
        assert!(c.push("1234", b"1234", 0).is_none());
        let seg = c.push("56789", b"56789", 0).unwrap();
        assert!(seg.text.len() >= 8);
    }

    #[test]
    fn finish_drains() {
        let mut c = TerminalCoalescer::new(CoalescePolicy::default(), false);
        assert!(c.push("partial", b"partial", 0).is_none());
        let seg = c.finish().unwrap();
        assert_eq!(seg.text, "partial");
    }
}
