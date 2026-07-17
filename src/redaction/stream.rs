//! Holdback streaming redactor (1.4 S1).
//!
//! PTY and native-log reads fragment secrets across chunk boundaries. A naïve
//! per-chunk `SecretScanner::redact` can miss those; an **overlap-only** design
//! still emits the first unrecognized fragment before the pattern completes.
//!
//! This redactor **holds back** a trailing window and only emits text that is
//! older than that window (or is flushed at end-of-stream), after scanning the
//! full pending buffer for secret spans. Meaningful secret prefixes therefore
//! never reach SQLite/blobs under the default path.
//!
//! ```text
//! receive chunk N
//! append to pending (unredacted)
//! redact using spans on full pending
//! emit only prefix older than holdback window
//! (pull emit cursor back if a span crosses the boundary)
//! finish() → redact + emit remaining pending
//! ```

use crate::redaction::scanner::SecretScanner;

/// Default holdback window in bytes (char-boundary rounded).
///
/// Sized for common PATs / JWTs / provider keys. Pathological multi-KiB PEMs
/// still match the BEGIN header within this window; full PEM bodies rely on
/// the extended `BEGIN … PRIVATE KEY` pattern once the header is seen.
pub const DEFAULT_STREAM_WINDOW: usize = 1024;

/// Hard cap on pending unredacted buffer (bytes). Excess is force-flushed
/// after redaction so a hostile giant line cannot grow RAM without bound.
pub const DEFAULT_MAX_PENDING: usize = 256 * 1024;

/// Holdback stream redactor.
pub struct StreamRedactor {
    scanner: SecretScanner,
    /// Unredacted pending text not yet released for persistence.
    pending: String,
    /// Holdback window (trailing bytes retained until later / finish).
    window: usize,
    /// Maximum pending size before force-flush.
    max_pending: usize,
}

impl StreamRedactor {
    pub fn new(scanner: SecretScanner) -> Self {
        Self::with_window(scanner, DEFAULT_STREAM_WINDOW)
    }

    pub fn with_window(scanner: SecretScanner, window: usize) -> Self {
        Self {
            scanner,
            pending: String::new(),
            // Allow small windows in tests; production uses DEFAULT_STREAM_WINDOW.
            window: window.max(8),
            max_pending: DEFAULT_MAX_PENDING,
        }
    }

    pub fn with_limits(scanner: SecretScanner, window: usize, max_pending: usize) -> Self {
        Self {
            scanner,
            pending: String::new(),
            window: window.max(8),
            max_pending: max_pending.max(window.saturating_mul(2).max(64)),
        }
    }

    /// Push a new UTF-8 chunk; returns `(safe_to_persist, redaction_hit_count)`.
    ///
    /// The returned string may be empty when the entire pending buffer still
    /// fits inside the holdback window. Call [`finish`](Self::finish) at
    /// end-of-stream to release the remainder.
    pub fn push(&mut self, chunk: &str) -> (String, u64) {
        if chunk.is_empty() {
            return (String::new(), 0);
        }
        // Avoid splitting a multi-byte UTF-8 sequence: callers should pass
        // valid str slices (ANSI normalizer / line readers do). Defensive
        // path for lossy recovery lives in `push_bytes`.
        self.pending.push_str(chunk);
        self.emit_ready(false)
    }

    /// Push raw bytes, lossy-decoding invalid UTF-8 without dropping content.
    ///
    /// Invalid sequences become U+FFFD; those replacement chars are not secret
    /// material but keep the stream scannable without leaking raw opaque bytes
    /// past the redactor.
    pub fn push_bytes(&mut self, data: &[u8]) -> (String, u64) {
        if data.is_empty() {
            return (String::new(), 0);
        }
        let lossy = String::from_utf8_lossy(data);
        self.push(&lossy)
    }

    /// Flush remaining pending (redacted). Clears state for reuse.
    pub fn finish(&mut self) -> (String, u64) {
        let (out, hits) = self.emit_ready(true);
        self.pending.clear();
        (out, hits)
    }

    /// Bytes currently held (unredacted) — tests / diagnostics.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Access the underlying scanner (for JSON metadata redaction, etc.).
    pub fn scanner(&self) -> &SecretScanner {
        &self.scanner
    }

    fn emit_ready(&mut self, force_all: bool) -> (String, u64) {
        if self.pending.is_empty() {
            return (String::new(), 0);
        }

        // Memory bound: if pending is huge, force a full redacted flush of
        // everything except a trailing window (or all if force_all).
        if !force_all && self.pending.len() > self.max_pending {
            return self.force_flush_over_cap();
        }

        let spans = self.scanner.find_spans(&self.pending);

        let mut emit_end = if force_all {
            self.pending.len()
        } else if self.pending.len() > self.window {
            self.pending
                .floor_char_boundary(self.pending.len() - self.window)
        } else {
            0
        };

        // Never emit the leading half of a secret still completing in holdback.
        for &(s, e) in &spans {
            if s < emit_end && e > emit_end {
                emit_end = s;
            }
        }
        emit_end = self.pending.floor_char_boundary(emit_end);

        if emit_end == 0 {
            return (String::new(), 0);
        }

        let (out, hits) = redact_region(&self.pending, emit_end, &spans);
        self.pending = self.pending[emit_end..].to_string();
        (out, hits)
    }

    fn force_flush_over_cap(&mut self) -> (String, u64) {
        // Redact entire pending, keep only a redacted trailing window so we
        // do not drop the stream, but never retain unredacted over-cap data.
        let spans = self.scanner.find_spans(&self.pending);
        let keep = self.window.min(self.pending.len());
        let keep_from = self.pending.floor_char_boundary(self.pending.len() - keep);
        let (out, hits) = redact_region(&self.pending, keep_from, &spans);
        // Trailing window stays unredacted only if no complete span sits there;
        // re-scan after truncate.
        let tail = self.pending[keep_from..].to_string();
        // If the tail alone still matches a full secret, redact it in place.
        let tail_redacted = self.scanner.redact(&tail);
        // We cannot un-redact; store redacted tail as pending only when equal
        // (no secret). If redacted, pending becomes the redacted form so we
        // never re-emit secret material — pending is defined as unredacted,
        // so clear secrets by keeping only non-secret redacted output outside.
        // Simpler: if tail had secrets, emit them redacted too and clear.
        if tail_redacted != tail {
            let (extra, h2) = redact_region(&self.pending, self.pending.len(), &spans);
            self.pending.clear();
            return (extra, hits.saturating_add(h2));
        }
        self.pending = tail;
        (out, hits)
    }
}

/// Redact `text[0..emit_end)` using absolute spans; return (output, hit_count).
fn redact_region(text: &str, emit_end: usize, spans: &[(usize, usize)]) -> (String, u64) {
    let emit_end = text.floor_char_boundary(emit_end.min(text.len()));
    let region = &text[..emit_end];
    let mut region_spans: Vec<(usize, usize)> = Vec::new();
    let mut hits = 0u64;
    for &(s, e) in spans {
        if e == 0 || s >= emit_end {
            continue;
        }
        hits = hits.saturating_add(1);
        let rs = s.min(emit_end);
        let re = e.min(emit_end);
        if rs < re {
            region_spans.push((rs, re));
        }
    }
    region_spans.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for span in region_spans {
        if let Some(last) = merged.last_mut() {
            if span.0 <= last.1 {
                last.1 = last.1.max(span.1);
                continue;
            }
        }
        merged.push(span);
    }

    if merged.is_empty() {
        return (region.to_string(), 0);
    }

    let mut out = String::with_capacity(region.len());
    let mut cursor = 0;
    for (start, end) in merged {
        let start = region.floor_char_boundary(start);
        let end = region.floor_char_boundary(end);
        if cursor < start {
            out.push_str(&region[cursor..start]);
        }
        out.push_str("[REDACTED]");
        cursor = end;
    }
    if cursor < region.len() {
        out.push_str(&region[cursor..]);
    }
    (out, hits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redaction::RedactionConfig;

    fn stream() -> StreamRedactor {
        StreamRedactor::new(SecretScanner::new(RedactionConfig::default()))
    }

    fn stream_window(w: usize) -> StreamRedactor {
        StreamRedactor::with_window(SecretScanner::new(RedactionConfig::default()), w)
    }

    #[test]
    fn single_chunk_secret_held_until_finish() {
        let mut s = stream_window(64);
        let (out, hits) = s.push("key=sk-abcdefghijklmnopqrstuvwxyz012345\n");
        // Entire line fits in holdback — nothing emitted yet.
        assert!(out.is_empty(), "holdback should retain short chunk: {out}");
        assert_eq!(hits, 0);
        let (flush, hits2) = s.finish();
        assert!(hits2 > 0);
        assert!(flush.contains("[REDACTED]"));
        assert!(!flush.contains("sk-abcdef"));
    }

    #[test]
    fn split_openai_key_never_emits_fragment() {
        let mut s = stream_window(64);
        let secret = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let mid = secret.len() / 2;
        let (a, _) = s.push(&secret[..mid]);
        assert!(
            a.is_empty() || !a.contains("sk-"),
            "first fragment must not be persisted: {a}"
        );
        let (b, _) = s.push(&format!("{}\n", &secret[mid..]));
        let (tail, hits) = s.finish();
        let combined = format!("{a}{b}{tail}");
        assert!(hits > 0 || combined.contains("[REDACTED]"));
        assert!(
            !combined.contains(secret),
            "full secret leaked: {combined}"
        );
        assert!(!combined.contains(&secret[..mid]), "prefix leaked: {combined}");
        assert!(!combined.contains(&secret[mid..]), "suffix leaked: {combined}");
    }

    #[test]
    fn exhaustive_split_positions_openai_key() {
        let secret = "sk-abcdefghijklmnopqrstuvwxyz012345";
        for split in 1..secret.len() {
            let mut s = stream_window(32);
            let (a, _) = s.push(&secret[..split]);
            let (b, _) = s.push(&secret[split..]);
            let (c, _) = s.finish();
            let combined = format!("{a}{b}{c}");
            assert!(
                !combined.contains(secret),
                "split={split}: full secret survived: {combined}"
            );
            // Meaningful prefixes that look like key material
            if split >= 8 {
                assert!(
                    !combined.contains(&secret[..split]) || combined.contains("[REDACTED]"),
                    "split={split}: raw prefix leaked: {combined}"
                );
            }
            assert!(
                combined.contains("[REDACTED]"),
                "split={split}: expected redaction marker: {combined}"
            );
        }
    }

    #[test]
    fn split_github_token_across_chunks() {
        let mut s = stream_window(64);
        let secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12";
        let mid = 8;
        let (a, _) = s.push(&secret[..mid]);
        let (b, _) = s.push(&secret[mid..]);
        let (c, hits) = s.finish();
        let combined = format!("{a}{b}{c}");
        assert!(hits > 0 || combined.contains("[REDACTED]"));
        assert!(!combined.contains(secret));
        assert!(!combined.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12") || combined.contains("[REDACTED]"));
    }

    #[test]
    fn structural_sha_survives_stream() {
        let mut s = stream_window(16);
        let sha = "ea950d8180f520d808274579577db86bc6365a7a";
        // Push enough padding to force emission past holdback.
        let pad = "x".repeat(40);
        let (a, h1) = s.push(&format!("{pad}{sha}"));
        let (b, h2) = s.finish();
        assert_eq!(h1 + h2, 0);
        let combined = format!("{a}{b}");
        assert!(combined.contains(sha), "sha scarred: {combined}");
    }

    #[test]
    fn ansi_adjacent_secret() {
        let mut s = stream_window(32);
        let (_a, _) =
            s.push("status=\x1b[32mok\x1b[0m key=sk-abcdefghijklmnopqrstuvwxyz012345");
        let (out, hits) = s.finish();
        assert!(hits > 0);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("sk-abcdef"));
    }

    #[test]
    fn finish_idempotent() {
        let mut s = stream();
        let _ = s.push("hello");
        let (a, _) = s.finish();
        let (b, _) = s.finish();
        assert_eq!(b, "");
        assert!(a.contains("hello"));
    }

    #[test]
    fn push_bytes_lossy_utf8() {
        let mut s = stream_window(8);
        // Invalid UTF-8 mid-stream
        let mut data = b"ok ".to_vec();
        data.push(0xFF);
        data.extend_from_slice(b" key=sk-abcdefghijklmnopqrstuvwxyz012345");
        let (_a, _) = s.push_bytes(&data);
        let (out, hits) = s.finish();
        assert!(hits > 0);
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn non_secret_text_eventually_emits() {
        let mut s = stream_window(8);
        // 20 bytes with window 8 → emit first 12 immediately.
        let text = "abcdefghij0123456789";
        let (a, _) = s.push(text);
        assert!(!a.is_empty(), "expected emit of prefix older than holdback");
        let (b, _) = s.finish();
        assert_eq!(format!("{a}{b}"), text);
    }
}
