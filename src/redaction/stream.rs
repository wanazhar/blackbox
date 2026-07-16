//! Stream-aware redaction with an overlap window.
//!
//! PTY and native-log reads often fragment secrets across chunk boundaries.
//! Per-chunk `SecretScanner::redact` alone can miss those. `StreamRedactor`
//! keeps a short unredacted carry buffer so matches that straddle the boundary
//! are still detected, while only emitting the redacted form of the new chunk.

use crate::redaction::scanner::SecretScanner;

/// Default carry window: long enough for PATs / JWTs / PEM headers without
/// retaining large amounts of sensitive text in memory.
pub const DEFAULT_STREAM_WINDOW: usize = 256;

/// Overlap-window stream redactor.
pub struct StreamRedactor {
    scanner: SecretScanner,
    /// Unredacted tail of previously seen text (≤ window).
    carry: String,
    window: usize,
}

impl StreamRedactor {
    pub fn new(scanner: SecretScanner) -> Self {
        Self::with_window(scanner, DEFAULT_STREAM_WINDOW)
    }

    pub fn with_window(scanner: SecretScanner, window: usize) -> Self {
        Self {
            scanner,
            carry: String::new(),
            window: window.max(32),
        }
    }

    /// Push a new chunk; returns `(redacted_chunk, redaction_hit_count)`.
    ///
    /// `redaction_hit_count` counts secret spans that intersect this chunk
    /// (including spans that began in the carry buffer).
    pub fn push(&mut self, chunk: &str) -> (String, u64) {
        if chunk.is_empty() {
            return (String::new(), 0);
        }

        let carry_len = self.carry.len();
        let mut combined = String::with_capacity(carry_len + chunk.len());
        combined.push_str(&self.carry);
        combined.push_str(chunk);

        let spans = self.scanner.find_spans(&combined);

        // Map absolute spans onto the chunk region [carry_len, carry_len+chunk.len()).
        let chunk_end = carry_len + chunk.len();
        let mut chunk_spans: Vec<(usize, usize)> = Vec::new();
        let mut hits = 0u64;
        for (s, e) in spans {
            if e <= carry_len || s >= chunk_end {
                continue;
            }
            hits = hits.saturating_add(1);
            let rel_s = s.saturating_sub(carry_len);
            let rel_e = e.saturating_sub(carry_len).min(chunk.len());
            if rel_s < rel_e {
                chunk_spans.push((rel_s, rel_e));
            }
        }

        // Also apply pure chunk-local redaction so non-boundary secrets still die
        // if span mapping edge cases miss (should not happen, but defensive).
        let local = self.scanner.find_spans(chunk);
        for (s, e) in local {
            chunk_spans.push((s, e));
            hits = hits.saturating_add(1);
        }

        chunk_spans.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for span in chunk_spans {
            if let Some(last) = merged.last_mut() {
                if span.0 <= last.1 {
                    last.1 = last.1.max(span.1);
                    continue;
                }
            }
            merged.push(span);
        }

        let redacted = if merged.is_empty() {
            chunk.to_string()
        } else {
            let mut out = String::with_capacity(chunk.len());
            let mut cursor = 0;
            for (start, end) in merged {
                let start = chunk.floor_char_boundary(start);
                let end = chunk.floor_char_boundary(end);
                if cursor < start {
                    out.push_str(&chunk[cursor..start]);
                }
                out.push_str("[REDACTED]");
                cursor = end;
            }
            if cursor < chunk.len() {
                out.push_str(&chunk[cursor..]);
            }
            out
        };

        // Advance unredacted carry from original stream.
        self.carry.push_str(chunk);
        if self.carry.len() > self.window {
            let keep_from = self.carry.floor_char_boundary(self.carry.len() - self.window);
            self.carry = self.carry[keep_from..].to_string();
        }

        (redacted, hits)
    }

    /// Flush any remaining carry (no new emission — carry was already emitted
    /// as part of previous chunks). Clears state for reuse.
    pub fn finish(&mut self) {
        self.carry.clear();
    }

    /// Access the underlying scanner (for JSON metadata redaction, etc.).
    pub fn scanner(&self) -> &SecretScanner {
        &self.scanner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redaction::RedactionConfig;

    fn stream() -> StreamRedactor {
        StreamRedactor::new(SecretScanner::new(RedactionConfig::default()))
    }

    #[test]
    fn single_chunk_secret_redacted() {
        let mut s = stream();
        let (out, hits) = s.push("key=sk-abcdefghijklmnopqrstuvwxyz012345\n");
        assert!(hits > 0);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("sk-abcdef"));
    }

    #[test]
    fn split_openai_key_across_chunks() {
        let mut s = stream();
        let secret = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let mid = secret.len() / 2;
        // Avoid `token=` prefix so only the sk- pattern can fire (and only once full).
        let (a, _) = s.push(&secret[..mid]);
        let (b, hits_b) = s.push(&format!("{}\n", &secret[mid..]));
        // First half alone is too short for sk-[A-Za-z0-9]{20,}.
        assert_eq!(a, &secret[..mid], "partial first chunk should pass through: {a}");
        // Combined stream must catch the secret on the second push.
        assert!(hits_b > 0, "boundary hit expected on second chunk");
        let combined = format!("{a}{b}");
        assert!(
            !combined.contains(secret),
            "full secret leaked across chunks: {combined}"
        );
        assert!(
            combined.contains("[REDACTED]") || b.contains("[REDACTED]"),
            "expected redaction marker: {combined}"
        );
    }

    #[test]
    fn split_github_token_across_chunks() {
        let mut s = stream();
        let secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12";
        let mid = 8; // after "ghp_ABCD"
        let (_a, _) = s.push(&secret[..mid]);
        let (b, hits) = s.push(&secret[mid..]);
        assert!(hits > 0);
        assert!(b.contains("[REDACTED]") || !b.contains(&secret[mid..]));
        // Ensure remainder of token body does not survive intact.
        assert!(!b.contains("EFGHIJKLMNOPQRSTUVWXYZabcdefgh12") || b.contains("[REDACTED]"));
    }

    #[test]
    fn structural_sha_survives_stream() {
        let mut s = stream();
        let sha = "ea950d8180f520d808274579577db86bc6365a7a";
        let (a, h1) = s.push(&sha[..20]);
        let (b, h2) = s.push(&sha[20..]);
        assert_eq!(h1, 0);
        assert_eq!(h2, 0);
        assert_eq!(format!("{a}{b}"), sha);
    }

    #[test]
    fn ansi_adjacent_secret() {
        let mut s = stream();
        // CSI sequence then secret (ANSI already stripped upstream normally;
        // still ensure redaction works when control-ish text is nearby).
        let (out, hits) = s.push("status=\x1b[32mok\x1b[0m key=sk-abcdefghijklmnopqrstuvwxyz012345");
        assert!(hits > 0);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("sk-abcdef"));
    }
}
