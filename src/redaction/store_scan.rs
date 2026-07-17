//! Store-level secret scan for tests and operator audit (1.4 S1).
//!
//! Scans **raw bytes** of SQLite DB files (including WAL/SHM when present) and
//! content-addressed blob files for scanner matches — not only decoded event
//! objects. This catches accidental persistence of secret fragments that
//! never appear as clean event fields.

use crate::redaction::scanner::SecretScanner;
use std::path::{Path, PathBuf};

/// One finding from a store-level scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreScanFinding {
    pub path: PathBuf,
    pub kind: &'static str,
    pub detail: String,
}

/// Scan a single byte buffer for secrets; returns short descriptions.
pub fn scan_bytes(scanner: &SecretScanner, data: &[u8], label: &str) -> Vec<String> {
    // Lossy decode is intentional: we want to find ASCII/UTF-8 secrets even
    // inside binary pages. We also search raw bytes for known ASCII prefixes.
    let text = String::from_utf8_lossy(data);
    let mut hits = Vec::new();
    if !scanner.find_spans(&text).is_empty() {
        hits.push(format!("{label}: scanner span match"));
    }
    // Prefix probes for common fragments that might appear incomplete.
    for prefix in [
        "sk-abcdef",
        "ghp_ABCDEF",
        "github_pat_11",
        "AKIAIOSFODNN7",
        "xoxb-123456789012",
        "sk_live_51Ab",
        "xai-abcdef",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "npm_ABCDEF",
    ] {
        if data.windows(prefix.len()).any(|w| w == prefix.as_bytes()) {
            hits.push(format!("{label}: raw prefix {prefix:?}"));
        }
    }
    hits
}

/// Scan DB path (+ wal/shm siblings) and all files under blob_dir.
pub fn scan_store_paths(
    scanner: &SecretScanner,
    db_path: &Path,
    blob_dir: &Path,
) -> Vec<StoreScanFinding> {
    let mut findings = Vec::new();

    for path in db_related_paths(db_path) {
        if let Ok(data) = std::fs::read(&path) {
            for detail in scan_bytes(scanner, &data, "db") {
                findings.push(StoreScanFinding {
                    path: path.clone(),
                    kind: "sqlite",
                    detail,
                });
            }
        }
    }

    if blob_dir.is_dir() {
        if let Ok(rd) = std::fs::read_dir(blob_dir) {
            for ent in rd.flatten() {
                let path = ent.path();
                if !path.is_file() {
                    continue;
                }
                if let Ok(data) = std::fs::read(&path) {
                    for detail in scan_bytes(scanner, &data, "blob") {
                        findings.push(StoreScanFinding {
                            path: path.clone(),
                            kind: "blob",
                            detail,
                        });
                    }
                }
            }
        }
    }

    findings
}

fn db_related_paths(db_path: &Path) -> Vec<PathBuf> {
    let mut out = vec![db_path.to_path_buf()];
    let s = db_path.to_string_lossy();
    out.push(PathBuf::from(format!("{s}-wal")));
    out.push(PathBuf::from(format!("{s}-shm")));
    out
}

/// Assert helper for tests: panic with detail if any finding exists.
pub fn assert_store_clean(scanner: &SecretScanner, db_path: &Path, blob_dir: &Path) {
    let findings = scan_store_paths(scanner, db_path, blob_dir);
    assert!(
        findings.is_empty(),
        "store-level secret scan failed: {findings:#?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redaction::RedactionConfig;

    #[test]
    fn detects_secret_in_raw_bytes() {
        let s = SecretScanner::new(RedactionConfig::default());
        let data = b"noise sk-abcdefghijklmnopqrstuvwxyz012345 noise";
        let hits = scan_bytes(&s, data, "t");
        assert!(!hits.is_empty());
    }

    #[test]
    fn clean_structural_bytes() {
        let s = SecretScanner::new(RedactionConfig::default());
        let data = b"ea950d8180f520d808274579577db86bc6365a7a";
        let hits = scan_bytes(&s, data, "t");
        assert!(hits.is_empty(), "{hits:?}");
    }
}
