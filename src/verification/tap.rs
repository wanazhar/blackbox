//! TAP (Test Anything Protocol) parser for verification receipts.

use crate::verification::receipt::{
    VerificationConfidence, VerificationReceipt, VerificationStatus, VerifierType,
};

#[derive(Debug, Clone, Default)]
pub struct TapSummary {
    pub planned: Option<u64>,
    pub ok: u64,
    pub not_ok: u64,
    pub skipped: u64,
}

pub fn parse_tap(text: &str) -> TapSummary {
    let mut s = TapSummary::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("1..") {
            s.planned = rest
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok());
        } else if line.starts_with("ok ") {
            if line.contains("# SKIP") || line.contains("# skip") {
                s.skipped += 1;
            } else {
                s.ok += 1;
            }
        } else if line.starts_with("not ok ") {
            s.not_ok += 1;
        }
    }
    s
}

pub fn receipt_from_tap(run_id: &str, summary: &TapSummary, source: &str) -> VerificationReceipt {
    let total = summary
        .planned
        .unwrap_or(summary.ok + summary.not_ok + summary.skipped);
    let status = if summary.not_ok == 0 && (summary.ok > 0 || total == 0) {
        if total == 0 && summary.ok == 0 {
            VerificationStatus::Inconclusive
        } else {
            VerificationStatus::Passed
        }
    } else if summary.ok > 0 {
        VerificationStatus::PartiallyPassed
    } else {
        VerificationStatus::Failed
    };
    let mut r = VerificationReceipt::new(run_id, VerifierType::Tap);
    r.tests_total = Some(total);
    r.tests_passed = Some(summary.ok);
    r.tests_failed = Some(summary.not_ok);
    r.tests_skipped = Some(summary.skipped);
    r.status = status;
    r.confidence = VerificationConfidence::Confirmed;
    r.verified_scope = Some(source.into());
    r.summary = Some(format!(
        "tap: {} ok, {} not ok, {} skipped",
        summary.ok, summary.not_ok, summary.skipped
    ));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tap() {
        let t = "1..3\nok 1\nnot ok 2 - fail\nok 3 # SKIP\n";
        let s = parse_tap(t);
        assert_eq!(s.planned, Some(3));
        assert_eq!(s.ok, 1);
        assert_eq!(s.not_ok, 1);
        assert_eq!(s.skipped, 1);
    }
}
