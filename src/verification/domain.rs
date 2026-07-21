//! Verification domain matching — correlate receipts to prior failures (1.6).

use serde::{Deserialize, Serialize};

use crate::core::event::TraceEvent;
use crate::verification::receipt::{
    VerificationConfidence, VerificationReceipt, VerificationStatus,
};

/// How tightly a receipt matches a failure/task domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainMatchClass {
    /// `Confirmed` variant.
    Confirmed,
    /// `StronglyCorrelated` variant.
    StronglyCorrelated,
    /// `WeaklyCorrelated` variant.
    WeaklyCorrelated,
    /// `Unknown` variant.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `DomainMatchReport` value.
pub struct DomainMatchReport {
    /// Class.
    pub class: DomainMatchClass,
    /// Score.
    pub score: u32,
    /// Reasons.
    pub reasons: Vec<String>,
}

/// Score how well `receipt` covers `failure` (or a tool/test fingerprint).
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `match_receipt_to_failure` — see module docs for full workflow.
/// ```
pub fn match_receipt_to_failure(
    receipt: &VerificationReceipt,
    failure: Option<&TraceEvent>,
    changed_paths: &[String],
) -> DomainMatchReport {
    let mut score = 0u32;
    let mut reasons = Vec::new();

    if let Some(scope) = receipt.verified_scope.as_deref() {
        if !scope.is_empty() {
            score += 20;
            reasons.push(format!("explicit scope: {scope}"));
            if let Some(ev) = failure {
                let hay = format!(
                    "{} {} {}",
                    ev.kind,
                    ev.metadata
                        .get("tool_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    ev.metadata
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                );
                if hay.to_lowercase().contains(&scope.to_lowercase()) {
                    score += 40;
                    reasons.push("scope appears in failure text".into());
                }
            }
            for p in changed_paths {
                if p.contains(scope) || scope.contains(p) {
                    score += 25;
                    reasons.push(format!("scope matches path {p}"));
                }
            }
        }
    }

    if let Some(fp) = receipt.failure_fingerprint.as_deref() {
        if let Some(ev) = failure {
            let fail_fp = failure_fingerprint(ev);
            if !fp.is_empty() && fp == fail_fp {
                score += 50;
                reasons.push("failure fingerprint exact match".into());
            } else if !fp.is_empty() && fail_fp.starts_with(&fp[..fp.len().min(8)]) {
                score += 15;
                reasons.push("failure fingerprint prefix match".into());
            }
        }
    }

    if matches!(receipt.verifier_type, crate::verification::VerifierType::CommandExit)
        && receipt
            .command_argv
            .iter()
            .any(|a| a.contains("test") || a.contains("cargo"))
    {
        score += 10;
        reasons.push("test-like verifier command".into());
    }

    if matches!(receipt.status, VerificationStatus::Passed) {
        score += 5;
    }

    let class = match score {
        // Explicit scope hit in failure text (≥60) is enough for Confirmed.
        60.. => DomainMatchClass::Confirmed,
        40..=59 => DomainMatchClass::StronglyCorrelated,
        15..=39 => DomainMatchClass::WeaklyCorrelated,
        _ => DomainMatchClass::Unknown,
    };

    DomainMatchReport {
        class,
        score,
        reasons,
    }
}

/// Failure fingerprint.
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `failure_fingerprint` — see module docs for full workflow.
/// ```
pub fn failure_fingerprint(ev: &TraceEvent) -> String {
    use crate::crypto::content_key;
    let tool = ev
        .metadata
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let msg = ev
        .metadata
        .get("message")
        .or_else(|| ev.metadata.get("error"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let raw = format!("{}|{}|{}", ev.kind, tool, msg);
    content_key(raw.as_bytes())[..16].to_string()
}

/// Map domain class to receipt confidence (does not mutate storage).
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `confidence_from_domain` — see module docs for full workflow.
/// ```
pub fn confidence_from_domain(class: DomainMatchClass) -> VerificationConfidence {
    match class {
        DomainMatchClass::Confirmed => VerificationConfidence::Confirmed,
        DomainMatchClass::StronglyCorrelated => VerificationConfidence::StronglyCorrelated,
        DomainMatchClass::WeaklyCorrelated => VerificationConfidence::WeaklyCorrelated,
        DomainMatchClass::Unknown => VerificationConfidence::Unknown,
    }
}

/// Whether a receipt may satisfy a **strict** regression gate.
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `satisfies_strict_gate` — see module docs for full workflow.
/// ```
pub fn satisfies_strict_gate(receipt: &VerificationReceipt, domain: &DomainMatchReport) -> bool {
    matches!(receipt.status, VerificationStatus::Passed)
        && matches!(domain.class, DomainMatchClass::Confirmed)
        && matches!(
            receipt.confidence,
            VerificationConfidence::Confirmed | VerificationConfidence::StronglyCorrelated
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};
    use crate::verification::receipt::VerifierType;

    #[test]
    fn scope_match_is_confirmed() {
        let mut fail = TraceEvent::new("r", EventSource::Tool, "tool.result");
        fail.status = EventStatus::Error;
        fail.metadata
            .insert("message".into(), serde_json::json!("invalid_session failed"));
        let mut r = VerificationReceipt::new("r", VerifierType::CommandExit);
        r.status = VerificationStatus::Passed;
        r.verified_scope = Some("invalid_session".into());
        r.confidence = VerificationConfidence::Confirmed;
        let m = match_receipt_to_failure(&r, Some(&fail), &[]);
        assert!(matches!(m.class, DomainMatchClass::Confirmed));
        assert!(satisfies_strict_gate(&r, &m));
    }

    #[test]
    fn unrelated_pass_is_not_strict() {
        let mut fail = TraceEvent::new("r", EventSource::Tool, "tool.result");
        fail.status = EventStatus::Error;
        fail.metadata
            .insert("message".into(), serde_json::json!("auth broke"));
        let mut r = VerificationReceipt::new("r", VerifierType::CommandExit);
        r.status = VerificationStatus::Passed;
        r.verified_scope = Some("unrelated-suite".into());
        r.command_argv = vec!["true".into()];
        let m = match_receipt_to_failure(&r, Some(&fail), &[]);
        assert!(!satisfies_strict_gate(&r, &m) || matches!(m.class, DomainMatchClass::Unknown | DomainMatchClass::WeaklyCorrelated));
    }
}
