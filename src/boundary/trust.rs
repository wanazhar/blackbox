//! Boundary trust rollup for summary, score, and experiment gates (1.7).
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use crate::boundary::{
    evaluate_provenance, evaluate_required_evidence, BoundaryFinding, ContainmentClaimState,
    ContainmentReceipt, EvidenceStatus, FindingSeverity, ObservedEvidence, ProvenanceRecord,
    ProvenanceStatus, ResolvedBoundary,
};
use crate::evidence::ExternalEvidenceEvent;

/// Schema for boundary trust rollups embedded in summary/score.
pub const BOUNDARY_TRUST_SCHEMA: &str = "blackbox.boundary.trust/v1";

/// Compact trust view for a single run (summary + score + gates).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BoundaryTrustView {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(default)]
    pub has_boundary: bool,
    #[serde(default)]
    pub fail_closed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_status: Option<String>,
    #[serde(default)]
    pub evidence_gate_failed: bool,
    #[serde(default)]
    pub finding_count: usize,
    #[serde(default)]
    pub critical_finding_count: usize,
    #[serde(default)]
    pub high_finding_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earliest_finding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earliest_finding_summary: Option<String>,
    #[serde(default)]
    pub containment_receipt_count: usize,
    #[serde(default)]
    pub containment_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_status: Option<String>,
    #[serde(default)]
    pub provenance_gate_failed: bool,
    /// True when no fail-closed boundary/provenance failure and no critical findings.
    #[serde(default)]
    pub trust_ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

/// Build a trust rollup from store-derived slices.
pub fn build_boundary_trust(
    boundary: Option<&ResolvedBoundary>,
    findings: &[BoundaryFinding],
    receipts: &[ContainmentReceipt],
    provenance: &[ProvenanceRecord],
    external: &[ExternalEvidenceEvent],
    present_classes: &[String],
) -> BoundaryTrustView {
    let mut reasons = Vec::new();
    let mut view = BoundaryTrustView {
        schema: BOUNDARY_TRUST_SCHEMA.into(),
        ..Default::default()
    };

    if let Some(b) = boundary {
        view.has_boundary = true;
        view.policy_hash = Some(b.policy_hash.clone());
        view.fail_closed = b.contract.fail_closed;

        let observed = ObservedEvidence {
            present_classes: present_classes.to_vec(),
            containment_receipts: receipts.to_vec(),
            has_artifact_provenance: provenance
                .iter()
                .any(|record| !record.observed_sources.is_empty() || record.content_hash.is_some()),
            ..Default::default()
        };
        let ev = evaluate_required_evidence(Some(b), &observed);
        view.evidence_status = Some(ev.status.as_str().into());
        view.evidence_gate_failed = ev.gate_failed;
        reasons.extend(ev.reasons.iter().take(8).cloned());
    }

    view.finding_count = findings.len();
    view.critical_finding_count = findings
        .iter()
        .filter(|f| matches!(f.severity, FindingSeverity::Critical))
        .count();
    view.high_finding_count = findings
        .iter()
        .filter(|f| matches!(f.severity, FindingSeverity::High))
        .count();
    if let Some(f) = findings
        .iter()
        .filter(|f| {
            matches!(
                f.severity,
                FindingSeverity::Critical | FindingSeverity::High
            )
        })
        .min_by_key(|f| f.created_at)
    {
        view.earliest_finding_id = Some(f.id.clone());
        view.earliest_finding_summary = Some(f.summary.clone());
        reasons.push(format!("finding:{}", f.summary));
    }

    view.containment_receipt_count = receipts.len();
    view.containment_verified = boundary.is_some_and(|b| {
        receipts.iter().any(|r| {
            matches!(r.claim_state, ContainmentClaimState::Verified)
                && r.satisfies_required_containment_for(&b.policy_hash)
        })
    });

    if !provenance.is_empty() || !external.is_empty() {
        let allowed: Vec<String> = boundary
            .map(|b| {
                let mut a = b.contract.allowed.provenance.clone();
                a.extend(b.contract.allowed.network.clone());
                a
            })
            .unwrap_or_default();
        let report = evaluate_provenance(
            boundary.map(|b| b.run_id.as_str()).unwrap_or(""),
            provenance,
            external,
            &allowed,
            None,
            !provenance.is_empty(),
        );
        view.provenance_status = Some(report.provenance_status.as_str().into());
        view.provenance_gate_failed = report.provenance_gate_failed;
        if report.provenance_gate_failed {
            reasons.extend(report.reasons.iter().take(4).cloned());
        }
    } else if view.has_boundary
        && boundary
            .map(|b| {
                b.contract
                    .required_evidence
                    .iter()
                    .any(|e| e == "artifact_provenance")
            })
            .unwrap_or(false)
    {
        view.provenance_status = Some(ProvenanceStatus::InsufficientEvidence.as_str().into());
        if view.fail_closed {
            view.provenance_gate_failed = true;
            reasons.push("required artifact_provenance missing".into());
        }
    }

    let critical_fail = view.critical_finding_count > 0;
    view.trust_ok = !view.evidence_gate_failed
        && !view.provenance_gate_failed
        && !critical_fail
        && (!view.has_boundary
            || !view.fail_closed
            || matches!(
                view.evidence_status.as_deref(),
                Some("sufficient") | Some("no_boundary") | None
            )
            || !view.evidence_gate_failed);

    // Stricter: if fail_closed and evidence not sufficient → trust_ok false already via gate.
    if view.fail_closed && view.has_boundary {
        if let Some(ref st) = view.evidence_status {
            if st != EvidenceStatus::Sufficient.as_str()
                && st != EvidenceStatus::NoBoundary.as_str()
            {
                view.trust_ok = false;
            }
        }
    }
    if critical_fail {
        view.trust_ok = false;
    }

    view.reasons = reasons;
    if view.reasons.len() > 12 {
        view.reasons.truncate(12);
    }
    view
}

/// Whether score/CI should treat the run as failed due to trust gates.
pub fn trust_fails_score(view: &BoundaryTrustView) -> bool {
    view.evidence_gate_failed || view.provenance_gate_failed || view.critical_finding_count > 0
}
