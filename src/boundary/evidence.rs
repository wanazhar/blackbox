//! Required-evidence evaluation and fail-closed boundary gates.

use serde::{Deserialize, Serialize};

use super::containment::{ContainmentClaimState, ContainmentReceipt, ContainmentResult};
use super::resolve::ResolvedBoundary;

/// Schema for boundary evidence evaluation reports.
pub const BOUNDARY_EVAL_SCHEMA: &str = "blackbox.boundary.eval/v1";

/// A single required evidence class from the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRequirement {
    /// Evidence class token (`process`, `network`, `containment_receipt`, …).
    pub class: String,
    /// Availability observed at evaluation time.
    pub availability: EvidenceAvailability,
    /// Optional detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Whether a required evidence class is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAvailability {
    /// Sensor data present and usable.
    Present,
    /// Explicitly missing.
    Missing,
    /// Sensor not available on this platform.
    Unavailable,
    /// Present but degraded / partial.
    Partial,
    /// Not applicable for this contract/run.
    NotApplicable,
}

impl EvidenceAvailability {
    /// Stable snake_case form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
            Self::Unavailable => "unavailable",
            Self::Partial => "partial",
            Self::NotApplicable => "not_applicable",
        }
    }

    /// Counts as satisfied for non-fail-closed soft evaluation.
    pub fn is_sufficient(self) -> bool {
        matches!(self, Self::Present | Self::NotApplicable)
    }
}

/// Overall evidence / gate status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    /// All required evidence present (or not applicable).
    Sufficient,
    /// At least one required class missing or unavailable under fail-closed.
    InsufficientEvidence,
    /// Containment required and not verified-held.
    ContainmentUnproven,
    /// Containment explicitly violated.
    ContainmentViolated,
    /// No boundary contract on the run.
    NoBoundary,
    /// Evaluation skipped.
    NotEvaluated,
}

impl EvidenceStatus {
    /// Stable snake_case form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sufficient => "sufficient",
            Self::InsufficientEvidence => "insufficient_evidence",
            Self::ContainmentUnproven => "containment_unproven",
            Self::ContainmentViolated => "containment_violated",
            Self::NoBoundary => "no_boundary",
            Self::NotEvaluated => "not_evaluated",
        }
    }

    /// Fail-closed gate should reject this status.
    pub fn is_gate_failure(self) -> bool {
        matches!(
            self,
            Self::InsufficientEvidence | Self::ContainmentUnproven | Self::ContainmentViolated
        )
    }
}

/// Observed evidence inputs for evaluation (caller fills from store / capture).
#[derive(Debug, Clone, Default)]
pub struct ObservedEvidence {
    /// Capture classes present (e.g. `process`, `network`, `pty`, `filesystem`).
    pub present_classes: Vec<String>,
    /// Capture classes known unavailable on this platform.
    pub unavailable_classes: Vec<String>,
    /// Capture classes partially present.
    pub partial_classes: Vec<String>,
    /// Containment receipts for the run.
    pub containment_receipts: Vec<ContainmentReceipt>,
    /// Whether artifact provenance records exist.
    pub has_artifact_provenance: bool,
}

/// Report from evaluating required evidence against a resolved boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundaryEvidenceReport {
    /// Schema id.
    pub schema: String,
    /// Run id.
    pub run_id: String,
    /// Policy hash when a boundary was present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// Overall status.
    pub status: EvidenceStatus,
    /// Whether the contract requested fail-closed behavior.
    pub fail_closed: bool,
    /// Whether a gate should fail (status is a gate failure AND fail_closed).
    pub gate_failed: bool,
    /// Per-requirement breakdown.
    pub requirements: Vec<EvidenceRequirement>,
    /// Human-readable reasons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

/// Evaluate required evidence for a resolved boundary.
///
/// Rules:
/// - Missing required evidence → `insufficient_evidence`
/// - Required `containment_receipt` without a verified-held receipt →
///   `containment_unproven` (stronger than mere missing when receipts exist
///   but only claim `configured` / `enforced`)
/// - Any containment receipt with `result = violated` → `containment_violated`
/// - Task success is **never** consulted; a correct answer cannot satisfy
///   a containment gate through this function
pub fn evaluate_required_evidence(
    boundary: Option<&ResolvedBoundary>,
    observed: &ObservedEvidence,
) -> BoundaryEvidenceReport {
    let Some(boundary) = boundary else {
        return BoundaryEvidenceReport {
            schema: BOUNDARY_EVAL_SCHEMA.into(),
            run_id: String::new(),
            policy_hash: None,
            status: EvidenceStatus::NoBoundary,
            fail_closed: false,
            gate_failed: false,
            requirements: Vec::new(),
            reasons: vec!["no boundary contract attached to run".into()],
        };
    };

    let mut requirements = Vec::new();
    let mut reasons = Vec::new();
    let mut any_missing = false;
    let mut containment_unproven = false;
    let mut containment_violated = false;

    // Explicit violation always surfaces.
    for r in observed
        .containment_receipts
        .iter()
        .filter(|r| r.policy_hash.as_deref() == Some(boundary.policy_hash.as_str()))
    {
        if matches!(r.result, ContainmentResult::Violated) {
            containment_violated = true;
            reasons.push(format!(
                "containment violated by receipt {} (control={:?})",
                r.id, r.scope.control
            ));
        }
    }

    for class in &boundary.contract.required_evidence {
        let availability = classify_requirement(class, observed, Some(&boundary.policy_hash));
        if !availability.is_sufficient() {
            any_missing = true;
            reasons.push(format!(
                "required evidence {class:?} is {}",
                availability.as_str()
            ));
        }

        // Special handling: containment_receipt must be verified-held when required.
        if class == "containment_receipt" {
            let has_verified = observed
                .containment_receipts
                .iter()
                .any(|r| r.satisfies_required_containment_for(&boundary.policy_hash));
            if !has_verified {
                // If we only have configured/enforced claims, say unproven not just missing.
                containment_unproven = true;
                if !observed.containment_receipts.is_empty() {
                    reasons.push("containment receipts present but none are verified+held".into());
                    // Configured/enforced must never count as verified — note each.
                    for r in &observed.containment_receipts {
                        if matches!(
                            r.claim_state,
                            ContainmentClaimState::Configured | ContainmentClaimState::Enforced
                        ) {
                            let note = format!(
                                "receipt {} is {} (not verified)",
                                r.id,
                                r.claim_state.as_str()
                            );
                            if !reasons.iter().any(|x| x == &note) {
                                reasons.push(note);
                            }
                        }
                    }
                }
            }
        }

        requirements.push(EvidenceRequirement {
            class: class.clone(),
            availability,
            detail: None,
        });
    }

    let status = if containment_violated {
        EvidenceStatus::ContainmentViolated
    } else if containment_unproven {
        EvidenceStatus::ContainmentUnproven
    } else if any_missing {
        EvidenceStatus::InsufficientEvidence
    } else {
        EvidenceStatus::Sufficient
    };

    let fail_closed = boundary.contract.fail_closed;
    let gate_failed = fail_closed && status.is_gate_failure();

    BoundaryEvidenceReport {
        schema: BOUNDARY_EVAL_SCHEMA.into(),
        run_id: boundary.run_id.clone(),
        policy_hash: Some(boundary.policy_hash.clone()),
        status,
        fail_closed,
        gate_failed,
        requirements,
        reasons,
    }
}

fn classify_requirement(
    class: &str,
    observed: &ObservedEvidence,
    policy_hash: Option<&str>,
) -> EvidenceAvailability {
    // Special classes mapped from structured fields.
    match class {
        "containment_receipt" => {
            if observed
                .containment_receipts
                .iter()
                .any(|r| policy_hash.is_some_and(|hash| r.satisfies_required_containment_for(hash)))
            {
                EvidenceAvailability::Present
            } else if !observed.containment_receipts.is_empty() {
                EvidenceAvailability::Partial
            } else if observed
                .unavailable_classes
                .iter()
                .any(|c| c == "containment_receipt")
            {
                EvidenceAvailability::Unavailable
            } else {
                EvidenceAvailability::Missing
            }
        }
        "artifact_provenance" => {
            if observed.has_artifact_provenance {
                EvidenceAvailability::Present
            } else {
                EvidenceAvailability::Missing
            }
        }
        other => {
            if observed.present_classes.iter().any(|c| c == other) {
                EvidenceAvailability::Present
            } else if observed.partial_classes.iter().any(|c| c == other) {
                EvidenceAvailability::Partial
            } else if observed.unavailable_classes.iter().any(|c| c == other) {
                EvidenceAvailability::Unavailable
            } else {
                EvidenceAvailability::Missing
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{
        resolve_boundary, BoundaryContract, ContainmentClaimState, ContainmentReceipt,
        ContainmentResult, ResolveOpts,
    };

    fn resolved_fail_closed() -> ResolvedBoundary {
        let mut c = BoundaryContract::eval_example();
        c.fail_closed = true;
        resolve_boundary(&c, ResolveOpts::default())
            .unwrap()
            .with_run_id("run-test")
    }

    #[test]
    fn missing_evidence_fail_closed() {
        let b = resolved_fail_closed();
        let observed = ObservedEvidence::default();
        let report = evaluate_required_evidence(Some(&b), &observed);
        assert_eq!(report.status, EvidenceStatus::ContainmentUnproven);
        assert!(report.gate_failed);
        assert!(report
            .reasons
            .iter()
            .any(|r| r.contains("process") || r.contains("containment")));
    }

    #[test]
    fn configured_receipt_does_not_satisfy() {
        let b = resolved_fail_closed();
        let mut observed = ObservedEvidence {
            present_classes: vec!["process".into(), "network".into()],
            has_artifact_provenance: true,
            ..Default::default()
        };
        observed.containment_receipts.push(ContainmentReceipt::new(
            "run-test",
            ContainmentClaimState::Configured,
            ContainmentResult::NotObserved,
            "blackbox",
            "launch_record",
        ));
        let report = evaluate_required_evidence(Some(&b), &observed);
        assert_eq!(report.status, EvidenceStatus::ContainmentUnproven);
        assert!(report.gate_failed);
    }

    #[test]
    fn verified_held_and_all_sensors_sufficient() {
        let b = resolved_fail_closed();
        let mut observed = ObservedEvidence {
            present_classes: vec!["process".into(), "network".into()],
            has_artifact_provenance: true,
            ..Default::default()
        };
        let mut receipt = ContainmentReceipt::new(
            "run-test",
            ContainmentClaimState::Verified,
            ContainmentResult::Held,
            "canary",
            "post_run_canary",
        );
        receipt.scope.control = Some("network_egress".into());
        receipt.policy_hash = Some(b.policy_hash.clone());
        receipt.evidence_hashes.push("a".repeat(64));
        observed.containment_receipts.push(receipt);
        let report = evaluate_required_evidence(Some(&b), &observed);
        assert_eq!(report.status, EvidenceStatus::Sufficient);
        assert!(!report.gate_failed);
    }

    #[test]
    fn violation_outranks_sufficient_sensors() {
        let b = resolved_fail_closed();
        let mut observed = ObservedEvidence {
            present_classes: vec!["process".into(), "network".into()],
            has_artifact_provenance: true,
            ..Default::default()
        };
        let mut receipt = ContainmentReceipt::new(
            "run-test",
            ContainmentClaimState::Verified,
            ContainmentResult::Violated,
            "canary",
            "post_run_canary",
        );
        receipt.policy_hash = Some(b.policy_hash.clone());
        observed.containment_receipts.push(receipt);
        let report = evaluate_required_evidence(Some(&b), &observed);
        assert_eq!(report.status, EvidenceStatus::ContainmentViolated);
        assert!(report.gate_failed);
    }

    #[test]
    fn no_boundary_is_not_gate_failure() {
        let report = evaluate_required_evidence(None, &ObservedEvidence::default());
        assert_eq!(report.status, EvidenceStatus::NoBoundary);
        assert!(!report.gate_failed);
    }
}
