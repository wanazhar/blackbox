//! Calibrated finding decisions (1.8).
//!
//! Severity is derived from observation + policy + integrity + confidence +
//! effect. `deterministic_detector` describes algorithm repeatability only and
//! must not be treated as confidence evidence.

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use crate::core::event::Confidence;
use crate::evidence::EvidenceIntegrity;

use super::vocab::Disposition;

/// Severity recommendation for a boundary finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warn,
    High,
    Critical,
}

impl FindingSeverity {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Schema for the decision object embedded in findings.
pub const FINDING_DECISION_SCHEMA: &str = "blackbox.boundary.finding.decision/v1";

/// Whether the observation constitutes a policy violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationState {
    /// Confirmed violation under the resolved policy.
    Violation,
    /// Observation is allowed by policy.
    Allowed,
    /// Not enough evidence to decide.
    InsufficientEvidence,
    /// Observation noted; not evaluated as a violation.
    ObservedOnly,
    /// Ambiguous (e.g. doc mention vs verified read).
    Ambiguous,
    /// No violation determination (informational transition).
    NotApplicable,
}

impl ViolationState {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Violation => "violation",
            Self::Allowed => "allowed",
            Self::InsufficientEvidence => "insufficient_evidence",
            Self::ObservedOnly => "observed_only",
            Self::Ambiguous => "ambiguous",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Coarse observed effect class used for severity calibration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedEffect {
    None,
    Read,
    Write,
    NetworkEgress,
    CredentialUse,
    PrivilegeGain,
    Persistence,
    PackageInstall,
    ProcessExec,
    Unknown,
}

impl ObservedEffect {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Read => "read",
            Self::Write => "write",
            Self::NetworkEgress => "network_egress",
            Self::CredentialUse => "credential_use",
            Self::PrivilegeGain => "privilege_gain",
            Self::Persistence => "persistence",
            Self::PackageInstall => "package_install",
            Self::ProcessExec => "process_exec",
            Self::Unknown => "unknown",
        }
    }
}

/// Evidence integrity class for confidence calibration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceIntegrityClass {
    Unverified,
    Transformed,
    HashVerified,
    SignatureVerified,
    SignedInvalid,
}

impl EvidenceIntegrityClass {
    /// Map from imported external evidence integrity.
    pub fn from_evidence(i: EvidenceIntegrity) -> Self {
        match i {
            EvidenceIntegrity::Unverified => Self::Unverified,
            EvidenceIntegrity::Transformed => Self::Transformed,
            EvidenceIntegrity::HashOk => Self::HashVerified,
            EvidenceIntegrity::SignedVerified => Self::SignatureVerified,
            EvidenceIntegrity::SignedInvalid => Self::SignedInvalid,
        }
    }

    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Transformed => "transformed",
            Self::HashVerified => "hash_verified",
            Self::SignatureVerified => "signature_verified",
            Self::SignedInvalid => "signed_invalid",
        }
    }

    /// Numeric strength for calibration (higher = more trusted).
    pub fn strength(self) -> u8 {
        match self {
            Self::SignatureVerified => 4,
            Self::HashVerified => 3,
            Self::Transformed => 2,
            Self::Unverified => 1,
            Self::SignedInvalid => 0,
        }
    }
}

/// Finding decision object separating observation from interpretation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingDecision {
    /// Schema id for the decision object.
    #[serde(default = "default_decision_schema")]
    pub schema: String,
    /// What was observed (short, redaction-safe description).
    pub observation: String,
    /// Policy disposition for the relevant token.
    pub policy_disposition: Disposition,
    /// Strongest evidence integrity among cited external evidence.
    pub evidence_integrity: EvidenceIntegrityClass,
    /// Confidence in agent/principal identity binding.
    pub identity_confidence: Confidence,
    /// Confidence in correlation of intent to effect.
    pub correlation_confidence: Confidence,
    /// Observed effect class.
    pub observed_effect: ObservedEffect,
    /// Whether this is a violation.
    pub violation_state: ViolationState,
    /// Derived severity (must match parent finding.severity).
    pub severity: FindingSeverity,
    /// Human/machine reasons for the decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    /// Algorithm repeatability note — not confidence evidence.
    #[serde(default = "default_repeatability")]
    pub detector_repeatability: String,
}

fn default_decision_schema() -> String {
    FINDING_DECISION_SCHEMA.into()
}

fn default_repeatability() -> String {
    "deterministic_detector".into()
}

impl FindingDecision {
    /// Build a decision and derive severity + violation state.
    pub fn calibrate(input: DecisionInput<'_>) -> Self {
        let mut reasons = input.reasons.to_vec();
        let violation_state = derive_violation_state(
            input.policy_disposition,
            input.evidence_integrity,
            input.correlation_confidence,
            input.force_violation_state,
            &mut reasons,
        );
        let severity = derive_severity(
            violation_state,
            input.policy_disposition,
            input.evidence_integrity,
            input.identity_confidence,
            input.correlation_confidence,
            input.observed_effect,
            &mut reasons,
        );
        Self {
            schema: FINDING_DECISION_SCHEMA.into(),
            observation: input.observation.into(),
            policy_disposition: input.policy_disposition,
            evidence_integrity: input.evidence_integrity,
            identity_confidence: input.identity_confidence,
            correlation_confidence: input.correlation_confidence,
            observed_effect: input.observed_effect,
            violation_state,
            severity,
            reasons,
            detector_repeatability: "deterministic_detector".into(),
        }
    }
}

/// Inputs for severity / violation calibration.
#[derive(Debug, Clone)]
pub struct DecisionInput<'a> {
    pub observation: &'a str,
    pub policy_disposition: Disposition,
    pub evidence_integrity: EvidenceIntegrityClass,
    pub identity_confidence: Confidence,
    pub correlation_confidence: Confidence,
    pub observed_effect: ObservedEffect,
    pub reasons: &'a [String],
    /// Optional override when the detector already classified ambiguity.
    pub force_violation_state: Option<ViolationState>,
}

impl Default for DecisionInput<'_> {
    fn default() -> Self {
        Self {
            observation: "",
            policy_disposition: Disposition::Unknown,
            evidence_integrity: EvidenceIntegrityClass::Unverified,
            identity_confidence: Confidence::Unknown,
            correlation_confidence: Confidence::Unknown,
            observed_effect: ObservedEffect::Unknown,
            reasons: &[],
            force_violation_state: None,
        }
    }
}

fn confidence_is_strong(c: Confidence) -> bool {
    matches!(c, Confidence::Confirmed | Confidence::StronglyCorrelated)
}

fn confidence_is_weak(c: Confidence) -> bool {
    matches!(c, Confidence::Unknown | Confidence::WeaklyCorrelated)
}

fn derive_violation_state(
    disposition: Disposition,
    integrity: EvidenceIntegrityClass,
    correlation: Confidence,
    force: Option<ViolationState>,
    reasons: &mut Vec<String>,
) -> ViolationState {
    if let Some(v) = force {
        reasons.push(format!("violation_state_forced:{}", v.as_str()));
        return v;
    }
    match disposition {
        Disposition::Allowed => {
            reasons.push("disposition_allowed".into());
            ViolationState::Allowed
        }
        Disposition::ObservedOnly => {
            reasons.push("disposition_observed_only".into());
            ViolationState::ObservedOnly
        }
        Disposition::Unknown => {
            if matches!(correlation, Confidence::Confirmed)
                && integrity.strength() >= EvidenceIntegrityClass::HashVerified.strength()
            {
                reasons.push("unknown_disposition_with_strong_evidence".into());
                ViolationState::Ambiguous
            } else {
                reasons.push("unknown_disposition".into());
                ViolationState::InsufficientEvidence
            }
        }
        Disposition::HardProhibition | Disposition::ApprovalRequired => {
            if integrity == EvidenceIntegrityClass::SignedInvalid {
                reasons.push("signed_invalid_insufficient".into());
                return ViolationState::InsufficientEvidence;
            }
            // Unverified evidence cannot alone confirm a critical hard prohibition
            // without at least plausible correlation.
            if integrity == EvidenceIntegrityClass::Unverified && confidence_is_weak(correlation) {
                reasons.push("unverified_weak_correlation".into());
                ViolationState::Ambiguous
            } else {
                reasons.push("prohibited_disposition".into());
                ViolationState::Violation
            }
        }
    }
}

fn derive_severity(
    violation: ViolationState,
    disposition: Disposition,
    integrity: EvidenceIntegrityClass,
    identity: Confidence,
    correlation: Confidence,
    effect: ObservedEffect,
    reasons: &mut Vec<String>,
) -> FindingSeverity {
    match violation {
        ViolationState::Allowed | ViolationState::NotApplicable => {
            reasons.push("severity_info_non_violation".into());
            FindingSeverity::Info
        }
        ViolationState::ObservedOnly => {
            reasons.push("severity_info_observed_only".into());
            FindingSeverity::Info
        }
        ViolationState::InsufficientEvidence => {
            reasons.push("severity_warn_insufficient_evidence".into());
            FindingSeverity::Warn
        }
        ViolationState::Ambiguous => {
            reasons.push("severity_warn_ambiguous".into());
            FindingSeverity::Warn
        }
        ViolationState::Violation => {
            // Critical only when hard prohibition + strong evidence + identity confirmed
            // + high-impact effect.
            let hard = matches!(disposition, Disposition::HardProhibition);
            let strong_integrity =
                integrity.strength() >= EvidenceIntegrityClass::HashVerified.strength();
            let id_ok = confidence_is_strong(identity);
            let corr_ok = confidence_is_strong(correlation);
            let high_impact = matches!(
                effect,
                ObservedEffect::CredentialUse
                    | ObservedEffect::PrivilegeGain
                    | ObservedEffect::Persistence
                    | ObservedEffect::NetworkEgress
            );
            if hard && strong_integrity && id_ok && corr_ok && high_impact {
                reasons.push("severity_critical_hard_verified".into());
                FindingSeverity::Critical
            } else if hard && (strong_integrity || matches!(correlation, Confidence::Confirmed)) {
                reasons.push("severity_high_hard_prohibition".into());
                FindingSeverity::High
            } else if matches!(disposition, Disposition::ApprovalRequired) {
                reasons.push("severity_high_approval_required".into());
                FindingSeverity::High
            } else {
                reasons.push("severity_warn_violation_weak_evidence".into());
                FindingSeverity::Warn
            }
        }
    }
}

/// Pick the strongest integrity class among a set of external events.
pub fn strongest_integrity(
    integrities: impl IntoIterator<Item = EvidenceIntegrity>,
) -> EvidenceIntegrityClass {
    integrities
        .into_iter()
        .map(EvidenceIntegrityClass::from_evidence)
        .max_by_key(|c| c.strength())
        .unwrap_or(EvidenceIntegrityClass::Unverified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_credential_not_violation() {
        let d = FindingDecision::calibrate(DecisionInput {
            observation: "synthetic credential access",
            policy_disposition: Disposition::Allowed,
            evidence_integrity: EvidenceIntegrityClass::SignatureVerified,
            identity_confidence: Confidence::Confirmed,
            correlation_confidence: Confidence::Confirmed,
            observed_effect: ObservedEffect::CredentialUse,
            reasons: &[],
            force_violation_state: None,
        });
        assert_eq!(d.violation_state, ViolationState::Allowed);
        assert_eq!(d.severity, FindingSeverity::Info);
    }

    #[test]
    fn unverified_credential_not_confirmed_critical() {
        let d = FindingDecision::calibrate(DecisionInput {
            observation: "credential access",
            policy_disposition: Disposition::HardProhibition,
            evidence_integrity: EvidenceIntegrityClass::Unverified,
            identity_confidence: Confidence::Unknown,
            correlation_confidence: Confidence::WeaklyCorrelated,
            observed_effect: ObservedEffect::CredentialUse,
            reasons: &[],
            force_violation_state: None,
        });
        assert_ne!(d.severity, FindingSeverity::Critical);
        // Weak correlation + unverified → ambiguous, not critical.
        assert_eq!(d.violation_state, ViolationState::Ambiguous);
        assert_eq!(d.severity, FindingSeverity::Warn);
    }

    #[test]
    fn hard_prohibition_verified_can_be_critical() {
        let d = FindingDecision::calibrate(DecisionInput {
            observation: "production credential read",
            policy_disposition: Disposition::HardProhibition,
            evidence_integrity: EvidenceIntegrityClass::SignatureVerified,
            identity_confidence: Confidence::Confirmed,
            correlation_confidence: Confidence::Confirmed,
            observed_effect: ObservedEffect::CredentialUse,
            reasons: &[],
            force_violation_state: None,
        });
        assert_eq!(d.violation_state, ViolationState::Violation);
        assert_eq!(d.severity, FindingSeverity::Critical);
    }

    #[test]
    fn doc_mention_vs_verified_read() {
        let doc = FindingDecision::calibrate(DecisionInput {
            observation: "documentation mentions .ssh",
            policy_disposition: Disposition::HardProhibition,
            evidence_integrity: EvidenceIntegrityClass::Unverified,
            identity_confidence: Confidence::Unknown,
            correlation_confidence: Confidence::Unknown,
            observed_effect: ObservedEffect::None,
            reasons: &[],
            force_violation_state: Some(ViolationState::Ambiguous),
        });
        assert_eq!(doc.severity, FindingSeverity::Warn);

        let read = FindingDecision::calibrate(DecisionInput {
            observation: "verified filesystem read of ~/.ssh/id_rsa",
            policy_disposition: Disposition::HardProhibition,
            evidence_integrity: EvidenceIntegrityClass::HashVerified,
            identity_confidence: Confidence::Confirmed,
            correlation_confidence: Confidence::Confirmed,
            observed_effect: ObservedEffect::CredentialUse,
            reasons: &[],
            force_violation_state: None,
        });
        assert_eq!(read.severity, FindingSeverity::Critical);
    }

    #[test]
    fn deterministic_note_is_repeatability_not_confidence() {
        let d = FindingDecision::calibrate(DecisionInput {
            observation: "x",
            policy_disposition: Disposition::HardProhibition,
            evidence_integrity: EvidenceIntegrityClass::Unverified,
            identity_confidence: Confidence::Unknown,
            correlation_confidence: Confidence::WeaklyCorrelated,
            observed_effect: ObservedEffect::NetworkEgress,
            reasons: &[],
            force_violation_state: None,
        });
        assert_eq!(d.detector_repeatability, "deterministic_detector");
        // Repeatability string must not inflate severity.
        assert_ne!(d.severity, FindingSeverity::Critical);
    }
}
