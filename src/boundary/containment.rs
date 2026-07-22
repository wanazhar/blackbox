//! Containment claims and immutable receipts (1.7 Phase B schema).
//!
//! Containment is represented as independent claims — configuration is never
//! silently equated with enforcement or verification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Schema identifier for containment receipts.
pub const CONTAINMENT_RECEIPT_SCHEMA: &str = "blackbox.containment.receipt/v1";

/// Independent containment claim state.
///
/// These are intentionally distinct: a control may be configured without ever
/// being enforced or verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentClaimState {
    /// Declared in launch/config; not proven.
    Configured,
    /// Control actively applied at launch (e.g. cgroup, bwrap, proxy).
    Enforced,
    /// Independent check confirmed the control held.
    Verified,
    /// Seen in telemetry only; not authorized as a control.
    ObservedOnly,
    /// Control was attempted and failed.
    Failed,
    /// State cannot be determined from available evidence.
    Unknown,
    /// Control not available on this platform/backend.
    Unavailable,
}

impl ContainmentClaimState {
    /// Stable snake_case form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Enforced => "enforced",
            Self::Verified => "verified",
            Self::ObservedOnly => "observed_only",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Result of a containment check (distinct from claim state lifecycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentResult {
    /// Restriction held under the declared method.
    Held,
    /// Restriction did not hold (escape or misconfiguration).
    Violated,
    /// Command denied by policy (distinct from network unreachable).
    Denied,
    /// Destination unreachable (not the same as denied).
    Unreachable,
    /// Check could not be completed.
    Inconclusive,
    /// Not observed (sensor gap).
    NotObserved,
    /// Method not applicable on this platform.
    NotApplicable,
}

impl ContainmentResult {
    /// Stable snake_case form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Violated => "violated",
            Self::Denied => "denied",
            Self::Unreachable => "unreachable",
            Self::Inconclusive => "inconclusive",
            Self::NotObserved => "not_observed",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// What a containment receipt covers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentScope {
    /// Control name (e.g. `network_egress`, `filesystem_mount`, `credential_isolation`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<String>,
    /// Launch backend (e.g. `bwrap`, `cgroup_v2`, `proxy`, `none`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Namespace / cgroup / sandbox identity when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
    /// Free-form scope label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Immutable containment receipt. Later checks append; they never rewrite prior evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainmentReceipt {
    /// Schema id.
    pub schema: String,
    /// Unique receipt id.
    pub id: String,
    /// Owning run id.
    pub run_id: String,
    /// When the receipt was recorded.
    pub created_at: DateTime<Utc>,
    /// Claim state for this receipt.
    pub claim_state: ContainmentClaimState,
    /// Check result.
    pub result: ContainmentResult,
    /// Who/what produced the receipt (binary, sensor, operator).
    pub verifier_identity: String,
    /// Method used (`preflight_canary`, `post_run_canary`, `launch_record`, `import`, …).
    pub method: String,
    /// Scope of the claim.
    #[serde(default)]
    pub scope: ContainmentScope,
    /// When the check ran (may differ from created_at).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<DateTime<Utc>>,
    /// Content hashes of supporting evidence blobs (sha256 hex).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_hashes: Vec<String>,
    /// Control / policy version strings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub control_versions: Vec<String>,
    /// Optional parent receipt for lineage (re-check).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    /// Related boundary policy hash when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// Human summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Explicit limitations / uncertainty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

impl ContainmentReceipt {
    /// Create a new receipt skeleton for a run.
    pub fn new(
        run_id: impl Into<String>,
        claim_state: ContainmentClaimState,
        result: ContainmentResult,
        verifier_identity: impl Into<String>,
        method: impl Into<String>,
    ) -> Self {
        Self {
            schema: CONTAINMENT_RECEIPT_SCHEMA.into(),
            id: format!("contain-{}", Uuid::new_v4()),
            run_id: run_id.into(),
            created_at: Utc::now(),
            claim_state,
            result,
            verifier_identity: verifier_identity.into(),
            method: method.into(),
            scope: ContainmentScope::default(),
            checked_at: None,
            evidence_hashes: Vec::new(),
            control_versions: Vec::new(),
            parent_receipt_id: None,
            policy_hash: None,
            summary: None,
            limitations: Vec::new(),
        }
    }

    /// True when this receipt asserts verified containment that held.
    pub fn is_verified_held(&self) -> bool {
        matches!(self.claim_state, ContainmentClaimState::Verified)
            && matches!(self.result, ContainmentResult::Held)
    }

    /// True when a receipt may satisfy a **required** `containment_receipt`
    /// evidence class.
    ///
    /// Passing task verification is independent of containment — this helper
    /// never inspects task success.
    ///
    /// Only **verified + held** claims on a real control (not mere process
    /// observation / bookkeeping) count. Network-required contracts must not
    /// be satisfied by process-only observations.
    pub fn satisfies_required_containment(&self) -> bool {
        if !self.is_verified_held() {
            return false;
        }
        match self.scope.control.as_deref() {
            None | Some("") => false,
            Some("process_observation") | Some("boundary_contract") => false,
            Some(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_roundtrip() {
        let mut r = ContainmentReceipt::new(
            "run-1",
            ContainmentClaimState::Configured,
            ContainmentResult::NotObserved,
            "blackbox",
            "launch_record",
        );
        r.scope.control = Some("network_egress".into());
        r.scope.backend = Some("none".into());
        r.limitations
            .push("no network sensor attached".into());
        let json = serde_json::to_string(&r).unwrap();
        let back: ContainmentReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
        assert!(!back.satisfies_required_containment());
    }

    #[test]
    fn verified_held_satisfies() {
        let r = ContainmentReceipt::new(
            "run-1",
            ContainmentClaimState::Verified,
            ContainmentResult::Held,
            "canary",
            "post_run_canary",
        );
        assert!(r.satisfies_required_containment());
    }

    #[test]
    fn configured_is_not_verified() {
        assert_ne!(
            ContainmentClaimState::Configured.as_str(),
            ContainmentClaimState::Verified.as_str()
        );
        assert_ne!(
            ContainmentClaimState::Enforced.as_str(),
            ContainmentClaimState::Verified.as_str()
        );
    }
}
