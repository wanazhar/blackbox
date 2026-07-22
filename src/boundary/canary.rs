//! Preflight / post-run containment canaries (1.7).
//!
//! These record honest containment claims. They do **not** enforce sandbox
//! policy — they only observe and emit receipts.
#![allow(missing_docs)]

use crate::boundary::{
    ContainmentClaimState, ContainmentReceipt, ContainmentResult, ContainmentScope,
    ResolvedBoundary,
};

/// Launch-backend description for canary receipts.
#[derive(Debug, Clone, Default)]
pub struct LaunchBackendInfo {
    pub backend: String,
    pub sandbox_id: Option<String>,
    pub control_versions: Vec<String>,
    /// True when a real isolation backend is active (e.g. bwrap).
    pub isolation_active: bool,
    /// True when network egress is believed restricted.
    pub network_restricted: bool,
}

/// Emit launch-record containment receipts for a run that has a boundary.
pub fn launch_containment_receipts(
    run_id: &str,
    boundary: Option<&ResolvedBoundary>,
    backend: &LaunchBackendInfo,
) -> Vec<ContainmentReceipt> {
    let mut out = Vec::new();
    let policy_hash = boundary.map(|b| b.policy_hash.clone());

    // Always record configured claim when a boundary exists.
    if boundary.is_some() {
        let mut r = ContainmentReceipt::new(
            run_id,
            ContainmentClaimState::Configured,
            ContainmentResult::NotObserved,
            "blackbox",
            "launch_record",
        );
        r.scope = ContainmentScope {
            control: Some("boundary_contract".into()),
            backend: Some(backend.backend.clone()),
            sandbox_id: backend.sandbox_id.clone(),
            label: Some("boundary_attached".into()),
        };
        r.policy_hash = policy_hash.clone();
        r.control_versions = backend.control_versions.clone();
        r.summary = Some("boundary contract stored with run".into());
        r.limitations
            .push("configuration is not verification".into());
        out.push(r);
    }

    // Isolation backend.
    let (state, result, summary) = if backend.isolation_active {
        (
            ContainmentClaimState::Enforced,
            ContainmentResult::Held,
            "isolation backend active at launch",
        )
    } else {
        (
            ContainmentClaimState::Unavailable,
            ContainmentResult::NotApplicable,
            "no isolation backend (recorder neutrality; containment not enforced)",
        )
    };
    let mut iso = ContainmentReceipt::new(
        run_id,
        state,
        result,
        "blackbox",
        "launch_record",
    );
    iso.scope = ContainmentScope {
        control: Some("process_isolation".into()),
        backend: Some(backend.backend.clone()),
        sandbox_id: backend.sandbox_id.clone(),
        label: None,
    };
    iso.policy_hash = policy_hash.clone();
    iso.summary = Some(summary.into());
    if !backend.isolation_active {
        iso.limitations
            .push("blackbox does not provide sandbox isolation by default".into());
    }
    out.push(iso);

    // Network control honesty.
    let (nstate, nresult, nsum) = if backend.network_restricted {
        (
            ContainmentClaimState::Enforced,
            ContainmentResult::Held,
            "network restriction declared at launch",
        )
    } else {
        (
            ContainmentClaimState::ObservedOnly,
            ContainmentResult::NotObserved,
            "network egress not restricted by blackbox",
        )
    };
    let mut net = ContainmentReceipt::new(run_id, nstate, nresult, "blackbox", "launch_record");
    net.scope = ContainmentScope {
        control: Some("network_egress".into()),
        backend: Some(backend.backend.clone()),
        sandbox_id: None,
        label: None,
    };
    net.policy_hash = policy_hash;
    net.summary = Some(nsum.into());
    net.limitations
        .push("verified network hold requires external canary or proxy evidence".into());
    out.push(net);

    out
}

/// Post-run canary: if external evidence shows public egress while boundary
/// prohibits it, emit a violated receipt; if required sensors present and no
/// violation, emit verified-held for observed controls only when evidence supports it.
pub fn post_run_canary_receipts(
    run_id: &str,
    boundary: Option<&ResolvedBoundary>,
    public_egress_observed: bool,
    process_evidence_present: bool,
) -> Vec<ContainmentReceipt> {
    let mut out = Vec::new();
    let policy_hash = boundary.map(|b| b.policy_hash.clone());
    let prohibits_public = boundary
        .map(|b| {
            b.contract
                .prohibited
                .iter()
                .any(|p| p == "public_network")
                || matches!(
                    b.contract.disposition_of("public_network"),
                    crate::boundary::Disposition::HardProhibition
                )
        })
        .unwrap_or(false);

    if public_egress_observed && prohibits_public {
        let mut r = ContainmentReceipt::new(
            run_id,
            ContainmentClaimState::Verified,
            ContainmentResult::Violated,
            "blackbox-canary",
            "post_run_canary",
        );
        r.scope = ContainmentScope {
            control: Some("network_egress".into()),
            backend: Some("evidence".into()),
            sandbox_id: None,
            label: Some("public_network".into()),
        };
        r.policy_hash = policy_hash.clone();
        r.summary = Some("public egress observed under hard prohibition".into());
        out.push(r);
    } else if process_evidence_present && !public_egress_observed && prohibits_public {
        // Honest: process capture without network sensors is **not** verified
        // network containment. Use ObservedOnly + NotObserved so required
        // `containment_receipt` gates cannot be satisfied by absence of egress.
        let mut r = ContainmentReceipt::new(
            run_id,
            ContainmentClaimState::ObservedOnly,
            ContainmentResult::NotObserved,
            "blackbox-canary",
            "post_run_canary",
        );
        r.scope = ContainmentScope {
            control: Some("network_egress".into()),
            backend: Some("capture".into()),
            sandbox_id: None,
            label: Some("no_public_egress_in_capture".into()),
        };
        r.policy_hash = policy_hash;
        r.summary = Some(
            "process evidence present; no prohibited public egress observed in capture window"
                .into(),
        );
        r.limitations.push(
            "absence of observed egress is not verified containment without a network sensor"
                .into(),
        );
        out.push(r);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{resolve_boundary, BoundaryContract, ResolveOpts};

    #[test]
    fn launch_records_configured_and_unavailable() {
        let b = resolve_boundary(&BoundaryContract::eval_example(), ResolveOpts::default())
            .unwrap()
            .with_run_id("r1");
        let receipts = launch_containment_receipts(
            "r1",
            Some(&b),
            &LaunchBackendInfo {
                backend: "none".into(),
                isolation_active: false,
                network_restricted: false,
                ..Default::default()
            },
        );
        assert!(receipts
            .iter()
            .any(|r| matches!(r.claim_state, ContainmentClaimState::Configured)));
        assert!(receipts
            .iter()
            .any(|r| matches!(r.claim_state, ContainmentClaimState::Unavailable)));
    }

    #[test]
    fn post_run_flags_violation() {
        let b = resolve_boundary(&BoundaryContract::eval_example(), ResolveOpts::default())
            .unwrap()
            .with_run_id("r1");
        let r = post_run_canary_receipts("r1", Some(&b), true, true);
        assert!(r
            .iter()
            .any(|x| matches!(x.result, ContainmentResult::Violated)));
    }

    #[test]
    fn process_only_does_not_satisfy_required_containment() {
        let b = resolve_boundary(&BoundaryContract::eval_example(), ResolveOpts::default())
            .unwrap()
            .with_run_id("r1");
        let r = post_run_canary_receipts("r1", Some(&b), false, true);
        assert!(!r.is_empty());
        assert!(
            r.iter().all(|x| !x.satisfies_required_containment()),
            "process-only canary must not satisfy required containment_receipt"
        );
    }
}
