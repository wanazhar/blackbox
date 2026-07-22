//! Agent boundary contracts, containment receipts, and evidence gates (1.7).
//!
//! Schema id: **`blackbox.boundary/v1`**.
//!
//! Blackbox records what an agent was *authorized* to do and what evidence
//! supports that claim. It does **not** enforce sandbox/firewall policy by
//! default — see the threat model in `docs/plan/agent-boundary-1.7.md`.

mod containment;
mod contract;
mod evidence;
mod resolve;
mod vocab;

pub use containment::{
    ContainmentClaimState, ContainmentReceipt, ContainmentResult, ContainmentScope,
};
pub use contract::{
    AllowedResources, BoundaryContract, BOUNDARY_SCHEMA, DispositionMap,
};
pub use evidence::{
    evaluate_required_evidence, BoundaryEvidenceReport, EvidenceAvailability,
    EvidenceRequirement, EvidenceStatus, ObservedEvidence, BOUNDARY_EVAL_SCHEMA,
};
pub use resolve::{
    load_boundary_file, resolve_boundary, ResolvedBoundary, ResolveOpts,
};
pub use vocab::{
    well_known, CapabilityToken, DataClassToken, Disposition, EffectToken, IdentityToken,
    ProvenanceToken, TargetToken, BOUNDARY_DISPOSITIONS,
};
