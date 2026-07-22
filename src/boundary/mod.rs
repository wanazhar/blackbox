//! Agent boundary contracts, containment receipts, and evidence gates (1.7).
//!
//! Schema id: **`blackbox.boundary/v1`**.
//!
//! Blackbox records what an agent was *authorized* to do and what evidence
//! supports that claim. It does **not** enforce sandbox/firewall policy by
//! default — see the threat model in `docs/plan/agent-boundary-1.7.md`.

mod containment;
mod contract;
mod correlate;
mod detect;
mod evidence;
mod identity;
mod provenance;
mod resolve;
mod vocab;

pub use containment::{
    ContainmentClaimState, ContainmentReceipt, ContainmentResult, ContainmentScope,
};
pub use contract::{
    AllowedResources, BoundaryContract, BOUNDARY_SCHEMA, DispositionMap,
};
pub use correlate::{
    correlate_external_batch, correlate_external_event, CorrelationContext, EntityKind,
    EvidenceEdge, EvidenceRelation, EVIDENCE_EDGE_SCHEMA,
};
pub use detect::{
    detect_boundary_findings, BoundaryFinding, DetectInputs, FindingKind, FindingSeverity,
    BOUNDARY_FINDING_SCHEMA,
};
pub use evidence::{
    evaluate_required_evidence, BoundaryEvidenceReport, EvidenceAvailability,
    EvidenceRequirement, EvidenceStatus, ObservedEvidence, BOUNDARY_EVAL_SCHEMA,
};
pub use identity::{
    PropagationChannel, PropagationRecord, PropagationStatus, TraceIdentity,
    TRACE_IDENTITY_SCHEMA,
};
pub use provenance::{
    evaluate_provenance, record_from_observations, ProvenanceGateReport, ProvenanceKind,
    ProvenanceRecord, ProvenanceStatus, PROVENANCE_EVAL_SCHEMA, PROVENANCE_SCHEMA,
};
pub use resolve::{
    load_boundary_file, resolve_boundary, ResolvedBoundary, ResolveOpts,
};
pub use vocab::{
    well_known, CapabilityToken, DataClassToken, Disposition, EffectToken, IdentityToken,
    ProvenanceToken, TargetToken, BOUNDARY_DISPOSITIONS,
};
