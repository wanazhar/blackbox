//! Agent boundary contracts, containment receipts, and evidence gates (1.7).
//!
//! Schema id: **`blackbox.boundary/v1`**.
//!
//! # What this module provides
//!
//! - **Contracts** — [`BoundaryContract`], [`resolve_boundary`], policy hash
//! - **Containment** — [`ContainmentReceipt`] claim states (configured ≠ verified)
//! - **Trust rollup** — [`build_boundary_trust`] for summary/score/gates
//! - **Detectors** — [`detect_boundary_findings`] deterministic violations
//! - **Quality corpus** — [`evaluate_detector_quality`] permanent FP/FN bar
//! - **Provenance** — [`evaluate_provenance`], [`auto_provenance_record`]
//!
//! Blackbox records what an agent was *authorized* to do and what evidence
//! supports that claim. It does **not** enforce sandbox/firewall policy by
//! default — see the threat model in `docs/plan/agent-boundary-1.7.md` and
//! operator guide `docs/guide/boundaries-and-incidents.md`.

mod auto_provenance;
mod canary;
mod containment;
mod contract;
mod correlate;
mod corpus;
mod detect;
mod evidence;
mod identity;
mod provenance;
mod resolve;
mod trust;
mod vocab;

pub use auto_provenance::{
    auto_provenance_record, declared_sources_from_experiment, observed_sources_from_evidence,
};
pub use canary::{
    launch_containment_receipts, post_run_canary_receipts, LaunchBackendInfo,
};
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
pub use corpus::{
    detector_corpus, evaluate_detector_quality, CaseExpectation, CaseResult, CorpusCase,
    QualityReport, MAX_BENIGN_FALSE_POSITIVES, MIN_PRECISION, MIN_RECALL,
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
pub use trust::{
    build_boundary_trust, trust_fails_score, BoundaryTrustView, BOUNDARY_TRUST_SCHEMA,
};
pub use vocab::{
    well_known, CapabilityToken, DataClassToken, Disposition, EffectToken, IdentityToken,
    ProvenanceToken, TargetToken, BOUNDARY_DISPOSITIONS,
};
