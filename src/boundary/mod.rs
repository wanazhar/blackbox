//! Agent boundary contracts, containment receipts, and evidence gates (1.7+).
//!
//! Schema id: **`blackbox.boundary/v1`**.
//!
//! # What this module provides
//!
//! - **Contracts** — [`BoundaryContract`], [`resolve_boundary`], policy hash
//! - **Typed selectors (1.8)** — [`ResourceSelector`], canonical matching
//! - **Containment** — [`ContainmentReceipt`] claim states (configured ≠ verified)
//! - **Trust rollup** — [`build_boundary_trust`] for summary/score/gates
//! - **Detectors** — [`detect_boundary_findings`] deterministic violations
//! - **Calibrated findings (1.8)** — [`FindingDecision`] separates observation from severity
//! - **Quality corpus** — [`evaluate_detector_quality`] permanent FP/FN bar
//! - **Provenance** — [`evaluate_provenance`], [`auto_provenance_record`]
//!
//! Blackbox records what an agent was *authorized* to do and what evidence
//! supports that claim. It does **not** enforce sandbox/firewall policy by
//! default — see the threat model in `docs/plan/agent-boundary-1.7.md` and
//! operator guide `docs/guide/boundaries-and-incidents.md`.

mod auto_provenance;
mod benchmark;
mod canary;
mod containment;
mod contract;
mod corpus;
mod correlate;
mod detect;
mod evidence;
mod finding;
mod identity;
mod lint;
mod normalize;
mod provenance;
mod resolve;
mod selector;
mod trust;
mod vocab;

pub use auto_provenance::{
    auto_provenance_record, declared_sources_from_experiment, observed_sources_from_evidence,
};
pub use benchmark::{
    evaluate_frozen_benchmark, label_layer, BenchmarkReport, EvidenceLayer, IntegrityClassStats,
    SeverityCalibrationRow, BENCHMARK_VERSION, FROZEN_SCENARIO_IDS,
};
pub use canary::{launch_containment_receipts, post_run_canary_receipts, LaunchBackendInfo};
pub use containment::{
    ContainmentClaimState, ContainmentReceipt, ContainmentResult, ContainmentScope,
    CONTAINMENT_RECEIPT_SCHEMA,
};
pub use contract::{AllowedResources, BoundaryContract, DispositionMap, BOUNDARY_SCHEMA};
pub use corpus::{
    detector_corpus, evaluate_detector_quality, CaseExpectation, CaseResult, CorpusCase,
    QualityReport, MAX_BENIGN_FALSE_POSITIVES, MIN_PRECISION, MIN_RECALL,
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
    evaluate_required_evidence, BoundaryEvidenceReport, EvidenceAvailability, EvidenceRequirement,
    EvidenceStatus, ObservedEvidence, BOUNDARY_EVAL_SCHEMA,
};
pub use finding::{
    strongest_integrity, DecisionInput, EvidenceIntegrityClass, FindingDecision, ObservedEffect,
    ViolationState, FINDING_DECISION_SCHEMA,
};
pub use identity::{
    PropagationChannel, PropagationRecord, PropagationStatus, TraceIdentity, TRACE_IDENTITY_SCHEMA,
};
pub use lint::{
    explain_boundary_policy, lint_boundary_contract, nearest_token, LintDiagnostic, LintLevel,
    LintReport, OverriddenValue, PolicyExplanation, PolicySourceLayer, PolicyValueResolution,
    TokenResolution, CORE_CAPABILITY_TOKENS, CORE_EVIDENCE_TOKENS,
};
pub use normalize::{
    host_matches_exact, host_matches_suffix, normalize_cidr, normalize_host, normalize_ip,
    normalize_path, normalize_port, normalize_url, observation_host, CanonicalHost, CanonicalUrl,
    NormalizeOutcome,
};
pub use provenance::{
    evaluate_provenance, record_from_observations, ProvenanceGateReport, ProvenanceKind,
    ProvenanceRecord, ProvenanceStatus, PROVENANCE_EVAL_SCHEMA, PROVENANCE_SCHEMA,
};
pub use resolve::{
    load_boundary_file, policy_hash_of, resolve_boundary, ResolveOpts, ResolvedBoundary,
};
pub use selector::{
    match_network_selector, match_path_selector, match_token_selector, network_entries_allow,
    MatchDecision, MatchExplanation, ResourceEntry, ResourceSelector, RESOURCE_SELECTOR_SCHEMA,
};
pub use trust::{
    build_boundary_trust, trust_fails_score, BoundaryTrustView, BOUNDARY_TRUST_SCHEMA,
};
pub use vocab::{
    well_known, CapabilityToken, DataClassToken, Disposition, EffectToken, IdentityToken,
    ProvenanceToken, TargetToken, BOUNDARY_DISPOSITIONS,
};
