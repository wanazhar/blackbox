//! Local forensic analysis packs (1.7–1.8).
//!
//! Build bounded, redacted packs with evidence citations for offline analysis.
//! 1.8 adds citation-complete selection, scope accounting, typed redaction, and
//! optional project-keyed HMAC secret tokens. Optional local model claims
//! (`apply_model_analysis`) must cite existing pointers and never replace
//! original evidence. No hosted provider is required.

mod pack;

pub use pack::{
    apply_model_analysis, build_forensic_pack, build_forensic_pack_result,
    build_forensic_pack_with_trust, build_forensic_pack_with_trust_result,
    validate_claim_citations, validate_forensic_pack, ForensicClaim, ForensicPack,
    ForensicPackOpts, ForensicPackScope, ModelAnalysisInput, SecretTokenMode, UnavailableCitation,
    FORENSIC_PACK_SCHEMA, SELECTION_STRATEGY_HEAD_TAIL_CITED_GRAPH,
};
