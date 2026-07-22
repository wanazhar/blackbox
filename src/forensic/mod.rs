//! Local forensic analysis packs (1.7).
//!
//! Build bounded, redacted packs with evidence citations for offline analysis.
//! Optional local model claims (`apply_model_analysis`) must cite existing
//! pointers and never replace original evidence. No hosted provider is required.

mod pack;

pub use pack::{
    apply_model_analysis, build_forensic_pack, validate_claim_citations, ForensicClaim,
    ForensicPack, ForensicPackOpts, ModelAnalysisInput, FORENSIC_PACK_SCHEMA,
};
