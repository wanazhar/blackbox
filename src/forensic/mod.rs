//! Local forensic analysis packs (1.7 Phase H).

mod pack;

pub use pack::{
    apply_model_analysis, build_forensic_pack, validate_claim_citations, ForensicClaim,
    ForensicPack, ForensicPackOpts, ModelAnalysisInput, FORENSIC_PACK_SCHEMA,
};
