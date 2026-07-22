//! Local forensic analysis packs (1.7 Phase H).

mod pack;

pub use pack::{
    build_forensic_pack, validate_claim_citations, ForensicClaim, ForensicPack, ForensicPackOpts,
    FORENSIC_PACK_SCHEMA,
};
