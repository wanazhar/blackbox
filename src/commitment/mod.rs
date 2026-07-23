//! Run evidence commitments: event hashes, append-only chains, optional signatures (1.9).
//!
//! # Honesty
//!
//! Integrity commitments prove **record consistency after commitment**. They do
//! **not** prove completeness of observation, truth of external systems, or that
//! denied actions could not occur outside the recorder's view.

pub mod chain;
pub mod event_hash;
pub mod sign;
pub mod verify;

pub use chain::{
    build_run_commitment, ChainLink, RunCommitment, RunCommitmentBuilder, COMMITMENT_RUN_SCHEMA,
    GENESIS_PREV_HASH,
};
pub use event_hash::{event_content_hash, hash_hex, EventHashInput};
pub use sign::{
    generate_signing_key, public_key_hex, sign_run_root, verify_run_root_signature, SignatureStatus,
    SignedRunRoot,
};
pub use verify::{
    verify_chain, verify_commitment, ChainFault, ChainVerifyReport, CommitmentVerifyReport,
};
