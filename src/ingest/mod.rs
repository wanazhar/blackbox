//! Durable event ingest spool and recovery (1.6 Phase B).

pub mod recovery;
pub mod spool;

pub use recovery::{recover_spool_on_open, RecoveryStats};
pub use spool::{
    inspect_spool, EventSpool, SpoolAppendResult, SpoolBatch, SpoolHealth, SpoolInspectInfo,
    SPOOL_VERSION,
};
