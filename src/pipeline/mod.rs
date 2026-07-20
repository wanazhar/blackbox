//! Capture pipeline: single-writer event ingress and sequencing.

mod batch_ingest;
mod event_writer;

pub use batch_ingest::{
    is_barrier_kind, BatchIngestConfig, BatchIngestHealth, BatchIngestor, DEFAULT_BATCH_SIZE,
    DEFAULT_FLUSH_INTERVAL, DEFAULT_QUEUE_CAPACITY,
};
pub use event_writer::{EventWriter, WriterHealth};
