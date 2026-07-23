//! Native run/event ingestion without PTY process wrapping (1.9).
//!
//! Harnesses embed [`NativeRecorder`] in-process, or send
//! [`blackbox.native.ingest/v1`](crate::protocol) envelopes over bounded NDJSON
//! or a local Unix socket. Process wrapping remains available as an independent
//! observation source.
//!
//! This module depends on [`TraceStore`](crate::storage::TraceStore) and core
//! types only — never clap CLI types or SQLite concrete types at the API
//! boundary.

pub mod envelope;
pub mod ndjson;
pub mod recorder;
pub mod unix_socket;

pub use envelope::{
    IngestAck, IngestError, IngestOp, NativeIngestEnvelope, NATIVE_INGEST_SCHEMA,
};
pub use ndjson::{NdjsonIngestError, NdjsonIngestServer};
pub use recorder::{
    FinishRunOpts, NativeRecorder, NativeRecorderConfig, RecordEventOpts, StartRunOpts,
};
pub use unix_socket::{UnixIngestServer, UnixIngestServerConfig};
