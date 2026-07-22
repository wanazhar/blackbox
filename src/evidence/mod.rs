//! External evidence ingestion (1.7).
//!
//! Schema: **`blackbox.evidence.event/v1`**.
//!
//! # Safety
//!
//! Imports are **bounded**, **idempotent** on `(source, source_event_id)`,
//! and reject absolute/traversal path attributes used as loadable file refs.
//! Sensors are adapters (Falco-like, HTTP proxy, process audit, generic JSONL);
//! Blackbox does not run those agents itself.
//!
//! Operator docs: `docs/guide/boundaries-and-incidents.md` · reference
//! `docs/reference/boundary.md`.

mod adapters;
mod event;
mod import;

pub use adapters::map_sensor_event;
pub use event::{
    ClockUncertainty, EvidenceAction, EvidenceIntegrity, EvidenceOutcome, ExternalEvidenceEvent,
    ExternalIdentity, EVIDENCE_EVENT_SCHEMA, TELEMETRY_ANOMALY_ATTRIBUTE,
    TELEMETRY_ANOMALY_SIGNED_INVALID, TELEMETRY_ANOMALY_SOURCE_IDENTITY_CONFLICT,
};
pub use import::{
    import_evidence_ndjson, import_evidence_ndjson_str, ImportOptions, ImportReject, ImportReport,
    MAX_EVIDENCE_IMPORT_BYTES, MAX_EVIDENCE_IMPORT_EVENTS,
};
