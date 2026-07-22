//! External evidence ingestion (1.7 Phase C).
//!
//! Schema: **`blackbox.evidence.event/v1`**.
//!
//! Imports kernel/network/proxy/container/cloud/identity telemetry as
//! versioned, integrity-checked NDJSON without reimplementing those sensors.

mod adapters;
mod event;
mod import;

pub use adapters::map_sensor_event;
pub use event::{
    ClockUncertainty, EvidenceAction, EvidenceIntegrity, EvidenceOutcome, ExternalEvidenceEvent,
    ExternalIdentity, EVIDENCE_EVENT_SCHEMA,
};
pub use import::{
    import_evidence_ndjson, import_evidence_ndjson_str, ImportOptions, ImportReport,
    ImportReject, MAX_EVIDENCE_IMPORT_BYTES, MAX_EVIDENCE_IMPORT_EVENTS,
};
