//! Versioned external adapter protocol (process/NDJSON) — 1.6 Phase F.

pub mod manifest;
pub mod validation;

pub use manifest::{AdapterManifest, ADAPTER_PROTOCOL};
// re-export for tests/docs
pub use validation::{validate_adapter_event, validate_adapter_manifest, ValidationReport};
