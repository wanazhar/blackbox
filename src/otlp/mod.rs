//! OpenTelemetry interoperability foundation (1.9).
//!
//! OTel is used as transport/interoperability, **not** as a replacement for
//! Blackbox semantics. Export preserves Blackbox attributes under the
//! `blackbox.*` namespace; concepts that cannot round-trip appear in an explicit
//! loss ledger.

pub mod export;
pub mod import;
pub mod loss;

pub use export::{export_run_to_otlp, OtlpExportOptions, OtlpResourceSpans};
pub use import::{import_otlp_as_evidence, OtlpImportReport};
pub use loss::{LossEntry, LossLedger, OTLP_LOSS_SCHEMA};
