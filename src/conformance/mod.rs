//! Machine-readable protocol conformance runner (1.9).
//!
//! Profiles: Core, Recorder, Boundary, Forensic.
//! Conformance is determined by public tests/vectors, not manual approval.

pub mod profiles;
pub mod runner;

pub use profiles::{CapabilityReq, ConformanceLevel, ConformanceProfile, PROFILE_CATALOG};
pub use runner::{
    run_conformance, ConformanceCaseResult, ConformanceReport, CONFORMANCE_REPORT_SCHEMA,
};
