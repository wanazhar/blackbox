//! Conformance profile definitions.

use serde::{Deserialize, Serialize};

/// Conformance level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceLevel {
    /// Canonical form, schema validation, unknown fields.
    Core,
    /// Native ingest lifecycle, idempotency, ordering.
    Recorder,
    /// Security decisions, boundary citations.
    Boundary,
    /// Forensic packs, commitments, redaction honesty.
    Forensic,
}

impl ConformanceLevel {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Recorder => "recorder",
            Self::Boundary => "boundary",
            Self::Forensic => "forensic",
        }
    }

    /// Parse from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "core" => Some(Self::Core),
            "recorder" => Some(Self::Recorder),
            "boundary" => Some(Self::Boundary),
            "forensic" => Some(Self::Forensic),
            _ => None,
        }
    }
}

/// Capability requirement within a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityReq {
    /// Must pass.
    Mandatory,
    /// May pass or skip with declaration.
    Optional,
    /// Must declare unsupported (cannot silently ignore).
    UnsupportedOk,
}

/// One profile declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceProfile {
    /// Level.
    pub level: ConformanceLevel,
    /// Human description.
    pub description: String,
    /// Mandatory case ids.
    pub mandatory_cases: Vec<String>,
    /// Optional case ids.
    pub optional_cases: Vec<String>,
}

/// Built-in profile catalog.
pub fn profile_for(level: ConformanceLevel) -> ConformanceProfile {
    match level {
        ConformanceLevel::Core => ConformanceProfile {
            level,
            description: "Canonical JSON, schema validation, unknown fields, non-finite rejection"
                .into(),
            mandatory_cases: vec![
                "canonical_key_order".into(),
                "canonical_nested_sort".into(),
                "valid_run_minimal".into(),
                "invalid_bad_schema".into(),
                "provisional_field_in_hash".into(),
                "dual_encoder_identity".into(),
            ],
            optional_cases: vec![],
        },
        ConformanceLevel::Recorder => ConformanceProfile {
            level,
            description: "Native ingest lifecycle, idempotent retry, ordering honesty".into(),
            mandatory_cases: vec![
                "native_complete_run".into(),
                "native_idempotent_retry".into(),
                "native_partial_frame".into(),
                "native_client_ts_no_reorder".into(),
            ],
            optional_cases: vec!["native_unix_socket".into()],
        },
        ConformanceLevel::Boundary => ConformanceProfile {
            level,
            description: "Security decisions and action-effect reconciliation".into(),
            mandatory_cases: vec![
                "security_decision_schema".into(),
                "denied_not_executed".into(),
                "denied_but_bypassed".into(),
                "integrity_demotion".into(),
            ],
            optional_cases: vec![],
        },
        ConformanceLevel::Forensic => ConformanceProfile {
            level,
            description: "Commitments, signatures, OTLP loss honesty".into(),
            mandatory_cases: vec![
                "commitment_tamper_detect".into(),
                "commitment_signature".into(),
                "otlp_loss_ledger".into(),
                "honesty_limitations".into(),
            ],
            optional_cases: vec![],
        },
    }
}

/// All profiles.
pub static PROFILE_CATALOG: &[ConformanceLevel] = &[
    ConformanceLevel::Core,
    ConformanceLevel::Recorder,
    ConformanceLevel::Boundary,
    ConformanceLevel::Forensic,
];
