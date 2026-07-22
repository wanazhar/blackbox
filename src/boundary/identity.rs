//! Run/attempt trace identity and propagation records (1.7 Phase D).

#![allow(missing_docs)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Schema for run trace identity records.
pub const TRACE_IDENTITY_SCHEMA: &str = "blackbox.trace.identity/v1";

/// How a trace id was propagated to a child or peer system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PropagationChannel {
    ChildEnv,
    OtelBaggage,
    HttpHeader,
    ContainerLabel,
    WorkloadAnnotation,
    ProcessArgv,
    FileMarker,
    Other(String),
}

impl PropagationChannel {
    /// Stable string form.
    pub fn as_str(&self) -> &str {
        match self {
            Self::ChildEnv => "child_env",
            Self::OtelBaggage => "otel_baggage",
            Self::HttpHeader => "http_header",
            Self::ContainerLabel => "container_label",
            Self::WorkloadAnnotation => "workload_annotation",
            Self::ProcessArgv => "process_argv",
            Self::FileMarker => "file_marker",
            Self::Other(s) => s.as_str(),
        }
    }
}

/// Outcome of a single propagation attempt (never assumed successful).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PropagationStatus {
    Attempted,
    Confirmed,
    Stripped,
    Forged,
    Missing,
    Unknown,
}

impl PropagationStatus {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attempted => "attempted",
            Self::Confirmed => "confirmed",
            Self::Stripped => "stripped",
            Self::Forged => "forged",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
        }
    }
}

/// One recorded propagation / transformation of the trace identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropagationRecord {
    pub channel: PropagationChannel,
    pub status: PropagationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<DateTime<Utc>>,
}

/// Cryptographically random run/attempt trace identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceIdentity {
    pub schema: String,
    pub run_id: String,
    /// Random trace id (UUID v4 hex, not derived from secrets).
    pub trace_id: String,
    /// Attempt id within a multi-attempt task (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Every propagation attempt / observation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub propagations: Vec<PropagationRecord>,
    /// Env key used for cooperative child propagation (recorded, not trusted alone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_key: Option<String>,
    /// HTTP header name for cooperative propagation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_header: Option<String>,
}

impl TraceIdentity {
    /// Mint a new random identity for a run.
    pub fn mint(run_id: impl Into<String>) -> Self {
        Self {
            schema: TRACE_IDENTITY_SCHEMA.into(),
            run_id: run_id.into(),
            trace_id: Uuid::new_v4().to_string(),
            attempt_id: None,
            created_at: Utc::now(),
            propagations: Vec::new(),
            env_key: Some("BLACKBOX_TRACE_ID".into()),
            http_header: Some("X-Blackbox-Trace-Id".into()),
        }
    }

    /// Record a propagation attempt.
    pub fn record_propagation(
        &mut self,
        channel: PropagationChannel,
        status: PropagationStatus,
        detail: impl Into<Option<String>>,
    ) {
        self.propagations.push(PropagationRecord {
            channel,
            status,
            detail: detail.into(),
            at: Some(Utc::now()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_unique() {
        let a = TraceIdentity::mint("r1");
        let b = TraceIdentity::mint("r1");
        assert_ne!(a.trace_id, b.trace_id);
        assert_eq!(a.schema, TRACE_IDENTITY_SCHEMA);
    }
}
