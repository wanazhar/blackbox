//! Normalized external evidence event (`blackbox.evidence.event/v1`).

#![allow(missing_docs)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Schema identifier for external evidence events.
pub const EVIDENCE_EVENT_SCHEMA: &str = "blackbox.evidence.event/v1";

/// Clock uncertainty for multi-host correlation.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClockUncertainty {
    /// Estimated skew bounds in milliseconds (±).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skew_ms: Option<i64>,
    /// Source clock id / NTP status note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Principal / workload identity carried on an external event.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExternalIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Cooperative blackbox run/trace id when present (may be forged/stripped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
}

/// High-level action classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAction {
    ProcessExec,
    ProcessExit,
    NetworkConnect,
    NetworkListen,
    DnsQuery,
    HttpRequest,
    FileRead,
    FileWrite,
    FileDelete,
    CredentialAccess,
    Authn,
    Authz,
    PackageInstall,
    ContainerStart,
    ContainerStop,
    K8sAudit,
    CloudAudit,
    ProxyDeny,
    ProxyAllow,
    Other(String),
}

impl EvidenceAction {
    /// Stable string form.
    pub fn as_str(&self) -> &str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::ProcessExit => "process_exit",
            Self::NetworkConnect => "network_connect",
            Self::NetworkListen => "network_listen",
            Self::DnsQuery => "dns_query",
            Self::HttpRequest => "http_request",
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::FileDelete => "file_delete",
            Self::CredentialAccess => "credential_access",
            Self::Authn => "authn",
            Self::Authz => "authz",
            Self::PackageInstall => "package_install",
            Self::ContainerStart => "container_start",
            Self::ContainerStop => "container_stop",
            Self::K8sAudit => "k8s_audit",
            Self::CloudAudit => "cloud_audit",
            Self::ProxyDeny => "proxy_deny",
            Self::ProxyAllow => "proxy_allow",
            Self::Other(s) => s.as_str(),
        }
    }
}

/// Outcome of the observed action.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOutcome {
    Success,
    Failure,
    Denied,
    Unreachable,
    #[default]
    Unknown,
}

impl EvidenceOutcome {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
            Self::Unreachable => "unreachable",
            Self::Unknown => "unknown",
        }
    }
}

/// Integrity / signature status of the imported event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceIntegrity {
    /// Hash matches declared content; no signature.
    HashOk,
    /// Cryptographic signature verified.
    SignedVerified,
    /// Signature present but failed verification.
    SignedInvalid,
    /// No integrity material provided.
    #[default]
    Unverified,
    /// Payload was transformed/redacted before ingest.
    Transformed,
}

impl EvidenceIntegrity {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HashOk => "hash_ok",
            Self::SignedVerified => "signed_verified",
            Self::SignedInvalid => "signed_invalid",
            Self::Unverified => "unverified",
            Self::Transformed => "transformed",
        }
    }
}

/// Normalized external evidence event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExternalEvidenceEvent {
    /// Always `blackbox.evidence.event/v1`.
    pub schema: String,
    /// Blackbox-assigned stable id (UUID). Re-import with same source identity is idempotent.
    pub id: String,
    /// Sensor / pipeline identity (e.g. `falco`, `otel-collector`, `http-proxy`).
    pub source: String,
    /// Sensor type class (`process`, `network`, `proxy`, `k8s_audit`, `cloud_audit`, `otel`, `generic`).
    pub sensor: String,
    /// Source-local event identity (required for idempotency with source).
    pub source_event_id: String,
    /// Source-local sequence when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sequence: Option<u64>,
    /// When the action occurred (source clock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<DateTime<Utc>>,
    /// When the sensor observed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<DateTime<Utc>>,
    /// When blackbox ingested it.
    pub ingested_at: DateTime<Utc>,
    #[serde(default)]
    pub clock_uncertainty: ClockUncertainty,
    #[serde(default)]
    pub identity: ExternalIdentity,
    pub action: EvidenceAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(default)]
    pub outcome: EvidenceOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_class: Option<String>,
    /// SHA-256 of the original payload bytes when provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_payload_hash: Option<String>,
    /// Optional content-addressed blob key for full original payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_blob: Option<String>,
    #[serde(default)]
    pub integrity: EvidenceIntegrity,
    /// Redaction / transformation notes (ledger).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transformations: Vec<String>,
    /// Known capture loss / coverage notes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_notes: Vec<String>,
    /// Linked blackbox run id when correlated at import time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_run_id: Option<String>,
    /// Free-form attributes (bounded; large payloads should be blobs).
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

impl ExternalEvidenceEvent {
    /// Create a minimal event skeleton.
    pub fn new(
        source: impl Into<String>,
        sensor: impl Into<String>,
        source_event_id: impl Into<String>,
        action: EvidenceAction,
    ) -> Self {
        Self {
            schema: EVIDENCE_EVENT_SCHEMA.into(),
            id: format!("evext-{}", Uuid::new_v4()),
            source: source.into(),
            sensor: sensor.into(),
            source_event_id: source_event_id.into(),
            source_sequence: None,
            occurred_at: None,
            observed_at: None,
            ingested_at: Utc::now(),
            clock_uncertainty: ClockUncertainty::default(),
            identity: ExternalIdentity::default(),
            action,
            object: None,
            destination: None,
            outcome: EvidenceOutcome::Unknown,
            data_class: None,
            original_payload_hash: None,
            payload_blob: None,
            integrity: EvidenceIntegrity::Unverified,
            transformations: Vec::new(),
            coverage_notes: Vec::new(),
            linked_run_id: None,
            attributes: serde_json::Map::new(),
        }
    }

    /// Idempotency key: source + source_event_id.
    pub fn idempotency_key(&self) -> String {
        format!("{}::{}", self.source, self.source_event_id)
    }

    /// Structural validation (schema, required fields, path safety).
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if self.schema != EVIDENCE_EVENT_SCHEMA {
            errs.push(format!(
                "unsupported schema {:?} (expected {})",
                self.schema, EVIDENCE_EVENT_SCHEMA
            ));
        }
        if self.source.is_empty() {
            errs.push("source is required".into());
        }
        if self.sensor.is_empty() {
            errs.push("sensor is required".into());
        }
        if self.source_event_id.is_empty() {
            errs.push("source_event_id is required".into());
        }
        if self.source.contains("..") || self.source_event_id.contains("..") {
            errs.push("source identity must not contain path traversal".into());
        }
        if let Some(ref dest) = self.destination {
            if dest.contains('\0') {
                errs.push("destination contains NUL".into());
            }
        }
        // Nested path references in attributes that look like absolute filesystem
        // paths used as loadable references are rejected (safety).
        for (k, v) in &self.attributes {
            if k.ends_with("_path") || k == "path" || k == "file" {
                if let Some(s) = v.as_str() {
                    if s.starts_with('/') || s.contains("..") {
                        errs.push(format!(
                            "attribute {k:?} rejects absolute/traversal path {s:?}"
                        ));
                    }
                }
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    /// Hash of the canonical JSON body for integrity fields.
    pub fn content_hash(&self) -> anyhow::Result<String> {
        let v = serde_json::to_value(self)?;
        let s = serde_json::to_string(&v)?;
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        Ok(hex::encode(h.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_traversal_path_attr() {
        let mut e = ExternalEvidenceEvent::new("proxy", "proxy", "1", EvidenceAction::HttpRequest);
        e.attributes
            .insert("path".into(), serde_json::json!("/etc/passwd"));
        assert!(e.validate().is_err());
    }

    #[test]
    fn validate_ok_minimal() {
        let e = ExternalEvidenceEvent::new("falco", "process", "abc", EvidenceAction::ProcessExec);
        e.validate().unwrap();
    }
}
