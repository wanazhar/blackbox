//! Normalized external evidence event (`blackbox.evidence.event/v1`).

#![allow(missing_docs)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Schema identifier for external evidence events.
pub const EVIDENCE_EVENT_SCHEMA: &str = "blackbox.evidence.event/v1";
/// Attribute carried by sanitized importer-generated telemetry anomaly records.
pub const TELEMETRY_ANOMALY_ATTRIBUTE: &str = "blackbox.telemetry_anomaly";
/// An imported record claimed an invalid signature.
pub const TELEMETRY_ANOMALY_SIGNED_INVALID: &str = "signed_invalid";
/// A sensor reused one source-local identity for conflicting content.
pub const TELEMETRY_ANOMALY_SOURCE_IDENTITY_CONFLICT: &str = "source_identity_conflict";

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
        if self.source.contains('\0') || self.source_event_id.contains('\0') {
            errs.push("source identity contains NUL".into());
        }
        if let Some(ref dest) = self.destination {
            if dest.contains('\0') {
                errs.push("destination contains NUL".into());
            }
        }
        // Object often carries process exe paths (absolute is normal); never load it.
        // Only reject NUL / control bytes that break storage/display integrity.
        if let Some(ref obj) = self.object {
            if obj.contains('\0') {
                errs.push("object contains NUL".into());
            }
        }
        // Nested path references that look like *loadable* filesystem refs are rejected.
        // (Blackbox must not treat evidence attributes as file paths to open.)
        for (k, v) in &self.attributes {
            if is_pathish_key(k) {
                if let Some(s) = v.as_str() {
                    if looks_like_loadable_path_ref(s) {
                        errs.push(format!(
                            "attribute {k:?} rejects absolute/traversal path {s:?}"
                        ));
                    }
                }
            }
        }
        // payload_blob is a content-addressed key, not a filesystem path.
        if let Some(ref key) = self.payload_blob {
            if !is_plausible_blob_key(key) {
                errs.push(format!(
                    "payload_blob is not a plausible content key: {key:?}"
                ));
            }
        }
        // Bound attribute map size (DoS).
        if self.attributes.len() > 128 {
            errs.push(format!("too many attributes ({})", self.attributes.len()));
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

    /// Hash fields that describe the source observation, excluding Blackbox
    /// IDs, ingest time, and run attachment. Used to distinguish an idempotent
    /// replay from conflicting content under one source-local identity.
    pub fn source_observation_hash(&self) -> anyhow::Result<String> {
        let body = serde_json::json!({
            "source": self.source,
            "sensor": self.sensor,
            "source_event_id": self.source_event_id,
            "source_sequence": self.source_sequence,
            "occurred_at": self.occurred_at,
            "observed_at": self.observed_at,
            "clock_uncertainty": self.clock_uncertainty,
            "identity": self.identity,
            "action": self.action,
            "object": self.object,
            "destination": self.destination,
            "outcome": self.outcome,
            "data_class": self.data_class,
            "original_payload_hash": self.original_payload_hash,
            "integrity": self.integrity,
            "attributes": self.attributes,
        });
        let mut hash = Sha256::new();
        hash.update(serde_json::to_vec(&body)?);
        Ok(hex::encode(hash.finalize()))
    }

    /// Whether two records reuse a source-local identity for different source
    /// observations. Blackbox ingest metadata is deliberately ignored.
    pub fn conflicts_with_source_observation(&self, other: &Self) -> bool {
        if self.source != other.source || self.source_event_id != other.source_event_id {
            return false;
        }
        self.source_observation_hash().ok() != other.source_observation_hash().ok()
    }

    /// Build a bounded sanitized record proving that an invalid-signature
    /// record was rejected. The untrusted record itself remains rejected.
    pub fn signed_invalid_anomaly(rejected: &Self) -> anyhow::Result<Self> {
        telemetry_anomaly(TELEMETRY_ANOMALY_SIGNED_INVALID, rejected, None)
    }

    /// Build an idempotent sanitized record proving source-identity reuse with
    /// conflicting content. Both source-observation hashes are retained.
    pub fn source_identity_conflict_anomaly(
        existing: &Self,
        conflicting: &Self,
    ) -> anyhow::Result<Self> {
        telemetry_anomaly(
            TELEMETRY_ANOMALY_SOURCE_IDENTITY_CONFLICT,
            conflicting,
            Some(existing),
        )
    }
}

fn telemetry_anomaly(
    kind: &str,
    observed: &ExternalEvidenceEvent,
    existing: Option<&ExternalEvidenceEvent>,
) -> anyhow::Result<ExternalEvidenceEvent> {
    let observed_hash = observed.source_observation_hash()?;
    let existing_hash = existing
        .map(ExternalEvidenceEvent::source_observation_hash)
        .transpose()?;
    let mut hashes = vec![observed_hash.clone()];
    if let Some(ref hash) = existing_hash {
        hashes.push(hash.clone());
    }
    hashes.sort();
    let mut marker_hash = Sha256::new();
    marker_hash.update(kind.as_bytes());
    marker_hash.update(observed.source.as_bytes());
    marker_hash.update(observed.source_event_id.as_bytes());
    for hash in &hashes {
        marker_hash.update(hash.as_bytes());
    }
    let marker_hash = hex::encode(marker_hash.finalize());

    let mut marker = ExternalEvidenceEvent::new(
        "blackbox-import",
        "telemetry_integrity",
        format!("{kind}:{}", &marker_hash[..32]),
        EvidenceAction::Other("telemetry_anomaly".into()),
    );
    marker.id = format!("evext-anomaly-{}", &marker_hash[..32]);
    marker.linked_run_id = observed
        .linked_run_id
        .clone()
        .or_else(|| existing.and_then(|event| event.linked_run_id.clone()));
    marker.integrity = EvidenceIntegrity::Transformed;
    marker.transformations = vec!["sanitized_telemetry_anomaly_record".into()];
    marker
        .attributes
        .insert(TELEMETRY_ANOMALY_ATTRIBUTE.into(), kind.into());
    let mut source_identity_hash = Sha256::new();
    source_identity_hash.update(observed.source.as_bytes());
    source_identity_hash.update(b"\0");
    source_identity_hash.update(observed.source_event_id.as_bytes());
    marker.attributes.insert(
        "evidence_source_identity_hash".into(),
        hex::encode(source_identity_hash.finalize()).into(),
    );
    marker
        .attributes
        .insert("observed_content_hash".into(), observed_hash.into());
    if let Some(hash) = existing_hash {
        marker
            .attributes
            .insert("existing_content_hash".into(), hash.into());
    }
    marker.coverage_notes.push(format!(
        "original telemetry rejected; preserved sanitized anomaly {kind}"
    ));
    Ok(marker)
}

fn is_pathish_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    k == "path"
        || k == "file"
        || k == "filename"
        || k == "pathname"
        || k == "filepath"
        || k.ends_with("_path")
        || k.ends_with(".path")
        || k.contains("file_path")
        || k.contains("pathname")
}

/// Paths that must never be treated as loadable references from evidence.
fn looks_like_loadable_path_ref(s: &str) -> bool {
    if s.contains('\0') {
        return true;
    }
    if s.starts_with('/') || s.starts_with('\\') {
        return true;
    }
    // Windows drive / UNC
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return true;
    }
    if s.starts_with("\\\\") || s.starts_with("//") {
        return true;
    }
    // Path traversal segments
    s.split(['/', '\\']).any(|seg| seg == "..")
}

fn is_plausible_blob_key(key: &str) -> bool {
    // Accept sha256 hex (64) or short content keys used elsewhere (prefix + hex).
    if key.is_empty()
        || key.len() > 128
        || key.contains('/')
        || key.contains('\\')
        || key.contains("..")
    {
        return false;
    }
    key.chars()
        .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_' || c == 'b')
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
    fn validate_rejects_windows_path_attr() {
        let mut e = ExternalEvidenceEvent::new("proxy", "proxy", "1", EvidenceAction::HttpRequest);
        e.attributes.insert(
            "file_path".into(),
            serde_json::json!(r"C:\Windows\System32\config"),
        );
        assert!(e.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_blob_key() {
        let mut e = ExternalEvidenceEvent::new("proxy", "proxy", "1", EvidenceAction::HttpRequest);
        e.payload_blob = Some("../etc/passwd".into());
        assert!(e.validate().is_err());
    }

    #[test]
    fn validate_allows_absolute_process_object() {
        let mut e =
            ExternalEvidenceEvent::new("audit", "process", "1", EvidenceAction::ProcessExec);
        e.object = Some("/usr/bin/sshd".into());
        e.validate().unwrap();
    }

    #[test]
    fn validate_ok_minimal() {
        let e = ExternalEvidenceEvent::new("falco", "process", "abc", EvidenceAction::ProcessExec);
        e.validate().unwrap();
    }
}
