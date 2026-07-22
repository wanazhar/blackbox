//! Transactional, idempotent, bounded NDJSON evidence importer.

#![allow(missing_docs)]
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::event::{
    EvidenceAction, EvidenceIntegrity, EvidenceOutcome, ExternalEvidenceEvent,
    EVIDENCE_EVENT_SCHEMA,
};

/// Soft defaults for import bounds (override via [`ImportOptions`]).
pub const MAX_EVIDENCE_IMPORT_EVENTS: usize = 50_000;
/// Max NDJSON file size (64 MiB).
pub const MAX_EVIDENCE_IMPORT_BYTES: u64 = 64 * 1024 * 1024;

/// Import configuration.
#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// Maximum events to accept in one import.
    pub max_events: usize,
    /// Maximum file/bytes size.
    pub max_bytes: u64,
    /// Default run id to link when event has none.
    pub default_run_id: Option<String>,
    /// Sensor class for generic JSONL remapping when schema is absent.
    pub default_sensor: String,
    /// Source name for generic JSONL remapping.
    pub default_source: String,
    /// Reject events with integrity `signed_invalid`.
    pub reject_invalid_signatures: bool,
    /// Reject events whose integrity is not `hash_ok` or `signed_verified`.
    /// Default **false** so generic JSONL still imports; enable for fail-closed IR.
    pub reject_unverified: bool,
    /// When `original_payload_hash` is present, require a matching `payload` /
    /// `raw` attribute string (sha256 hex) or reject the event.
    pub verify_payload_hashes: bool,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            max_events: MAX_EVIDENCE_IMPORT_EVENTS,
            max_bytes: MAX_EVIDENCE_IMPORT_BYTES,
            default_run_id: None,
            default_sensor: "generic".into(),
            default_source: "import".into(),
            reject_invalid_signatures: true,
            reject_unverified: false,
            verify_payload_hashes: true,
        }
    }
}

/// One rejected line during import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReject {
    /// 1-based line number.
    pub line: usize,
    /// Reason.
    pub reason: String,
}

/// Summary of an import attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReport {
    pub schema: String,
    pub accepted: usize,
    pub duplicates: usize,
    pub rejected: usize,
    pub rejects: Vec<ImportReject>,
    /// Accepted event ids (new inserts only).
    pub event_ids: Vec<String>,
    pub bytes_read: u64,
}

impl ImportReport {
    fn new() -> Self {
        Self {
            schema: "blackbox.evidence.import/v1".into(),
            accepted: 0,
            duplicates: 0,
            rejected: 0,
            rejects: Vec::new(),
            event_ids: Vec::new(),
            bytes_read: 0,
        }
    }
}

/// Parse and validate NDJSON from a file path (does not write to store).
pub fn import_evidence_ndjson(
    path: &Path,
    opts: &ImportOptions,
) -> anyhow::Result<(Vec<ExternalEvidenceEvent>, ImportReport)> {
    let meta =
        std::fs::metadata(path).map_err(|e| anyhow::anyhow!("stat {}: {e}", path.display()))?;
    if meta.len() > opts.max_bytes {
        anyhow::bail!(
            "evidence file {} is {} bytes (max {})",
            path.display(),
            meta.len(),
            opts.max_bytes
        );
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    import_evidence_ndjson_str(&raw, opts)
}

/// Parse and validate NDJSON string (does not write to store).
pub fn import_evidence_ndjson_str(
    raw: &str,
    opts: &ImportOptions,
) -> anyhow::Result<(Vec<ExternalEvidenceEvent>, ImportReport)> {
    let mut report = ImportReport::new();
    report.bytes_read = raw.len() as u64;
    if report.bytes_read > opts.max_bytes {
        anyhow::bail!(
            "evidence payload is {} bytes (max {})",
            report.bytes_read,
            opts.max_bytes
        );
    }

    let mut accepted = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();

    for (idx, line) in raw.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if accepted.len() >= opts.max_events {
            report.rejected += 1;
            report.rejects.push(ImportReject {
                line: line_no,
                reason: format!("exceeded max_events {}", opts.max_events),
            });
            // Fail closed on overflow: reject rest and stop accepting more.
            continue;
        }

        match parse_line(trimmed, opts) {
            Ok(mut ev) => {
                if let Err(errs) = ev.validate() {
                    report.rejected += 1;
                    report.rejects.push(ImportReject {
                        line: line_no,
                        reason: errs.join("; "),
                    });
                    continue;
                }
                if opts.reject_invalid_signatures
                    && matches!(ev.integrity, EvidenceIntegrity::SignedInvalid)
                {
                    report.rejected += 1;
                    report.rejects.push(ImportReject {
                        line: line_no,
                        reason: "integrity signed_invalid".into(),
                    });
                    continue;
                }
                if let Err(reason) = apply_integrity_checks(&mut ev, opts) {
                    report.rejected += 1;
                    report.rejects.push(ImportReject {
                        line: line_no,
                        reason,
                    });
                    continue;
                }
                if ev.linked_run_id.is_none() {
                    if let Some(ref r) = opts.default_run_id {
                        ev.linked_run_id = Some(r.clone());
                    } else if let Some(ref r) = ev.identity.run_id {
                        ev.linked_run_id = Some(r.clone());
                    }
                }
                let key = ev.idempotency_key();
                if !seen_keys.insert(key) {
                    report.duplicates += 1;
                    continue;
                }
                report.event_ids.push(ev.id.clone());
                accepted.push(ev);
                report.accepted += 1;
            }
            Err(reason) => {
                report.rejected += 1;
                report.rejects.push(ImportReject {
                    line: line_no,
                    reason,
                });
            }
        }
    }

    // Bound reject list size for report readability.
    if report.rejects.len() > 100 {
        report.rejects.truncate(100);
    }
    Ok((accepted, report))
}

fn parse_line(line: &str, opts: &ImportOptions) -> Result<ExternalEvidenceEvent, String> {
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("json parse: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "event must be a JSON object".to_string())?;

    // Native schema path.
    if let Some(schema) = obj.get("schema").and_then(|v| v.as_str()) {
        if schema == EVIDENCE_EVENT_SCHEMA {
            return serde_json::from_value(value).map_err(|e| format!("schema decode: {e}"));
        }
        return Err(format!("unsupported schema {schema:?}"));
    }

    // Sensor-specific adapters (Falco / proxy / process audit).
    if let Some(ev) = super::adapters::map_sensor_event(obj) {
        return Ok(ev);
    }

    // Generic JSONL mapping (OpenTelemetry-ish / loose).
    map_generic(obj, opts)
}

fn map_generic(
    obj: &serde_json::Map<String, serde_json::Value>,
    opts: &ImportOptions,
) -> Result<ExternalEvidenceEvent, String> {
    let source = obj
        .get("source")
        .or_else(|| obj.get("resource"))
        .and_then(|v| v.as_str())
        .unwrap_or(&opts.default_source)
        .to_string();
    let sensor = obj
        .get("sensor")
        .or_else(|| obj.get("instrumentation_scope"))
        .and_then(|v| v.as_str())
        .unwrap_or(&opts.default_sensor)
        .to_string();
    let source_event_id = obj
        .get("source_event_id")
        .or_else(|| obj.get("event_id"))
        .or_else(|| obj.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "generic event needs source_event_id|event_id|id".to_string())?
        .to_string();

    let action = map_action(
        obj.get("action")
            .or_else(|| obj.get("name"))
            .or_else(|| obj.get("kind"))
            .and_then(|v| v.as_str())
            .unwrap_or("other"),
    );

    let mut ev = ExternalEvidenceEvent::new(source, sensor, source_event_id, action);
    if let Some(dest) = obj
        .get("destination")
        .or_else(|| obj.get("dest"))
        .or_else(|| obj.get("url"))
        .and_then(|v| v.as_str())
    {
        ev.destination = Some(dest.to_string());
    }
    if let Some(object) = obj
        .get("object")
        .or_else(|| obj.get("target"))
        .and_then(|v| v.as_str())
    {
        ev.object = Some(object.to_string());
    }
    if let Some(o) = obj.get("outcome").and_then(|v| v.as_str()) {
        ev.outcome = match o {
            "success" | "ok" | "allow" | "allowed" => EvidenceOutcome::Success,
            "failure" | "error" | "fail" => EvidenceOutcome::Failure,
            "denied" | "deny" | "block" | "blocked" => EvidenceOutcome::Denied,
            "unreachable" => EvidenceOutcome::Unreachable,
            _ => EvidenceOutcome::Unknown,
        };
    }
    if let Some(tid) = obj
        .get("trace_id")
        .or_else(|| obj.get("traceId"))
        .and_then(|v| v.as_str())
    {
        ev.identity.trace_id = Some(tid.to_string());
    }
    if let Some(rid) = obj.get("run_id").and_then(|v| v.as_str()) {
        ev.identity.run_id = Some(rid.to_string());
        ev.linked_run_id = Some(rid.to_string());
    }
    if let Some(host) = obj.get("host").and_then(|v| v.as_str()) {
        ev.identity.host = Some(host.to_string());
    }
    if let Some(pid) = obj.get("pid").and_then(|v| v.as_i64()) {
        ev.identity.pid = Some(pid);
    }
    // Copy remaining keys into attributes (bounded).
    for (k, v) in obj {
        if matches!(
            k.as_str(),
            "source"
                | "sensor"
                | "source_event_id"
                | "event_id"
                | "id"
                | "action"
                | "name"
                | "kind"
                | "destination"
                | "dest"
                | "url"
                | "object"
                | "target"
                | "outcome"
                | "trace_id"
                | "traceId"
                | "run_id"
                | "host"
                | "pid"
                | "resource"
                | "instrumentation_scope"
        ) {
            continue;
        }
        if ev.attributes.len() >= 64 {
            break;
        }
        ev.attributes.insert(k.clone(), v.clone());
    }
    ev.integrity = EvidenceIntegrity::Unverified;
    ev.transformations.push("mapped_from_generic_jsonl".into());
    Ok(ev)
}

fn map_action(s: &str) -> EvidenceAction {
    match s.to_ascii_lowercase().as_str() {
        "process_exec" | "exec" | "process.exec" => EvidenceAction::ProcessExec,
        "process_exit" | "exit" => EvidenceAction::ProcessExit,
        "network_connect" | "connect" | "network.connect" => EvidenceAction::NetworkConnect,
        "network_listen" | "listen" => EvidenceAction::NetworkListen,
        "dns_query" | "dns" => EvidenceAction::DnsQuery,
        "http_request" | "http" => EvidenceAction::HttpRequest,
        "file_read" | "read" => EvidenceAction::FileRead,
        "file_write" | "write" => EvidenceAction::FileWrite,
        "file_delete" | "delete" | "unlink" => EvidenceAction::FileDelete,
        "credential_access" | "credential" | "creds" => EvidenceAction::CredentialAccess,
        "authn" | "login" => EvidenceAction::Authn,
        "authz" | "authorize" => EvidenceAction::Authz,
        "package_install" | "install" => EvidenceAction::PackageInstall,
        "container_start" => EvidenceAction::ContainerStart,
        "container_stop" => EvidenceAction::ContainerStop,
        "k8s_audit" | "kubernetes" => EvidenceAction::K8sAudit,
        "cloud_audit" | "cloud" => EvidenceAction::CloudAudit,
        "proxy_deny" | "deny" => EvidenceAction::ProxyDeny,
        "proxy_allow" | "allow" => EvidenceAction::ProxyAllow,
        other => EvidenceAction::Other(other.to_string()),
    }
}

/// Verify declared payload hashes and apply integrity honesty gates.
///
/// - When `original_payload_hash` is set and `verify_payload_hashes`, require a
///   matching `payload` / `raw` / `body` attribute (sha256 hex of UTF-8 bytes).
/// - Unverified claims of `hash_ok` without a successful check are demoted.
/// - `reject_unverified` fails closed unless integrity is `hash_ok` or
///   `signed_verified`.
fn apply_integrity_checks(
    ev: &mut ExternalEvidenceEvent,
    opts: &ImportOptions,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};

    // The NDJSON schema intentionally has no signature material, signer
    // identity, or configured trust root. Therefore an input document cannot
    // authenticate itself merely by spelling `signed_verified`.
    if matches!(ev.integrity, EvidenceIntegrity::SignedVerified) {
        ev.integrity = EvidenceIntegrity::Unverified;
        ev.transformations
            .push("signed_verified_demoted_no_verifier".into());
    }

    let mut hash_verified = false;

    if opts.verify_payload_hashes {
        if let Some(ref want) = ev.original_payload_hash {
            let want = want.trim().to_ascii_lowercase();
            if want.is_empty() || want.len() != 64 || !want.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "original_payload_hash is not a 64-char sha256 hex: {want:?}"
                ));
            }
            let payload = payload_bytes_from_attrs(ev).ok_or_else(|| {
                "original_payload_hash present but no payload/raw/body attribute".to_string()
            })?;
            let mut h = Sha256::new();
            h.update(&payload);
            let got = hex::encode(h.finalize());
            if got != want {
                return Err(format!(
                    "payload hash mismatch (declared {want}, computed {got})"
                ));
            }
            hash_verified = true;
            if matches!(
                ev.integrity,
                EvidenceIntegrity::Unverified | EvidenceIntegrity::Transformed
            ) {
                ev.integrity = EvidenceIntegrity::HashOk;
                ev.transformations.push("payload_hash_verified".into());
            }
        } else if matches!(ev.integrity, EvidenceIntegrity::HashOk) {
            // Source claimed hash_ok without material we can check — demote.
            ev.integrity = EvidenceIntegrity::Unverified;
            ev.transformations
                .push("hash_ok_demoted_no_payload_hash".into());
        }
    }

    if opts.reject_unverified
        && !matches!(
            ev.integrity,
            EvidenceIntegrity::HashOk | EvidenceIntegrity::SignedVerified
        )
    {
        return Err(format!(
            "reject_unverified: integrity is {}{}",
            ev.integrity.as_str(),
            if hash_verified {
                ""
            } else {
                " (provide original_payload_hash + payload; signed evidence requires a trusted verifier)"
            }
        ));
    }

    Ok(())
}

fn payload_bytes_from_attrs(ev: &ExternalEvidenceEvent) -> Option<Vec<u8>> {
    for key in ["payload", "raw", "body"] {
        if let Some(v) = ev.attributes.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.as_bytes().to_vec());
            }
            // Allow compact JSON objects/arrays as canonical payload.
            if v.is_object() || v.is_array() {
                return serde_json::to_vec(v).ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_native_and_generic() {
        let ndjson = r#"
{"schema":"blackbox.evidence.event/v1","id":"evext-1","source":"proxy","sensor":"proxy","source_event_id":"p1","ingested_at":"2026-07-22T00:00:00Z","action":"http_request","outcome":"denied","integrity":"unverified","destination":"evil.example"}
{"id":"g1","action":"connect","destination":"10.0.0.1:443","host":"worker-1","run_id":"run-abc"}
{"id":"g1","action":"connect","destination":"10.0.0.1:443"}
"#;
        let opts = ImportOptions {
            default_run_id: Some("run-default".into()),
            ..Default::default()
        };
        let (events, report) = import_evidence_ndjson_str(ndjson, &opts).unwrap();
        assert_eq!(report.accepted, 2);
        assert_eq!(report.duplicates, 1);
        assert_eq!(events[0].destination.as_deref(), Some("evil.example"));
        assert_eq!(events[1].linked_run_id.as_deref(), Some("run-abc"));
    }

    #[test]
    fn rejects_path_traversal_attrs() {
        let ndjson = r#"{"id":"x","action":"read","path":"/etc/shadow"}"#;
        let (_e, report) = import_evidence_ndjson_str(ndjson, &ImportOptions::default()).unwrap();
        assert_eq!(report.accepted, 0);
        assert_eq!(report.rejected, 1);
    }

    #[test]
    fn bounds_max_events() {
        let mut lines = String::new();
        for i in 0..10 {
            lines.push_str(&format!(r#"{{"id":"{i}","action":"exec"}}"#));
            lines.push('\n');
        }
        let opts = ImportOptions {
            max_events: 3,
            ..Default::default()
        };
        let (events, report) = import_evidence_ndjson_str(&lines, &opts).unwrap();
        assert_eq!(events.len(), 3);
        assert!(report.rejected >= 7);
    }

    #[test]
    fn verifies_payload_hash_and_promotes() {
        use sha2::{Digest, Sha256};
        let body = "hello-evidence";
        let mut h = Sha256::new();
        h.update(body.as_bytes());
        let digest = hex::encode(h.finalize());
        let ndjson = format!(
            r#"{{"schema":"blackbox.evidence.event/v1","id":"evext-hash","source":"proxy","sensor":"proxy","source_event_id":"h1","ingested_at":"2026-07-22T00:00:00Z","action":"http_request","outcome":"denied","integrity":"unverified","original_payload_hash":"{digest}","attributes":{{"payload":"{body}"}}}}"#
        );
        let (events, report) =
            import_evidence_ndjson_str(&ndjson, &ImportOptions::default()).unwrap();
        assert_eq!(report.accepted, 1, "{report:?}");
        assert!(matches!(events[0].integrity, EvidenceIntegrity::HashOk));
        assert!(events[0]
            .transformations
            .iter()
            .any(|t| t == "payload_hash_verified"));
    }

    #[test]
    fn rejects_payload_hash_mismatch() {
        let ndjson = r#"{"schema":"blackbox.evidence.event/v1","id":"evext-bad","source":"proxy","sensor":"proxy","source_event_id":"h2","ingested_at":"2026-07-22T00:00:00Z","action":"http_request","outcome":"denied","integrity":"unverified","original_payload_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","attributes":{"payload":"nope"}}"#;
        let (_e, report) = import_evidence_ndjson_str(ndjson, &ImportOptions::default()).unwrap();
        assert_eq!(report.accepted, 0);
        assert_eq!(report.rejected, 1);
        assert!(report.rejects[0].reason.contains("payload hash mismatch"));
    }

    #[test]
    fn demotes_unverified_hash_ok_claim() {
        let ndjson = r#"{"schema":"blackbox.evidence.event/v1","id":"evext-claim","source":"proxy","sensor":"proxy","source_event_id":"h3","ingested_at":"2026-07-22T00:00:00Z","action":"http_request","outcome":"denied","integrity":"hash_ok"}"#;
        let (events, report) =
            import_evidence_ndjson_str(ndjson, &ImportOptions::default()).unwrap();
        assert_eq!(report.accepted, 1);
        assert!(matches!(events[0].integrity, EvidenceIntegrity::Unverified));
        assert!(events[0]
            .transformations
            .iter()
            .any(|t| t == "hash_ok_demoted_no_payload_hash"));
    }

    #[test]
    fn reject_unverified_fail_closed() {
        let ndjson = r#"{"id":"g-unv","action":"connect","destination":"10.0.0.1:443"}"#;
        let opts = ImportOptions {
            reject_unverified: true,
            ..Default::default()
        };
        let (_e, report) = import_evidence_ndjson_str(ndjson, &opts).unwrap();
        assert_eq!(report.accepted, 0);
        assert_eq!(report.rejected, 1);
        assert!(report.rejects[0].reason.contains("reject_unverified"));
    }

    #[test]
    fn self_asserted_signed_verified_is_demoted() {
        let ndjson = r#"{"schema":"blackbox.evidence.event/v1","id":"evext-signed","source":"proxy","sensor":"proxy","source_event_id":"sig-1","ingested_at":"2026-07-22T00:00:00Z","action":"http_request","outcome":"denied","integrity":"signed_verified"}"#;
        let (events, report) =
            import_evidence_ndjson_str(ndjson, &ImportOptions::default()).unwrap();
        assert_eq!(report.accepted, 1);
        assert!(matches!(events[0].integrity, EvidenceIntegrity::Unverified));
        assert!(events[0]
            .transformations
            .iter()
            .any(|t| t == "signed_verified_demoted_no_verifier"));

        let opts = ImportOptions {
            reject_unverified: true,
            ..Default::default()
        };
        let (_, report) = import_evidence_ndjson_str(ndjson, &opts).unwrap();
        assert_eq!(report.rejected, 1);
    }
}
