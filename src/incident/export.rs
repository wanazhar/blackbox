//! Sanitized incident export with integrity fields (1.7).
#![allow(missing_docs)]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use crate::redaction::{scanner::SecretScanner, RedactionConfig};

use super::graph::IncidentGraph;
use super::model::Incident;

pub const INCIDENT_EXPORT_SCHEMA: &str = "blackbox.incident.export/v1";

/// Sanitized incident exchange document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentExport {
    pub schema: String,
    pub incident: Incident,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<IncidentGraph>,
    /// Content hashes of included attachment payloads (when present).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachment_hashes: Vec<String>,
    /// Redaction / transformation ledger.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transformations: Vec<String>,
    /// Unresolved references (ids that could not be expanded).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_references: Vec<String>,
    pub exported_at: chrono::DateTime<Utc>,
    pub export_hash: String,
}

/// Build a sanitized export. When `sanitize` is true, strip high-risk free text.
pub fn build_incident_export(
    incident: &Incident,
    graph: Option<&IncidentGraph>,
    attachment_payloads: &[(String, String)],
    sanitize: bool,
) -> IncidentExport {
    let mut inc = incident.clone();
    let mut transformations = Vec::new();
    let mut unresolved = Vec::new();

    if sanitize {
        if let Some(ref mut s) = inc.summary {
            *s = redact_text(s);
            transformations.push("summary_redacted".into());
        }
        if let Some(ref mut t) = inc.title {
            // Keep title but strip secret-like tokens.
            *t = redact_text(t);
            transformations.push("title_redacted".into());
        }
        transformations.push("sanitize=true".into());
    }

    // Validate attachments against known payloads.
    let mut attachment_hashes = Vec::new();
    for a in &inc.attachments {
        if let Some((_, payload)) = attachment_payloads.iter().find(|(id, _)| id == &a.ref_id) {
            let mut h = Sha256::new();
            h.update(payload.as_bytes());
            attachment_hashes.push(format!("{}:{}", a.ref_id, hex::encode(h.finalize())));
        } else {
            unresolved.push(format!("{}:{}", a.kind.as_str(), a.ref_id));
        }
    }

    let mut graph_out = graph.cloned();
    if sanitize {
        if let Some(ref mut g) = graph_out {
            for n in &mut g.nodes {
                if let Some(ref mut label) = n.label {
                    *label = redact_text(label);
                }
            }
            transformations.push("graph_labels_redacted".into());
        }
    }

    let mut doc = IncidentExport {
        schema: INCIDENT_EXPORT_SCHEMA.into(),
        incident: inc,
        graph: graph_out,
        attachment_hashes,
        transformations,
        unresolved_references: unresolved,
        exported_at: Utc::now(),
        export_hash: String::new(),
    };
    doc.export_hash = hash_export(&doc);
    doc
}

/// Validate export integrity (hash + unresolved policy).
pub fn validate_incident_export(
    doc: &IncidentExport,
    allow_unresolved: bool,
) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();
    let mut tmp = doc.clone();
    tmp.export_hash.clear();
    let expect = hash_export(&tmp);
    if expect != doc.export_hash {
        errs.push("export_hash mismatch".into());
    }
    if !allow_unresolved && !doc.unresolved_references.is_empty() {
        errs.push(format!(
            "{} unresolved references",
            doc.unresolved_references.len()
        ));
    }
    if doc.schema != INCIDENT_EXPORT_SCHEMA {
        errs.push(format!("unsupported schema {}", doc.schema));
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

fn hash_export(doc: &IncidentExport) -> String {
    let mut tmp = doc.clone();
    tmp.export_hash.clear();
    let s = serde_json::to_string(&tmp).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn redact_text(s: &str) -> String {
    static SCANNER: LazyLock<SecretScanner> =
        LazyLock::new(|| SecretScanner::new(RedactionConfig::default()));
    SCANNER.redact(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::{attach_to_incident, Incident, IncidentAttachmentKind};

    #[test]
    fn export_hash_stable_and_validates() {
        let mut i = Incident::new(Some("t".into()));
        attach_to_incident(&mut i, IncidentAttachmentKind::Run, "r1", None::<String>);
        let payloads = vec![("r1".into(), "{}".into())];
        let doc = build_incident_export(&i, None, &payloads, true);
        validate_incident_export(&doc, false).unwrap();
    }

    #[test]
    fn sanitized_export_removes_secrets_and_records_transformations() {
        let secret = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let mut incident = Incident::new(Some(format!("credential {secret}")));
        incident.summary = Some("password=correct-horse-battery-staple".into());
        attach_to_incident(
            &mut incident,
            IncidentAttachmentKind::Run,
            "r1",
            None::<String>,
        );

        let doc = build_incident_export(
            &incident,
            None,
            &[("r1".into(), format!("attachment still hashed: {secret}"))],
            true,
        );
        let encoded = serde_json::to_string(&doc).unwrap();

        assert!(!encoded.contains(secret));
        assert!(!encoded.contains("correct-horse-battery-staple"));
        assert!(encoded.contains("REDACTED"));
        assert!(doc.transformations.iter().any(|t| t == "title_redacted"));
        assert!(doc.transformations.iter().any(|t| t == "summary_redacted"));
        assert_eq!(doc.attachment_hashes.len(), 1);
        validate_incident_export(&doc, false).unwrap();
    }

    #[test]
    fn sanitized_export_detects_tampering() {
        let incident = Incident::new(Some("integrity".into()));
        let mut doc = build_incident_export(&incident, None, &[], true);
        doc.incident.title = Some("changed after export".into());

        let errors = validate_incident_export(&doc, false).unwrap_err();
        assert!(errors.iter().any(|error| error == "export_hash mismatch"));
    }
}
