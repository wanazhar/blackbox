//! Sanitized incident export with integrity fields (1.7).
#![allow(missing_docs)]

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

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
    let mut unresolved = Vec::new();

    // Resolve and hash attachments against original IDs before sanitization.
    let mut attachment_hashes = Vec::new();
    for a in &incident.attachments {
        if let Some((_, payload)) = attachment_payloads.iter().find(|(id, _)| id == &a.ref_id) {
            let mut h = Sha256::new();
            h.update(payload.as_bytes());
            attachment_hashes.push(format!("{}:{}", a.ref_id, hex::encode(h.finalize())));
        } else {
            unresolved.push(format!("{}:{}", a.kind.as_str(), a.ref_id));
        }
    }

    let mut incident_value = serde_json::to_value(incident)
        .expect("Incident serialization to serde_json::Value is infallible");
    let mut graph_value = graph.map(|graph| {
        serde_json::to_value(graph)
            .expect("IncidentGraph serialization to serde_json::Value is infallible")
    });
    let mut attachment_hashes_value = serde_json::to_value(&attachment_hashes)
        .expect("attachment hash serialization is infallible");
    let mut unresolved_value = serde_json::to_value(&unresolved)
        .expect("unresolved reference serialization is infallible");
    let mut transformations = Vec::new();
    if sanitize {
        let mut redactor = StableRedactor::new();
        sanitize_value(&mut incident_value, "incident", &mut redactor);
        if let Some(graph) = graph_value.as_mut() {
            sanitize_value(graph, "graph", &mut redactor);
        }
        sanitize_value(
            &mut attachment_hashes_value,
            "attachment_hashes",
            &mut redactor,
        );
        sanitize_value(
            &mut unresolved_value,
            "unresolved_references",
            &mut redactor,
        );
        transformations = redactor.ledger();
        transformations.push("sanitize:enabled".into());
    }

    let inc = serde_json::from_value(incident_value)
        .expect("sanitized Incident must retain its schema shape");
    let graph_out = graph_value.map(|graph| {
        serde_json::from_value(graph).expect("sanitized IncidentGraph must retain its schema shape")
    });
    attachment_hashes = serde_json::from_value(attachment_hashes_value)
        .expect("sanitized attachment hashes must remain strings");
    unresolved = serde_json::from_value(unresolved_value)
        .expect("sanitized unresolved references must remain strings");

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

struct StableRedactor {
    scanner: SecretScanner,
    replacements: HashMap<String, String>,
    namespace: String,
    next_replacement: usize,
    stats: BTreeMap<String, (usize, usize)>,
}

impl StableRedactor {
    fn new() -> Self {
        Self {
            scanner: SecretScanner::new(RedactionConfig::default()),
            replacements: HashMap::new(),
            namespace: uuid::Uuid::new_v4().simple().to_string()[..8].to_string(),
            next_replacement: 0,
            stats: BTreeMap::new(),
        }
    }

    fn redact(&mut self, value: &str, field: &str) -> String {
        let stats = self.stats.entry(field.to_string()).or_default();
        stats.0 += 1;
        let spans = self.scanner.find_spans(value);
        if spans.is_empty() {
            return value.to_string();
        }
        stats.1 += 1;

        let mut output = String::with_capacity(value.len());
        let mut cursor = 0;
        for (start, end) in spans {
            if cursor < start {
                output.push_str(&value[cursor..start]);
            }
            let secret = &value[start..end];
            let replacement = self
                .replacements
                .entry(secret.to_string())
                .or_insert_with(|| {
                    self.next_replacement += 1;
                    format!("[REDACTED:{}:{:04}]", self.namespace, self.next_replacement)
                });
            output.push_str(replacement);
            cursor = end;
        }
        output.push_str(&value[cursor..]);
        output
    }

    fn ledger(&self) -> Vec<String> {
        self.stats
            .iter()
            .map(|(field, (scanned, redacted))| {
                if *redacted == 0 {
                    format!("scanned_unchanged:{field}:{scanned}")
                } else {
                    format!("redacted:{field}:{redacted}/{scanned}")
                }
            })
            .collect()
    }
}

fn sanitize_value(value: &mut serde_json::Value, path: &str, redactor: &mut StableRedactor) {
    match value {
        serde_json::Value::String(text) => {
            *text = redactor.redact(text, path);
        }
        serde_json::Value::Array(items) => {
            let child_path = format!("{path}[]");
            for item in items {
                sanitize_value(item, &child_path, redactor);
            }
        }
        serde_json::Value::Object(map) => {
            let entries = std::mem::take(map);
            for (key, mut child) in entries {
                let safe_key = redactor.redact(&key, &format!("{path}.{{key}}"));
                let child_path = format!("{path}.{safe_key}");
                sanitize_value(&mut child, &child_path, redactor);
                map.insert(safe_key, child);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{EntityKind, EvidenceEdge, EvidenceRelation};
    use crate::core::event::Confidence;
    use crate::incident::{
        attach_to_incident, build_incident_graph, GraphInputs, Incident, IncidentAttachmentKind,
    };

    #[test]
    fn export_hash_stable_and_validates() {
        let mut i = Incident::new(Some("t".into()));
        attach_to_incident(&mut i, IncidentAttachmentKind::Run, "r1", None::<String>);
        let payloads = vec![("r1".into(), "{}".into())];
        let doc = build_incident_export(&i, None, &payloads, true);
        validate_incident_export(&doc, false).unwrap();
    }

    #[test]
    fn sanitized_export_scans_every_string_and_preserves_references() {
        let secret = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let mut incident = Incident::new(Some(secret.into()));
        incident.id = secret.into();
        incident.summary = Some(secret.into());
        incident.tags = vec![secret.into()];
        incident.earliest_signal_id = Some(secret.into());
        attach_to_incident(
            &mut incident,
            IncidentAttachmentKind::Run,
            secret,
            Some(secret.into()),
        );

        let mut edge = EvidenceEdge::new(
            EntityKind::Other(secret.into()),
            secret,
            EntityKind::Other(secret.into()),
            secret,
            EvidenceRelation::CredentialUse,
            Confidence::StronglyCorrelated,
        );
        edge.schema = secret.into();
        edge.id = secret.into();
        edge.reasons = vec![secret.into()];
        edge.run_id = Some(secret.into());
        let mut graph = build_incident_graph(
            &incident,
            &GraphInputs {
                edges: vec![edge],
                ..Default::default()
            },
        );
        graph.schema = secret.into();
        graph.incident_id = secret.into();
        for node in &mut graph.nodes {
            node.kind = secret.into();
            node.id = secret.into();
            node.run_id = Some(secret.into());
            node.label = Some(secret.into());
        }
        for flow in &mut graph.flows {
            flow.edge_id = secret.into();
            flow.from_kind = EntityKind::Other(secret.into());
            flow.from_id = secret.into();
            flow.to_kind = EntityKind::Other(secret.into());
            flow.to_id = secret.into();
            flow.run_id = Some(secret.into());
            flow.reasons = vec![secret.into()];
        }
        graph.techniques.push(crate::incident::TechniqueReuse {
            technique: secret.into(),
            first_run_id: secret.into(),
            first_ref: secret.into(),
            reused_by_runs: vec![secret.into()],
        });
        graph.earliest_signal = Some(crate::incident::IncidentSignal {
            ref_id: secret.into(),
            kind: secret.into(),
            summary: secret.into(),
            at: Utc::now(),
            run_id: Some(secret.into()),
        });

        let doc = build_incident_export(
            &incident,
            Some(&graph),
            &[(secret.into(), format!("attachment body {secret}"))],
            true,
        );
        let encoded = serde_json::to_string(&doc).unwrap();

        assert!(!encoded.contains(secret));
        assert!(encoded.contains("REDACTED"));
        assert!(doc
            .transformations
            .iter()
            .any(|entry| entry.starts_with("redacted:incident.attachments[].reason:")));
        assert!(doc
            .transformations
            .iter()
            .any(|entry| entry.starts_with("redacted:graph.flows[].reasons[]:")));
        assert!(doc
            .transformations
            .iter()
            .any(|entry| entry.starts_with("scanned_unchanged:")));
        assert_eq!(doc.attachment_hashes.len(), 1);
        let graph = doc.graph.as_ref().unwrap();
        assert_eq!(doc.incident.id, graph.incident_id);
        assert!(doc.attachment_hashes[0].starts_with(&doc.incident.attachments[0].ref_id));
        assert_eq!(graph.edges[0].id, graph.flows[0].edge_id);
        assert_eq!(
            graph.techniques.last().unwrap().first_ref,
            graph.flows[0].edge_id
        );
        assert_eq!(
            graph.earliest_signal.as_ref().unwrap().ref_id,
            graph.flows[0].edge_id
        );
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
