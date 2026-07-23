//! Ingest supported OTLP records as transformed external evidence.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::evidence::{EvidenceAction, EvidenceIntegrity, EvidenceOutcome, ExternalEvidenceEvent};

use super::loss::LossLedger;

/// Result of importing OTLP JSON as external evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpImportReport {
    /// Transformed evidence events.
    pub events: Vec<ExternalEvidenceEvent>,
    /// Semantic losses during import.
    pub loss: LossLedger,
    /// Number of spans considered.
    pub spans_seen: usize,
    /// Number of spans skipped.
    pub spans_skipped: usize,
}

/// Import an OTLP resourceSpans document (JSON value) as external evidence.
///
/// OTel attributes cannot self-assert Blackbox integrity levels — all imported
/// records are `unverified` unless a separate verification path is used.
pub fn import_otlp_as_evidence(doc: &Value, source: &str) -> OtlpImportReport {
    let mut loss = LossLedger::new("import");
    let mut events = Vec::new();
    let mut spans_seen = 0usize;
    let mut spans_skipped = 0usize;

    let resource_spans = doc
        .get("resourceSpans")
        .or_else(|| doc.get("resource_spans"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for rs in resource_spans {
        let scope_spans = rs
            .get("scopeSpans")
            .or_else(|| rs.get("scope_spans"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for ss in scope_spans {
            let spans = ss
                .get("spans")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for span in spans {
                spans_seen += 1;
                match span_to_evidence(&span, source, &mut loss) {
                    Some(ev) => events.push(ev),
                    None => spans_skipped += 1,
                }
            }
        }
    }

    if spans_seen == 0 {
        loss.push("otlp.document", "no resourceSpans/spans found", None);
    }

    loss.push(
        "coverage.sampling",
        "imported OTLP stream may be sampled; coverage gap not quantifiable from document alone",
        None,
    );

    OtlpImportReport {
        events,
        loss,
        spans_seen,
        spans_skipped,
    }
}

fn span_to_evidence(
    span: &Value,
    source: &str,
    loss: &mut LossLedger,
) -> Option<ExternalEvidenceEvent> {
    let name = span.get("name").and_then(|v| v.as_str()).unwrap_or("span");
    let span_id = span
        .get("spanId")
        .or_else(|| span.get("span_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if span_id.is_empty() {
        loss.push("otlp.span", "missing spanId", None);
        return None;
    }

    if let Some(attrs) = span.get("attributes").and_then(|v| v.as_array()) {
        for a in attrs {
            let key = a.get("key").and_then(|v| v.as_str()).unwrap_or("");
            if key == "blackbox.integrity" || key.ends_with(".integrity") {
                let claimed = a
                    .pointer("/value/stringValue")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if claimed == "signed_verified" || claimed == "hash_ok" {
                    loss.push(
                        "integrity.self_assert",
                        "OTLP attribute cannot self-assert Blackbox integrity; demoted to unverified",
                        Some(span_id.clone()),
                    );
                }
            }
        }
    }

    let mut ev = ExternalEvidenceEvent::new(source, "otlp", &span_id, classify_action(name));
    ev.outcome = EvidenceOutcome::Unknown;
    ev.integrity = EvidenceIntegrity::Unverified;
    ev.transformations.push("otlp_span_to_evidence_v1".into());
    if let Some(run_id) = attr_string(span, "blackbox.run_id") {
        ev.identity.run_id = Some(run_id.clone());
        ev.linked_run_id = Some(run_id);
    }
    ev.attributes
        .insert("otlp.span_name".into(), Value::String(name.into()));
    if let Some(tid) = span.get("traceId").and_then(|v| v.as_str()) {
        ev.attributes
            .insert("otlp.trace_id".into(), Value::String(tid.into()));
        ev.identity.trace_id = Some(tid.into());
    }
    if let Some(parent) = span.get("parentSpanId").and_then(|v| v.as_str()) {
        ev.attributes
            .insert("otlp.parent_span_id".into(), Value::String(parent.into()));
    }
    Some(ev)
}

fn attr_string(span: &Value, key: &str) -> Option<String> {
    let attrs = span.get("attributes")?.as_array()?;
    for a in attrs {
        if a.get("key").and_then(|v| v.as_str()) == Some(key) {
            if let Some(s) = a.pointer("/value/stringValue").and_then(|v| v.as_str()) {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn classify_action(name: &str) -> EvidenceAction {
    let n = name.to_ascii_lowercase();
    if n.contains("http") || n.contains("request") {
        EvidenceAction::HttpRequest
    } else if n.contains("exec") || n.contains("process") {
        EvidenceAction::ProcessExec
    } else if n.contains("file") || n.contains("write") {
        EvidenceAction::FileWrite
    } else if n.contains("connect") || n.contains("network") {
        EvidenceAction::NetworkConnect
    } else {
        EvidenceAction::Other(name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn import_demotes_self_asserted_integrity() {
        let doc = json!({
            "resourceSpans": [{
                "scopeSpans": [{
                    "spans": [{
                        "name": "tool.call",
                        "spanId": "aaaaaaaaaaaaaaaa",
                        "traceId": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "attributes": [
                            {"key": "blackbox.integrity", "value": {"stringValue": "signed_verified"}},
                            {"key": "blackbox.run_id", "value": {"stringValue": "run-1"}}
                        ]
                    }]
                }]
            }]
        });
        let report = import_otlp_as_evidence(&doc, "otel-collector");
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].integrity, EvidenceIntegrity::Unverified);
        assert!(report
            .loss
            .losses
            .iter()
            .any(|l| l.concept == "integrity.self_assert"));
    }
}
