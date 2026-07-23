//! Export Blackbox runs/events to OTLP-compatible JSON structures.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::core::event::TraceEvent;
use crate::core::run::Run;

use super::loss::LossLedger;

/// Export options.
#[derive(Debug, Clone, Default)]
pub struct OtlpExportOptions {
    /// Service name attribute.
    pub service_name: Option<String>,
    /// Include raw metadata map (may increase loss when non-OTLP types).
    pub include_metadata: bool,
}

/// Minimal OTLP-compatible resource spans document (JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpResourceSpans {
    /// resourceSpans array (OTLP JSON).
    #[serde(rename = "resourceSpans")]
    pub resource_spans: Vec<Value>,
    /// Blackbox loss ledger (not part of OTLP; companion object).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blackbox_loss: Option<LossLedger>,
}

/// Export a run and its events to OTLP JSON + loss ledger.
pub fn export_run_to_otlp(
    run: &Run,
    events: &[TraceEvent],
    opts: &OtlpExportOptions,
) -> OtlpResourceSpans {
    let mut loss = LossLedger::new("export");
    let service = opts
        .service_name
        .clone()
        .or_else(|| run.adapter.clone())
        .unwrap_or_else(|| "blackbox".into());

    let mut spans = Vec::new();
    // Root span for the run.
    let root_span_id = span_id_from(&run.id);
    let trace_id = trace_id_from(&run.id);
    spans.push(json!({
        "traceId": trace_id,
        "spanId": root_span_id,
        "name": run.name.clone().unwrap_or_else(|| format!("run:{}", short(&run.id))),
        "kind": 1, // INTERNAL
        "startTimeUnixNano": rfc3339_to_nanos(&run.started_at.to_rfc3339()),
        "endTimeUnixNano": run.ended_at.as_ref().map(|t| rfc3339_to_nanos(&t.to_rfc3339())),
        "attributes": [
            {"key": "blackbox.run_id", "value": {"stringValue": run.id}},
            {"key": "blackbox.schema", "value": {"stringValue": "blackbox.run/v1"}},
            {"key": "blackbox.status", "value": {"stringValue": format!("{:?}", run.status)}},
            {"key": "service.name", "value": {"stringValue": service}},
        ],
        "events": [],
        "status": {"code": if matches!(run.status, crate::core::run::RunStatus::Succeeded) { 1 } else { 2 }}
    }));

    for ev in events {
        let parent = ev
            .parent_event_id
            .as_ref()
            .map(|p| span_id_from(p))
            .unwrap_or_else(|| root_span_id.clone());

        // Concepts that do not map cleanly.
        if ev.kind == "security.decision" {
            loss.push(
                "security.decision.integrity",
                "OTLP attributes cannot self-assert Blackbox integrity levels; integrity left as blackbox.* string only",
                Some(ev.id.clone()),
            );
        }
        if ev.kind.starts_with("boundary.") {
            loss.push(
                "boundary.relation",
                "typed boundary relations may not round-trip as OTel links",
                Some(ev.id.clone()),
            );
        }

        let mut attrs = vec![
            json!({"key": "blackbox.event_id", "value": {"stringValue": ev.id}}),
            json!({"key": "blackbox.run_id", "value": {"stringValue": ev.run_id}}),
            json!({"key": "blackbox.sequence", "value": {"intValue": ev.sequence.to_string()}}),
            json!({"key": "blackbox.kind", "value": {"stringValue": ev.kind}}),
            json!({"key": "blackbox.source", "value": {"stringValue": format!("{:?}", ev.source)}}),
            json!({"key": "blackbox.side_effect", "value": {"stringValue": format!("{:?}", ev.side_effect)}}),
        ];
        if let Some(ref parent_id) = ev.parent_event_id {
            attrs.push(json!({
                "key": "blackbox.parent_event_id",
                "value": {"stringValue": parent_id}
            }));
        }
        if opts.include_metadata {
            for (k, v) in &ev.metadata {
                if k.starts_with("native.client_") {
                    loss.push(
                        "native.client_timestamp",
                        "client timestamps are not trusted OTel event times",
                        Some(ev.id.clone()),
                    );
                    continue;
                }
                attrs.push(json!({
                    "key": format!("blackbox.meta.{k}"),
                    "value": {"stringValue": v.to_string()}
                }));
            }
        }

        // Parent/child agent relationships when parent_event_id present.
        spans.push(json!({
            "traceId": trace_id,
            "spanId": span_id_from(&ev.id),
            "parentSpanId": parent,
            "name": ev.kind,
            "kind": 1,
            "startTimeUnixNano": rfc3339_to_nanos(&ev.started_at.to_rfc3339()),
            "endTimeUnixNano": ev.ended_at.as_ref().map(|t| rfc3339_to_nanos(&t.to_rfc3339())),
            "attributes": attrs,
            "status": {"code": 1}
        }));
    }

    // Sampling/collector loss is not known at export time — record capability note.
    loss.push(
        "coverage.sampling",
        "span sampling and collector loss are not known at export; importers must record coverage gaps",
        None,
    );

    OtlpResourceSpans {
        resource_spans: vec![json!({
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": service}},
                    {"key": "blackbox.exporter", "value": {"stringValue": "blackbox.otlp/v1"}},
                ]
            },
            "scopeSpans": [{
                "scope": {"name": "blackbox", "version": crate::protocol::PROTOCOL_VERSION},
                "spans": spans
            }]
        })],
        blackbox_loss: Some(loss),
    }
}

fn short(id: &str) -> &str {
    if id.len() > 8 {
        &id[..8]
    } else {
        id
    }
}

fn trace_id_from(run_id: &str) -> String {
    // 32 hex chars from sha256 prefix of run id.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(run_id.as_bytes());
    hex::encode(h.finalize())[..32].to_string()
}

fn span_id_from(id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(id.as_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

fn rfc3339_to_nanos(s: &str) -> String {
    // Best-effort: if parse fails, return "0".
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        let nanos = dt.timestamp_nanos_opt().unwrap_or(0);
        return nanos.to_string();
    }
    "0".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, TraceEvent};
    use crate::core::run::Run;

    #[test]
    fn export_preserves_run_id_and_parent() {
        let run = Run::new(vec!["x".into()], "/tmp".into());
        let mut e1 = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
        e1.sequence = 1;
        let mut e2 = TraceEvent::new(&run.id, EventSource::Tool, "tool.result");
        e2.sequence = 2;
        e2.parent_event_id = Some(e1.id.clone());
        let out = export_run_to_otlp(&run, &[e1.clone(), e2], &OtlpExportOptions::default());
        let spans = &out.resource_spans[0]["scopeSpans"][0]["spans"];
        assert!(spans.as_array().unwrap().len() >= 3);
        assert!(out.blackbox_loss.as_ref().unwrap().has_losses());
        // Parent relationship present.
        let child = spans
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "tool.result")
            .unwrap();
        assert!(child.get("parentSpanId").is_some());
    }
}
