//! 1.9 Phase E: OTLP export/import with explicit loss ledger.

use blackbox::core::event::{EventSource, TraceEvent};
use blackbox::core::run::Run;
use blackbox::otlp::{
    export_run_to_otlp, import_otlp_as_evidence, OtlpExportOptions, OTLP_LOSS_SCHEMA,
};
use blackbox::evidence::EvidenceIntegrity;
use serde_json::json;

#[test]
fn export_round_trip_reports_losses_deterministically() {
    let mut run = Run::new(vec!["agent".into()], "/tmp".into());
    run.name = Some("otlp-test".into());
    let mut e1 = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
    e1.sequence = 1;
    let mut e2 = TraceEvent::new(&run.id, EventSource::System, "security.decision");
    e2.sequence = 2;
    e2.parent_event_id = Some(e1.id.clone());

    let exported = export_run_to_otlp(
        &run,
        &[e1, e2],
        &OtlpExportOptions {
            service_name: Some("test".into()),
            include_metadata: true,
        },
    );
    let loss = exported.blackbox_loss.as_ref().unwrap();
    assert_eq!(loss.schema, OTLP_LOSS_SCHEMA);
    assert!(loss.has_losses());
    assert!(loss
        .losses
        .iter()
        .any(|l| l.concept == "security.decision.integrity"));
    assert!(loss.losses.iter().any(|l| l.concept == "coverage.sampling"));

    // Parent/child preserved as parentSpanId.
    let spans = exported.resource_spans[0]["scopeSpans"][0]["spans"]
        .as_array()
        .unwrap();
    let child = spans.iter().find(|s| s["name"] == "security.decision").unwrap();
    assert!(child.get("parentSpanId").is_some());

    // Import path demotes integrity.
    let as_value = serde_json::to_value(&exported).unwrap();
    let report = import_otlp_as_evidence(&as_value, "otlp-export");
    assert!(report.spans_seen >= 2);
    assert!(report.events.iter().all(|e| e.integrity == EvidenceIntegrity::Unverified));
    assert_eq!(report.loss.direction, "import");
}

#[test]
fn otel_cannot_self_assert_integrity() {
    let doc = json!({
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": [{
                    "name": "process",
                    "spanId": "1122334455667788",
                    "traceId": "00112233445566778899aabbccddeeff",
                    "attributes": [
                        {"key": "blackbox.integrity", "value": {"stringValue": "signed_verified"}}
                    ]
                }]
            }]
        }]
    });
    let report = import_otlp_as_evidence(&doc, "collector");
    assert_eq!(report.events[0].integrity, EvidenceIntegrity::Unverified);
    assert!(report
        .loss
        .losses
        .iter()
        .any(|l| l.concept == "integrity.self_assert"));
}
