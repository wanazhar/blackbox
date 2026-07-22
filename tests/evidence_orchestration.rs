//! Kubernetes and cloud-audit adapter qualification (1.7 Phase C/D).

use blackbox::boundary::{
    correlate_external_batch, correlate_external_event, CorrelationContext, EvidenceRelation,
};
use blackbox::core::Confidence;
use blackbox::evidence::{
    import_evidence_ndjson_str, EvidenceAction, EvidenceOutcome, ImportOptions,
};

const KUBERNETES: &str =
    include_str!("fixtures/boundary_1_7/orchestration/kubernetes_audit.ndjson");
const CLOUD: &str = include_str!("fixtures/boundary_1_7/orchestration/cloud_audit.ndjson");
const MALFORMED: &str = include_str!("fixtures/boundary_1_7/orchestration/malformed.ndjson");

#[test]
fn kubernetes_audit_preserves_orchestration_identity_and_effect() {
    let (events, report) =
        import_evidence_ndjson_str(KUBERNETES, &ImportOptions::default()).unwrap();
    assert_eq!(report.accepted, 2, "rejects={:?}", report.rejects);
    assert_eq!(report.rejected, 0);

    let exec = &events[0];
    assert_eq!(exec.source, "kubernetes-audit");
    assert_eq!(exec.sensor, "k8s_audit");
    assert_eq!(exec.source_event_id, "k8s-audit-001");
    assert_eq!(exec.action, EvidenceAction::K8sAudit);
    assert_eq!(exec.outcome, EvidenceOutcome::Success);
    assert_eq!(
        exec.identity.principal.as_deref(),
        Some("system:serviceaccount:eval:agent-runner")
    );
    assert_eq!(exec.identity.namespace.as_deref(), Some("eval"));
    assert_eq!(exec.identity.workload.as_deref(), Some("agent-worker"));
    assert_eq!(exec.identity.container.as_deref(), Some("runner"));
    assert_eq!(
        exec.identity.trace_id.as_deref(),
        Some("trace-orchestration-001")
    );
    assert_eq!(
        exec.object.as_deref(),
        Some("pods/eval/agent-worker-7f9c:exec")
    );
    assert_eq!(
        exec.destination.as_deref(),
        Some("/api/v1/namespaces/eval/pods/agent-worker-7f9c/exec?command=sh")
    );
    assert_eq!(
        exec.attributes.get("k8s.verb").and_then(|v| v.as_str()),
        Some("create")
    );
    assert!(exec.occurred_at.is_some());
    assert!(exec.observed_at.is_some());

    let denied = &events[1];
    assert_eq!(denied.outcome, EvidenceOutcome::Denied);
    assert_eq!(denied.object.as_deref(), Some("secrets/eval/model-token"));
}

#[test]
fn cloud_audit_preserves_provider_principal_action_object_and_outcome() {
    let (events, report) = import_evidence_ndjson_str(CLOUD, &ImportOptions::default()).unwrap();
    assert_eq!(report.accepted, 2, "rejects={:?}", report.rejects);
    assert_eq!(report.rejected, 0);

    let aws = &events[0];
    assert_eq!(aws.source, "aws-cloudtrail");
    assert_eq!(aws.sensor, "cloud_audit");
    assert_eq!(aws.source_event_id, "aws-event-001");
    assert_eq!(aws.action, EvidenceAction::CloudAudit);
    assert_eq!(aws.outcome, EvidenceOutcome::Denied);
    assert_eq!(
        aws.identity.principal.as_deref(),
        Some("arn:aws:sts::123456789012:assumed-role/eval-agent/agent-session")
    );
    assert_eq!(
        aws.destination.as_deref(),
        Some("secretsmanager.amazonaws.com")
    );
    assert_eq!(
        aws.object.as_deref(),
        Some("arn:aws:secretsmanager:us-east-1:123456789012:secret:production/api-key")
    );
    assert_eq!(
        aws.attributes.get("cloud.action").and_then(|v| v.as_str()),
        Some("GetSecretValue")
    );

    let gcp = &events[1];
    assert_eq!(gcp.source, "gcp-cloud-audit");
    assert_eq!(gcp.source_event_id, "gcp-event-001");
    assert_eq!(gcp.outcome, EvidenceOutcome::Success);
    assert_eq!(
        gcp.identity.principal.as_deref(),
        Some("agent-runner@eval-project.iam.gserviceaccount.com")
    );
    assert_eq!(gcp.destination.as_deref(), Some("storage.googleapis.com"));
    assert_eq!(
        gcp.object.as_deref(),
        Some("projects/_/buckets/eval-artifacts/objects/result.json")
    );
    assert!(gcp.occurred_at.is_some());
    assert!(gcp.observed_at.is_some());
}

#[test]
fn recognized_malformed_sensor_records_are_rejected_without_defaults() {
    let (events, report) =
        import_evidence_ndjson_str(MALFORMED, &ImportOptions::default()).unwrap();
    assert!(events.is_empty());
    assert_eq!(report.accepted, 0);
    assert_eq!(report.rejected, 3);
    assert!(report
        .rejects
        .iter()
        .all(|reject| reject.reason.contains("source is required")));
}

#[test]
fn importer_to_orchestration_correlation_uses_multiple_signals_but_stays_honest() {
    let opts = ImportOptions {
        default_run_id: Some("run-orchestration-001".into()),
        ..Default::default()
    };
    let (events, report) = import_evidence_ndjson_str(KUBERNETES, &opts).unwrap();
    assert_eq!(report.accepted, 2);

    let ctx = CorrelationContext {
        run_id: "run-orchestration-001".into(),
        trace_id: Some("trace-orchestration-001".into()),
        workload: Some("agent-worker".into()),
        ..Default::default()
    };
    let edges = correlate_external_batch(&events, &ctx);
    let exec_edge = edges
        .iter()
        .find(|edge| edge.to_id == events[0].id)
        .expect("mapped Kubernetes audit event must correlate");
    assert_eq!(exec_edge.relation, EvidenceRelation::SameTraceId);
    assert_eq!(exec_edge.confidence, Confidence::StronglyCorrelated);
    assert!(exec_edge.reasons.iter().any(|r| r == "matching_trace_id"));
    assert!(exec_edge.reasons.iter().any(|r| r == "matching_workload"));
    assert!(exec_edge
        .reasons
        .iter()
        .any(|r| r == "import_linked_run_id"));

    // The second audit event carries only a cooperative trace identity. Import
    // it without a default run link to prove that this forgeable signal cannot
    // become confirmed attribution.
    let (unlinked, _) = import_evidence_ndjson_str(KUBERNETES, &ImportOptions::default()).unwrap();
    let trace_only_ctx = CorrelationContext {
        run_id: "another-run".into(),
        trace_id: Some("trace-cooperative-only".into()),
        ..Default::default()
    };
    let trace_only = correlate_external_event(&unlinked[1], &trace_only_ctx).unwrap();
    assert_eq!(trace_only.confidence, Confidence::StronglyCorrelated);
    assert_ne!(trace_only.confidence, Confidence::Confirmed);
    assert_eq!(trace_only.relation, EvidenceRelation::SameTraceId);
}
