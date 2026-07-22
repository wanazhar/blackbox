//! Red-team evidence import validation (path attrs, blob keys, canary honesty).

use blackbox::boundary::{
    post_run_canary_receipts, resolve_boundary, BoundaryContract, ResolveOpts,
};
use blackbox::evidence::{
    import_evidence_ndjson_str, EvidenceAction, ExternalEvidenceEvent, ImportOptions,
};

#[test]
fn rejects_loadable_path_attributes() {
    let nd = r#"{"id":"x","action":"read","path":"/etc/shadow"}
{"id":"y","action":"read","file_path":"../../etc/passwd"}
{"id":"z","action":"read","pathname":"C:\\Windows\\system.ini"}
"#;
    let (_e, report) = import_evidence_ndjson_str(nd, &ImportOptions::default()).unwrap();
    assert_eq!(report.accepted, 0);
    assert!(report.rejected >= 3);
}

#[test]
fn accepts_absolute_process_object_label() {
    let nd = r#"{"id":"p1","action":"process_exec","object":"/usr/bin/sshd","source":"audit","sensor":"process"}"#;
    let (evs, report) = import_evidence_ndjson_str(nd, &ImportOptions::default()).unwrap();
    assert_eq!(report.accepted, 1);
    assert_eq!(evs[0].object.as_deref(), Some("/usr/bin/sshd"));
}

#[test]
fn rejects_bad_payload_blob_key() {
    let mut e = ExternalEvidenceEvent::new("s", "s", "1", EvidenceAction::HttpRequest);
    e.payload_blob = Some("/tmp/evil".into());
    assert!(e.validate().is_err());
}

#[test]
fn process_only_canary_cannot_satisfy_required_containment() {
    let b = resolve_boundary(&BoundaryContract::eval_example(), ResolveOpts::default())
        .unwrap()
        .with_run_id("r1");
    let receipts = post_run_canary_receipts("r1", Some(&b), false, true);
    assert!(
        receipts.iter().all(|r| !r.satisfies_required_containment()),
        "would allow false-green fail-closed gates"
    );
}
