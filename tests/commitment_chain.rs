//! 1.9 Phase D: run evidence commitments and tamper detection.

use blackbox::commitment::{
    build_run_commitment, generate_signing_key, sign_run_root, verify_commitment,
    verify_run_root_signature, ChainFault, SignatureStatus, COMMITMENT_RUN_SCHEMA,
};
use blackbox::core::event::{EventSource, TraceEvent};
use blackbox::protocol::validate_json_object;

fn ev(run: &str, seq: u64, kind: &str) -> TraceEvent {
    let mut e = TraceEvent::new(run, EventSource::Tool, kind);
    e.sequence = seq;
    e.id = format!("{run}-{seq}");
    e
}

#[test]
fn detects_insertion_deletion_replacement_reordering() {
    let events = vec![
        ev("run", 1, "run.started"),
        ev("run", 2, "tool.call"),
        ev("run", 3, "run.ended"),
    ];
    let commitment = build_run_commitment("run", &events, &[], None, None, true);
    assert_eq!(commitment.schema, COMMITMENT_RUN_SCHEMA);

    // Insertion
    let mut inserted = events.clone();
    let mut extra = ev("run", 4, "injected");
    extra.id = "injected".into();
    inserted.push(extra);
    let r = verify_commitment(&commitment, &inserted, None, &[]);
    assert!(!r.ok);

    // Deletion
    let deleted: Vec<_> = events.iter().take(2).cloned().collect();
    let r = verify_commitment(&commitment, &deleted, None, &[]);
    assert!(!r.ok);
    assert!(r.chain.faults.iter().any(|f| matches!(
        f,
        ChainFault::Deletion { .. } | ChainFault::Truncation { .. } | ChainFault::Insertion { .. }
    )) || !r.root_ok);

    // Replacement
    let mut replaced = events.clone();
    replaced[1].kind = "tool.result".into();
    let r = verify_commitment(&commitment, &replaced, None, &[]);
    assert!(!r.ok);

    // Reordering of embedded links
    let mut reordered = commitment.clone();
    reordered.links.swap(1, 2);
    let r = verify_commitment(&reordered, &events, None, &[]);
    assert!(!r.ok);
}

#[test]
fn optional_signature_verify_and_key_states() {
    let events = vec![ev("r", 1, "a"), ev("r", 2, "b")];
    let mut c = build_run_commitment("r", &events, &["recv1".into()], Some("man1"), None, true);
    let key = generate_signing_key();
    let signed = sign_run_root(&key, &c.root_hash);
    c.signature = Some(signed.clone());

    let report = verify_commitment(&c, &events, None, &[]);
    assert!(report.ok);
    assert_eq!(report.signature, SignatureStatus::Valid);

    // Unknown key
    let report = verify_commitment(&c, &events, Some(&["00".repeat(32)]), &[]);
    assert_eq!(report.signature, SignatureStatus::UnknownKey);

    // Revoked
    let pk = signed.public_key.clone();
    let report = verify_commitment(&c, &events, None, std::slice::from_ref(&pk));
    assert_eq!(report.signature, SignatureStatus::RevokedKey);

    // Direct API
    assert_eq!(
        verify_run_root_signature(&signed, &c.root_hash, Some(&[pk]), &[]),
        SignatureStatus::Valid
    );
}

#[test]
fn commitment_validates_protocol_schema() {
    let events = vec![ev("r", 1, "x")];
    let c = build_run_commitment("r", &events, &[], None, None, false);
    let v = serde_json::to_value(&c).unwrap();
    // ensure required fields present
    assert!(v.get("root_hash").is_some());
    let report = validate_json_object(&v);
    assert!(report.ok, "{:?}", report.errors);
}

#[test]
fn honesty_limitations_always_present() {
    let c = build_run_commitment("r", &[], &[], None, None, true);
    assert!(c
        .limitations
        .iter()
        .any(|l| l.contains("does_not_prove_observation_completeness")));
    assert!(c
        .limitations
        .iter()
        .any(|l| l.contains("proves_record_consistency_after_commitment")));
}

#[test]
fn receipt_and_manifest_roots_affect_root_hash() {
    let events = vec![ev("r", 1, "a")];
    let a = build_run_commitment("r", &events, &[], None, None, true);
    let b = build_run_commitment("r", &events, &["receipt".into()], Some("man"), None, true);
    assert_ne!(a.root_hash, b.root_hash);
    assert_eq!(a.chain_tip, b.chain_tip);
}
