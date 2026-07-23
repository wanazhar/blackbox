//! 1.9 Phase C: security decisions and action↔effect reconciliation.
//!
//! Exit gate: distinguish denied-not-executed from denied-but-bypassed with
//! cited evidence.

use blackbox::protocol::validate_json_object;
use blackbox::security::{
    reconcile_run, Acknowledgement, AcknowledgementActor, ActionFingerprint, DecisionIntegrity,
    DecisionKind, ObservedEffect, ObservedExecution, OverrideInfo, ReconcileInput,
    ReconcileOutcomeKind, SecurityDecision, SECURITY_DECISION_SCHEMA,
};
use chrono::Utc;

#[test]
fn exit_gate_denied_not_executed_vs_bypassed() {
    let fp = ActionFingerprint::process_exec(
        &["curl".into(), "https://evil.example/x".into()],
        Some("/tmp"),
    );

    // Case 1: denied, never executed.
    let deny = SecurityDecision::builder("opa", DecisionKind::Deny, fp.hash())
        .action(fp.clone())
        .id("d-noexec")
        .run_id("run-a")
        .rule_ids(vec!["block-egress".into()])
        .build();
    let noexec = reconcile_run(&ReconcileInput {
        run_id: Some("run-a".into()),
        decisions: vec![deny],
        executions: vec![],
        effects: vec![],
    });
    assert_eq!(noexec[0].outcome, ReconcileOutcomeKind::DeniedNotExecuted);
    assert!(noexec[0]
        .citations
        .iter()
        .any(|c| c.id == "d-noexec" && c.kind == "security.decision"));

    // Case 2: denied, then achieved via MCP tool path with same network target.
    let net = ActionFingerprint::network("evil.example");
    let deny2 = SecurityDecision::builder("proxy", DecisionKind::Deny, net.hash())
        .action(net.clone())
        .id("d-bypass")
        .run_id("run-b")
        .build();
    let bypass = reconcile_run(&ReconcileInput {
        run_id: Some("run-b".into()),
        decisions: vec![deny2],
        executions: vec![ObservedExecution {
            event_id: "mcp-fetch".into(),
            action: net,
            succeeded: true,
        }],
        effects: vec![ObservedEffect {
            event_id: "net-connect".into(),
            action: ActionFingerprint::network("evil.example"),
        }],
    });
    assert_eq!(bypass[0].outcome, ReconcileOutcomeKind::DeniedButBypassed);
    assert!(bypass[0].execution_event_ids.contains(&"mcp-fetch".into()));
    assert!(bypass[0].citations.len() >= 2);
}

#[test]
fn decision_action_hash_must_match_for_exact_link() {
    let declared = ActionFingerprint::process_exec(&["rm".into(), "a".into()], None);
    let executed = ActionFingerprint::process_exec(&["rm".into(), "b".into()], None);
    let d = SecurityDecision::builder("harness", DecisionKind::Allow, declared.hash())
        .action(declared)
        .build();
    let outs = reconcile_run(&ReconcileInput {
        decisions: vec![d],
        executions: vec![ObservedExecution {
            event_id: "ex".into(),
            action: executed,
            succeeded: true,
        }],
        effects: vec![],
        run_id: None,
    });
    // Same family target `rm` → related (ambiguous for allow without exact hash).
    assert!(
        outs[0].outcome == ReconcileOutcomeKind::Ambiguous
            || outs
                .iter()
                .any(|o| o.outcome == ReconcileOutcomeKind::EffectWithoutDecision),
        "got {:?}",
        outs.iter().map(|o| o.outcome).collect::<Vec<_>>()
    );
}

#[test]
fn self_asserted_signed_verified_demoted() {
    let mut d = SecurityDecision::builder("opa", DecisionKind::Deny, "aa".repeat(32))
        .integrity(DecisionIntegrity::SignedVerified)
        .build();
    assert_eq!(d.schema, SECURITY_DECISION_SCHEMA);
    d.normalize_integrity(false);
    assert_eq!(d.integrity, DecisionIntegrity::Unverified);
}

#[test]
fn user_ack_agent_ack_and_override_distinct() {
    let fp = ActionFingerprint::tool("shell", None);
    let user = SecurityDecision::builder("harness", DecisionKind::Warn, fp.hash())
        .action(fp.clone())
        .acknowledgement(Acknowledgement {
            actor: AcknowledgementActor::User,
            at: Utc::now(),
            note: None,
        })
        .build();
    let agent = SecurityDecision::builder("harness", DecisionKind::Warn, fp.hash())
        .action(fp.clone())
        .acknowledgement(Acknowledgement {
            actor: AcknowledgementActor::Agent,
            at: Utc::now(),
            note: None,
        })
        .build();
    let over = SecurityDecision::builder("harness", DecisionKind::Warn, fp.hash())
        .action(fp.clone())
        .acknowledgement(Acknowledgement {
            actor: AcknowledgementActor::User,
            at: Utc::now(),
            note: None,
        })
        .override_info(OverrideInfo {
            actor: "admin".into(),
            reason: Some("break-glass".into()),
            at: Utc::now(),
        })
        .build();

    for (d, expect_note) in [
        (user, "acknowledged_by=user"),
        (agent, "acknowledged_by=agent"),
        (over, "policy_override=true"),
    ] {
        let outs = reconcile_run(&ReconcileInput {
            decisions: vec![d],
            executions: vec![ObservedExecution {
                event_id: "e".into(),
                action: fp.clone(),
                succeeded: true,
            }],
            effects: vec![],
            run_id: None,
        });
        assert_eq!(outs[0].outcome, ReconcileOutcomeKind::WarnedAndAcknowledged);
        assert!(
            outs[0].notes.as_deref().unwrap_or("").contains(expect_note),
            "expected {expect_note} in {:?}",
            outs[0].notes
        );
    }
}

#[test]
fn decision_validates_against_protocol() {
    let fp = ActionFingerprint::network("example.com");
    let d = SecurityDecision::builder("falco", DecisionKind::Deny, fp.hash())
        .action(fp)
        .rule_ids(vec!["net-1".into()])
        .build();
    let v = serde_json::to_value(&d).unwrap();
    let report = validate_json_object(&v);
    assert!(report.ok, "{:?}", report.errors);
}

#[test]
fn duplicate_decisions_both_reported() {
    let fp = ActionFingerprint::tool("write", None);
    let d1 = SecurityDecision::builder("opa", DecisionKind::Deny, fp.hash())
        .action(fp.clone())
        .id("d1")
        .build();
    let d2 = SecurityDecision::builder("cedar", DecisionKind::Deny, fp.hash())
        .action(fp)
        .id("d2")
        .build();
    let outs = reconcile_run(&ReconcileInput {
        decisions: vec![d1, d2],
        executions: vec![],
        effects: vec![],
        run_id: Some("r".into()),
    });
    assert_eq!(outs.len(), 2);
    assert!(outs
        .iter()
        .all(|o| o.outcome == ReconcileOutcomeKind::DeniedNotExecuted));
}

#[test]
fn unrelated_actions_do_not_count_as_bypass() {
    let denied = ActionFingerprint::process_exec(
        &["curl".into(), "https://evil.example".into()],
        None,
    );
    let d = SecurityDecision::builder("opa", DecisionKind::Deny, denied.hash())
        .action(denied)
        .build();
    let other = ActionFingerprint::process_exec(&["echo".into(), "hi".into()], None);
    let outs = reconcile_run(&ReconcileInput {
        decisions: vec![d],
        executions: vec![ObservedExecution {
            event_id: "echo".into(),
            action: other,
            succeeded: true,
        }],
        effects: vec![],
        run_id: None,
    });
    assert!(outs
        .iter()
        .any(|o| o.outcome == ReconcileOutcomeKind::DeniedNotExecuted));
    assert!(!outs
        .iter()
        .any(|o| o.outcome == ReconcileOutcomeKind::DeniedButBypassed));
}
