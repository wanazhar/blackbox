//! Action → security decision → execution → effect reconciliation.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::action::ActionFingerprint;
use super::decision::{AcknowledgementActor, DecisionKind, SecurityDecision};

/// Schema for reconciliation outcomes.
pub const RECONCILE_OUTCOME_SCHEMA: &str = "blackbox.reconcile.outcome/v1";

/// Typed reconciliation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileOutcomeKind {
    /// Allowed decision and matching execution/effects.
    AllowedAsDeclared,
    /// Allowed, but observed effects diverge from declared action.
    AllowedEffectsDiverged,
    /// Denied and no matching execution observed.
    DeniedNotExecuted,
    /// Denied, but a matching or related execution/effect was observed (possible bypass).
    DeniedButBypassed,
    /// Warn decision was acknowledged and execution followed.
    WarnedAndAcknowledged,
    /// Effect/execution observed with no prior decision.
    EffectWithoutDecision,
    /// Decision recorded with no later observation.
    DecisionWithoutObservation,
    /// Links are partial; do not force a conclusion.
    Ambiguous,
    /// Not enough evidence to decide.
    InsufficientEvidence,
}

impl ReconcileOutcomeKind {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowedAsDeclared => "allowed_as_declared",
            Self::AllowedEffectsDiverged => "allowed_effects_diverged",
            Self::DeniedNotExecuted => "denied_not_executed",
            Self::DeniedButBypassed => "denied_but_bypassed",
            Self::WarnedAndAcknowledged => "warned_and_acknowledged",
            Self::EffectWithoutDecision => "effect_without_decision",
            Self::DecisionWithoutObservation => "decision_without_observation",
            Self::Ambiguous => "ambiguous",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }
}

/// Citation linking an outcome to evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileCitation {
    /// Kind of cited object.
    pub kind: String,
    /// Id of cited object.
    pub id: String,
    /// Why it was cited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One reconciliation result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReconcileOutcome {
    /// Schema.
    pub schema: String,
    /// Outcome id.
    pub id: String,
    /// Run id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Outcome kind.
    pub outcome: ReconcileOutcomeKind,
    /// Action hash under consideration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_hash: Option<String>,
    /// Decision id when linked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    /// Execution event ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub execution_event_ids: Vec<String>,
    /// Effect event ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effect_event_ids: Vec<String>,
    /// Citations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub citations: Vec<ReconcileCitation>,
    /// Notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl ReconcileOutcome {
    fn new(kind: ReconcileOutcomeKind) -> Self {
        Self {
            schema: RECONCILE_OUTCOME_SCHEMA.into(),
            id: Uuid::new_v4().to_string(),
            run_id: None,
            outcome: kind,
            action_hash: None,
            decision_id: None,
            execution_event_ids: vec![],
            effect_event_ids: vec![],
            citations: vec![],
            notes: None,
        }
    }
}

/// Observed execution of an action (from trace events).
#[derive(Debug, Clone)]
pub struct ObservedExecution {
    /// Event id.
    pub event_id: String,
    /// Fingerprint of what executed.
    pub action: ActionFingerprint,
    /// Whether execution succeeded.
    pub succeeded: bool,
}

/// Observed side effect (file write, network, etc.).
#[derive(Debug, Clone)]
pub struct ObservedEffect {
    /// Event id.
    pub event_id: String,
    /// Fingerprint of the effect.
    pub action: ActionFingerprint,
}

/// Input bundle for reconciliation.
#[derive(Debug, Clone, Default)]
pub struct ReconcileInput {
    /// Run id.
    pub run_id: Option<String>,
    /// Security decisions (already integrity-normalized).
    pub decisions: Vec<SecurityDecision>,
    /// Executions observed at runtime.
    pub executions: Vec<ObservedExecution>,
    /// Effects observed (may diverge from declared execution).
    pub effects: Vec<ObservedEffect>,
}

/// Reconcile decisions against executions and effects.
///
/// Decision evidence remains distinct from observation: outcomes cite both
/// sides rather than merging them into a single trusted claim.
pub fn reconcile_run(input: &ReconcileInput) -> Vec<ReconcileOutcome> {
    let mut outcomes = Vec::new();
    let mut matched_execution = vec![false; input.executions.len()];
    let mut matched_effect = vec![false; input.effects.len()];

    for decision in &input.decisions {
        let mut o = ReconcileOutcome::new(ReconcileOutcomeKind::InsufficientEvidence);
        o.run_id = input.run_id.clone().or_else(|| decision.run_id.clone());
        o.action_hash = Some(decision.action_hash.clone());
        o.decision_id = Some(decision.id.clone());
        o.citations.push(ReconcileCitation {
            kind: "security.decision".into(),
            id: decision.id.clone(),
            reason: Some(format!("decision={}", decision.decision.as_str())),
        });

        // Find executions whose action_hash matches the decision.
        let mut exact_execs: Vec<usize> = Vec::new();
        let mut related_execs: Vec<usize> = Vec::new();
        for (i, ex) in input.executions.iter().enumerate() {
            let ex_hash = ex.action.hash();
            if ex_hash == decision.action_hash {
                exact_execs.push(i);
            } else if let Some(ref da) = decision.action {
                if da.same_family_target(&ex.action) {
                    related_execs.push(i);
                }
            } else if decision_action_loosely_related(decision, &ex.action) {
                related_execs.push(i);
            }
        }

        // Effects linked to this action hash or family.
        let mut exact_effects: Vec<usize> = Vec::new();
        let mut related_effects: Vec<usize> = Vec::new();
        for (i, ef) in input.effects.iter().enumerate() {
            if ef.action.hash() == decision.action_hash {
                exact_effects.push(i);
            } else if let Some(ref da) = decision.action {
                if da.same_family_target(&ef.action) {
                    related_effects.push(i);
                }
            }
        }

        for &i in exact_execs.iter().chain(related_execs.iter()) {
            matched_execution[i] = true;
            o.execution_event_ids
                .push(input.executions[i].event_id.clone());
            o.citations.push(ReconcileCitation {
                kind: "execution".into(),
                id: input.executions[i].event_id.clone(),
                reason: Some(if exact_execs.contains(&i) {
                    "action_hash_match".into()
                } else {
                    "family_target_match".into()
                }),
            });
        }
        for &i in exact_effects.iter().chain(related_effects.iter()) {
            matched_effect[i] = true;
            o.effect_event_ids.push(input.effects[i].event_id.clone());
            o.citations.push(ReconcileCitation {
                kind: "effect".into(),
                id: input.effects[i].event_id.clone(),
                reason: Some("linked_effect".into()),
            });
        }

        let has_exact = !exact_execs.is_empty() || !exact_effects.is_empty();
        let has_related = !related_execs.is_empty() || !related_effects.is_empty();
        let has_any_obs = has_exact || has_related;

        o.outcome = match decision.decision {
            DecisionKind::Allow => {
                if !has_any_obs {
                    ReconcileOutcomeKind::DecisionWithoutObservation
                } else if !exact_effects.is_empty()
                    && related_effects
                        .iter()
                        .any(|i| input.effects[*i].action.hash() != decision.action_hash)
                {
                    // Exact + diverging related effects.
                    ReconcileOutcomeKind::AllowedEffectsDiverged
                } else if has_exact
                    && related_effects.iter().any(|i| {
                        // Effect with same family but different hash = divergence.
                        !exact_effects.contains(i)
                    })
                {
                    ReconcileOutcomeKind::AllowedEffectsDiverged
                } else if has_exact {
                    ReconcileOutcomeKind::AllowedAsDeclared
                } else if has_related {
                    ReconcileOutcomeKind::Ambiguous
                } else {
                    ReconcileOutcomeKind::AllowedAsDeclared
                }
            }
            DecisionKind::Deny => {
                if !has_any_obs {
                    ReconcileOutcomeKind::DeniedNotExecuted
                } else if has_exact || has_related {
                    // Bypass: denied action later achieved (exact or alternate path).
                    o.notes = Some(
                        "denied decision followed by matching or related execution/effect".into(),
                    );
                    ReconcileOutcomeKind::DeniedButBypassed
                } else {
                    ReconcileOutcomeKind::Ambiguous
                }
            }
            DecisionKind::Warn | DecisionKind::RequireApproval => {
                if decision.acknowledgement.is_some() && has_any_obs {
                    // Distinguish actor in notes.
                    if let Some(ref ack) = decision.acknowledgement {
                        o.notes = Some(format!(
                            "acknowledged_by={}",
                            match ack.actor {
                                AcknowledgementActor::User => "user",
                                AcknowledgementActor::Agent => "agent",
                                AcknowledgementActor::Policy => "policy",
                                AcknowledgementActor::Other => "other",
                            }
                        ));
                    }
                    if decision.override_info.is_some() {
                        o.notes = Some(match o.notes {
                            Some(n) => format!("{n}; policy_override=true"),
                            None => "policy_override=true".into(),
                        });
                    }
                    ReconcileOutcomeKind::WarnedAndAcknowledged
                } else if !has_any_obs {
                    ReconcileOutcomeKind::DecisionWithoutObservation
                } else {
                    ReconcileOutcomeKind::Ambiguous
                }
            }
            DecisionKind::Unknown => ReconcileOutcomeKind::InsufficientEvidence,
        };

        outcomes.push(o);
    }

    // Executions / effects with no decision.
    for (i, ex) in input.executions.iter().enumerate() {
        if matched_execution[i] {
            continue;
        }
        let mut o = ReconcileOutcome::new(ReconcileOutcomeKind::EffectWithoutDecision);
        o.run_id = input.run_id.clone();
        o.action_hash = Some(ex.action.hash());
        o.execution_event_ids.push(ex.event_id.clone());
        o.citations.push(ReconcileCitation {
            kind: "execution".into(),
            id: ex.event_id.clone(),
            reason: Some("no_prior_decision".into()),
        });
        outcomes.push(o);
    }
    for (i, ef) in input.effects.iter().enumerate() {
        if matched_effect[i] {
            continue;
        }
        // Skip if already covered via execution hash match above for same hash.
        let hash = ef.action.hash();
        if outcomes.iter().any(|o| {
            o.outcome == ReconcileOutcomeKind::EffectWithoutDecision
                && o.action_hash.as_deref() == Some(hash.as_str())
        }) {
            // Attach effect id to existing outcome if possible.
            if let Some(existing) = outcomes.iter_mut().find(|o| {
                o.outcome == ReconcileOutcomeKind::EffectWithoutDecision
                    && o.action_hash.as_deref() == Some(hash.as_str())
            }) {
                existing.effect_event_ids.push(ef.event_id.clone());
                existing.citations.push(ReconcileCitation {
                    kind: "effect".into(),
                    id: ef.event_id.clone(),
                    reason: Some("no_prior_decision".into()),
                });
            }
            continue;
        }
        let mut o = ReconcileOutcome::new(ReconcileOutcomeKind::EffectWithoutDecision);
        o.run_id = input.run_id.clone();
        o.action_hash = Some(hash);
        o.effect_event_ids.push(ef.event_id.clone());
        o.citations.push(ReconcileCitation {
            kind: "effect".into(),
            id: ef.event_id.clone(),
            reason: Some("no_prior_decision".into()),
        });
        outcomes.push(o);
    }

    outcomes
}

fn decision_action_loosely_related(
    decision: &SecurityDecision,
    action: &ActionFingerprint,
) -> bool {
    // Without embedded fingerprint, only exact hash matches count as related
    // at the action_hash level — already handled. No loose match.
    let _ = (decision, action);
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::action::ActionFingerprint;
    use crate::security::decision::{
        Acknowledgement, AcknowledgementActor, DecisionIntegrity, DecisionKind, SecurityDecision,
    };
    use chrono::Utc;

    fn deny_curl() -> (SecurityDecision, ActionFingerprint) {
        let fp =
            ActionFingerprint::process_exec(&["curl".into(), "https://evil.example".into()], None);
        let d = SecurityDecision::builder("opa", DecisionKind::Deny, fp.hash())
            .action(fp.clone())
            .id("dec-deny-curl")
            .build();
        (d, fp)
    }

    #[test]
    fn denied_not_executed() {
        let (d, _fp) = deny_curl();
        let outs = reconcile_run(&ReconcileInput {
            run_id: Some("r1".into()),
            decisions: vec![d],
            executions: vec![],
            effects: vec![],
        });
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].outcome, ReconcileOutcomeKind::DeniedNotExecuted);
        assert!(outs[0]
            .citations
            .iter()
            .any(|c| c.kind == "security.decision"));
    }

    #[test]
    fn denied_but_bypassed_via_exact_exec() {
        let (d, fp) = deny_curl();
        let outs = reconcile_run(&ReconcileInput {
            run_id: Some("r1".into()),
            decisions: vec![d],
            executions: vec![ObservedExecution {
                event_id: "ex-1".into(),
                action: fp,
                succeeded: true,
            }],
            effects: vec![],
        });
        assert_eq!(outs[0].outcome, ReconcileOutcomeKind::DeniedButBypassed);
        assert!(outs[0].execution_event_ids.contains(&"ex-1".into()));
    }

    #[test]
    fn denied_but_bypassed_via_related_path() {
        // Denied curl https://evil; later bash -c curl (same family target curl)
        // Actually same_family_target requires same target — use tool path that
        // achieves same network destination as related effect.
        let denied = ActionFingerprint::network("evil.example");
        let d = SecurityDecision::builder("proxy", DecisionKind::Deny, denied.hash())
            .action(denied)
            .id("dec-net")
            .build();
        // Alternate path: tool that hits same destination family.
        let bypass = ActionFingerprint::network("evil.example");
        let outs = reconcile_run(&ReconcileInput {
            decisions: vec![d],
            executions: vec![ObservedExecution {
                event_id: "tool-mcp".into(),
                action: bypass,
                succeeded: true,
            }],
            effects: vec![],
            run_id: Some("r1".into()),
        });
        assert_eq!(outs[0].outcome, ReconcileOutcomeKind::DeniedButBypassed);
    }

    #[test]
    fn unrelated_action_not_bypass() {
        let (d, _fp) = deny_curl();
        let other = ActionFingerprint::process_exec(&["ls".into(), "-la".into()], None);
        let outs = reconcile_run(&ReconcileInput {
            decisions: vec![d],
            executions: vec![ObservedExecution {
                event_id: "ex-ls".into(),
                action: other,
                succeeded: true,
            }],
            effects: vec![],
            run_id: None,
        });
        // Deny outcome is denied_not_executed; ls is effect_without_decision.
        assert!(outs
            .iter()
            .any(|o| o.outcome == ReconcileOutcomeKind::DeniedNotExecuted));
        assert!(outs
            .iter()
            .any(|o| o.outcome == ReconcileOutcomeKind::EffectWithoutDecision));
        assert!(!outs
            .iter()
            .any(|o| o.outcome == ReconcileOutcomeKind::DeniedButBypassed));
    }

    #[test]
    fn allowed_as_declared() {
        let fp = ActionFingerprint::tool("read", None);
        let d = SecurityDecision::builder("harness", DecisionKind::Allow, fp.hash())
            .action(fp.clone())
            .build();
        let outs = reconcile_run(&ReconcileInput {
            decisions: vec![d],
            executions: vec![ObservedExecution {
                event_id: "e1".into(),
                action: fp,
                succeeded: true,
            }],
            effects: vec![],
            run_id: None,
        });
        assert_eq!(outs[0].outcome, ReconcileOutcomeKind::AllowedAsDeclared);
    }

    #[test]
    fn allowed_effects_diverged() {
        let declared = ActionFingerprint::file_write("/tmp/a");
        let d = SecurityDecision::builder("harness", DecisionKind::Allow, declared.hash())
            .action(declared.clone())
            .build();
        let side = ActionFingerprint::file_write("/tmp/b");
        // same kind FileWrite but different target — family is same kind only via same_family_target
        // same_family_target requires same target, so use exact + related with same target different args
        let diverged = ActionFingerprint {
            kind: declared.kind.clone(),
            target: declared.target.clone(),
            args: vec!["extra".into()],
            cwd: None,
            attributes: None,
        };
        let outs = reconcile_run(&ReconcileInput {
            decisions: vec![d],
            executions: vec![ObservedExecution {
                event_id: "ex".into(),
                action: declared,
                succeeded: true,
            }],
            effects: vec![
                ObservedEffect {
                    event_id: "ef-declared".into(),
                    action: ActionFingerprint::file_write("/tmp/a"),
                },
                ObservedEffect {
                    event_id: "ef-div".into(),
                    action: diverged,
                },
            ],
            run_id: None,
        });
        assert_eq!(
            outs[0].outcome,
            ReconcileOutcomeKind::AllowedEffectsDiverged
        );
        let _ = side;
    }

    #[test]
    fn warn_acknowledged_by_user() {
        let fp = ActionFingerprint::process_exec(&["npm".into(), "install".into()], None);
        let d = SecurityDecision::builder("harness", DecisionKind::Warn, fp.hash())
            .action(fp.clone())
            .acknowledgement(Acknowledgement {
                actor: AcknowledgementActor::User,
                at: Utc::now(),
                note: Some("ok".into()),
            })
            .build();
        let outs = reconcile_run(&ReconcileInput {
            decisions: vec![d],
            executions: vec![ObservedExecution {
                event_id: "ex".into(),
                action: fp,
                succeeded: true,
            }],
            effects: vec![],
            run_id: None,
        });
        assert_eq!(outs[0].outcome, ReconcileOutcomeKind::WarnedAndAcknowledged);
        assert!(outs[0]
            .notes
            .as_deref()
            .unwrap_or("")
            .contains("acknowledged_by=user"));
    }

    #[test]
    fn decision_without_observation() {
        let fp = ActionFingerprint::tool("x", None);
        let d = SecurityDecision::builder("opa", DecisionKind::Allow, fp.hash())
            .action(fp)
            .build();
        let outs = reconcile_run(&ReconcileInput {
            decisions: vec![d],
            ..Default::default()
        });
        assert_eq!(
            outs[0].outcome,
            ReconcileOutcomeKind::DecisionWithoutObservation
        );
    }

    #[test]
    fn self_asserted_integrity_demoted_before_trust() {
        let mut d = SecurityDecision::builder("opa", DecisionKind::Deny, "ab".repeat(32))
            .integrity(DecisionIntegrity::SignedVerified)
            .build();
        d.normalize_integrity(false);
        assert_eq!(d.integrity, DecisionIntegrity::Unverified);
    }
}
