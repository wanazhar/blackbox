//! Typed incident continuation relations (1.8).
//!
//! A positive continuation conclusion requires an explainable entity
//! relationship. Unrelated later activity must not satisfy continuation.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::boundary::{BoundaryFinding, EntityKind, EvidenceEdge, EvidenceRelation};
use crate::core::event::Confidence;
use crate::evidence::ExternalEvidenceEvent;

use super::graph::IncidentSignal;

/// How later activity relates to the earliest signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationRelation {
    SameProcessLineage,
    SameAgentIdentity,
    SameCredential,
    SameDestination,
    SameArtifact,
    SameTechnique,
    /// Explicit non-continuation: later activity without a shared entity.
    UnrelatedLaterActivity,
}

impl ContinuationRelation {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameProcessLineage => "same_process_lineage",
            Self::SameAgentIdentity => "same_agent_identity",
            Self::SameCredential => "same_credential",
            Self::SameDestination => "same_destination",
            Self::SameArtifact => "same_artifact",
            Self::SameTechnique => "same_technique",
            Self::UnrelatedLaterActivity => "unrelated_later_activity",
        }
    }

    /// Whether this relation counts as incident continuation.
    pub fn is_continuation(self) -> bool {
        !matches!(self, Self::UnrelatedLaterActivity)
    }
}

/// Cited conclusion that execution continued after the earliest signal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContinuationConclusion {
    pub relation: ContinuationRelation,
    pub initial_signal_id: String,
    pub continuation_evidence_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_entity_kind: Option<EntityKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_entity_id: Option<String>,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    pub at: DateTime<Utc>,
}

/// Inputs for continuation analysis.
#[derive(Debug, Clone, Copy)]
pub struct ContinuationInputs<'a> {
    pub signal: &'a IncidentSignal,
    pub findings_by_run: &'a [(String, Vec<BoundaryFinding>)],
    pub external: &'a [ExternalEvidenceEvent],
    pub edges: &'a [EvidenceEdge],
}

/// Evaluate typed continuation after `signal`.
///
/// Returns `None` when there is no later activity at all.
/// Returns `Some(conclusion)` where relation may be
/// [`ContinuationRelation::UnrelatedLaterActivity`].
pub fn evaluate_continuation(inputs: ContinuationInputs<'_>) -> Option<ContinuationConclusion> {
    let sig = inputs.signal;
    let mut candidates: Vec<ContinuationConclusion> = Vec::new();

    // Technique / token reuse via later findings (token or detector, not kind alone).
    let seed_finding = inputs.findings_by_run.iter().find_map(|(_, fs)| {
        fs.iter().find(|f| f.id == sig.ref_id)
    });
    for (run_id, findings) in inputs.findings_by_run {
        for f in findings {
            if f.created_at <= sig.at || f.id == sig.ref_id {
                continue;
            }
            let same_technique = match seed_finding {
                Some(seed) => {
                    (seed.token.is_some() && seed.token == f.token)
                        || seed.detector == f.detector
                }
                None => f
                    .token
                    .as_ref()
                    .is_some_and(|t| sig.summary.contains(t.as_str()))
                    || sig.summary.contains(&f.detector),
            };
            if same_technique {
                candidates.push(ContinuationConclusion {
                    relation: ContinuationRelation::SameTechnique,
                    initial_signal_id: sig.ref_id.clone(),
                    continuation_evidence_id: f.id.clone(),
                    related_entity_kind: Some(EntityKind::Other("finding".into())),
                    related_entity_id: Some(f.id.clone()),
                    confidence: Confidence::StronglyCorrelated,
                    reasons: vec![
                        "later_finding_same_technique".into(),
                        format!("run={run_id}"),
                        format!("detector={}", f.detector),
                    ],
                    at: f.created_at,
                });
            }
        }
    }

    // Edges that link entities after the signal.
    for edge in inputs.edges {
        if edge.created_at <= sig.at {
            continue;
        }
        let relation = match &edge.relation {
            EvidenceRelation::Spawn | EvidenceRelation::SameProcess => {
                Some(ContinuationRelation::SameProcessLineage)
            }
            EvidenceRelation::SameTraceId
            | EvidenceRelation::SameWorkload
            | EvidenceRelation::Delegation => Some(ContinuationRelation::SameAgentIdentity),
            EvidenceRelation::CredentialUse => Some(ContinuationRelation::SameCredential),
            EvidenceRelation::NetworkConnection | EvidenceRelation::RemoteEffect => {
                Some(ContinuationRelation::SameDestination)
            }
            EvidenceRelation::ArtifactDerivation => Some(ContinuationRelation::SameArtifact),
            EvidenceRelation::PolicyViolation => Some(ContinuationRelation::SameTechnique),
            EvidenceRelation::TemporalProximity | EvidenceRelation::Other(_) => None,
        };
        let Some(rel) = relation else {
            continue;
        };
        // Prefer edges that reference the signal entity.
        let cites_signal = edge.from_id == sig.ref_id
            || edge.to_id == sig.ref_id
            || edge.reasons.iter().any(|r| r.contains(&sig.ref_id));
        let confidence = if cites_signal {
            edge.confidence
        } else if matches!(
            edge.confidence,
            Confidence::Confirmed | Confidence::StronglyCorrelated
        ) {
            Confidence::WeaklyCorrelated
        } else {
            continue;
        };
        candidates.push(ContinuationConclusion {
            relation: rel,
            initial_signal_id: sig.ref_id.clone(),
            continuation_evidence_id: edge.id.clone(),
            related_entity_kind: Some(edge.to_kind.clone()),
            related_entity_id: Some(edge.to_id.clone()),
            confidence,
            reasons: {
                let mut r = vec![format!("edge_relation={}", edge.relation.as_str())];
                r.extend(edge.reasons.iter().cloned());
                if cites_signal {
                    r.push("edge_cites_initial_signal".into());
                }
                r
            },
            at: edge.created_at,
        });
    }

    // Same destination / identity in later external evidence.
    if let Some(signal_dest) = signal_destination(sig, &inputs) {
        for ev in inputs.external {
            let at = ev.occurred_at.or(ev.observed_at).unwrap_or(ev.ingested_at);
            if at <= sig.at || ev.id == sig.ref_id {
                continue;
            }
            if ev.destination.as_deref() == Some(signal_dest.as_str()) {
                candidates.push(ContinuationConclusion {
                    relation: ContinuationRelation::SameDestination,
                    initial_signal_id: sig.ref_id.clone(),
                    continuation_evidence_id: ev.id.clone(),
                    related_entity_kind: Some(EntityKind::ExternalEvidence),
                    related_entity_id: Some(ev.id.clone()),
                    confidence: Confidence::StronglyCorrelated,
                    reasons: vec![
                        "later_external_same_destination".into(),
                        format!("destination={signal_dest}"),
                    ],
                    at,
                });
            }
            // Same agent identity markers.
            if identities_overlap(sig, &inputs, ev) {
                candidates.push(ContinuationConclusion {
                    relation: ContinuationRelation::SameAgentIdentity,
                    initial_signal_id: sig.ref_id.clone(),
                    continuation_evidence_id: ev.id.clone(),
                    related_entity_kind: Some(EntityKind::ExternalEvidence),
                    related_entity_id: Some(ev.id.clone()),
                    confidence: Confidence::WeaklyCorrelated,
                    reasons: vec!["later_external_same_identity_markers".into()],
                    at,
                });
            }
        }
    } else {
        for ev in inputs.external {
            let at = ev.occurred_at.or(ev.observed_at).unwrap_or(ev.ingested_at);
            if at <= sig.at || ev.id == sig.ref_id {
                continue;
            }
            if identities_overlap(sig, &inputs, ev) {
                candidates.push(ContinuationConclusion {
                    relation: ContinuationRelation::SameAgentIdentity,
                    initial_signal_id: sig.ref_id.clone(),
                    continuation_evidence_id: ev.id.clone(),
                    related_entity_kind: Some(EntityKind::ExternalEvidence),
                    related_entity_id: Some(ev.id.clone()),
                    confidence: Confidence::WeaklyCorrelated,
                    reasons: vec!["later_external_same_identity_markers".into()],
                    at,
                });
            }
        }
    }

    if let Some(best) = pick_best_continuation(candidates) {
        return Some(best);
    }

    // Later activity exists but no typed relation — explicitly unrelated.
    let later_finding = inputs.findings_by_run.iter().find_map(|(_, fs)| {
        fs.iter()
            .find(|f| f.created_at > sig.at && f.id != sig.ref_id)
            .map(|f| (f.id.clone(), f.created_at))
    });
    let later_ext = inputs.external.iter().find_map(|e| {
        let at = e.occurred_at.or(e.observed_at).unwrap_or(e.ingested_at);
        if at > sig.at && e.id != sig.ref_id {
            Some((e.id.clone(), at))
        } else {
            None
        }
    });
    match (later_finding, later_ext) {
        (None, None) => None,
        (Some((id, at)), _) | (None, Some((id, at))) => Some(ContinuationConclusion {
            relation: ContinuationRelation::UnrelatedLaterActivity,
            initial_signal_id: sig.ref_id.clone(),
            continuation_evidence_id: id,
            related_entity_kind: None,
            related_entity_id: None,
            confidence: Confidence::Unknown,
            reasons: vec![
                "later_activity_without_shared_entity".into(),
                "does_not_satisfy_continuation".into(),
            ],
            at,
        }),
    }
}

fn pick_best_continuation(
    mut candidates: Vec<ContinuationConclusion>,
) -> Option<ContinuationConclusion> {
    if candidates.is_empty() {
        return None;
    }
    candidates.sort_by(|a, b| {
        relation_rank(b.relation)
            .cmp(&relation_rank(a.relation))
            .then(confidence_rank(b.confidence).cmp(&confidence_rank(a.confidence)))
            .then(a.at.cmp(&b.at))
    });
    candidates.into_iter().next()
}

fn relation_rank(r: ContinuationRelation) -> u8 {
    match r {
        ContinuationRelation::SameProcessLineage => 6,
        ContinuationRelation::SameCredential => 5,
        ContinuationRelation::SameAgentIdentity => 4,
        ContinuationRelation::SameDestination => 3,
        ContinuationRelation::SameArtifact => 3,
        ContinuationRelation::SameTechnique => 2,
        ContinuationRelation::UnrelatedLaterActivity => 0,
    }
}

fn confidence_rank(c: Confidence) -> u8 {
    match c {
        Confidence::Confirmed => 4,
        Confidence::StronglyCorrelated => 3,
        Confidence::WeaklyCorrelated => 2,
        Confidence::Unknown => 1,
    }
}

fn signal_destination(
    sig: &IncidentSignal,
    inputs: &ContinuationInputs<'_>,
) -> Option<String> {
    // From external evidence with matching id.
    if let Some(ev) = inputs.external.iter().find(|e| e.id == sig.ref_id) {
        return ev.destination.clone();
    }
    // From finding summary "unexpected destination X".
    for (_, findings) in inputs.findings_by_run {
        if let Some(f) = findings.iter().find(|f| f.id == sig.ref_id) {
            if let Some(rest) = f.summary.strip_prefix("unexpected destination ") {
                return Some(rest.to_string());
            }
            for ext_id in &f.external_evidence_ids {
                if let Some(ev) = inputs.external.iter().find(|e| e.id == *ext_id) {
                    if ev.destination.is_some() {
                        return ev.destination.clone();
                    }
                }
            }
        }
    }
    None
}

fn identities_overlap(
    sig: &IncidentSignal,
    inputs: &ContinuationInputs<'_>,
    later: &ExternalEvidenceEvent,
) -> bool {
    let Some(seed) = inputs.external.iter().find(|e| e.id == sig.ref_id).or_else(|| {
        // Via finding citations.
        inputs.findings_by_run.iter().find_map(|(_, fs)| {
            fs.iter().find(|f| f.id == sig.ref_id).and_then(|f| {
                f.external_evidence_ids.iter().find_map(|id| {
                    inputs.external.iter().find(|e| e.id == *id)
                })
            })
        })
    }) else {
        // Fall back to run_id match on the signal.
        return sig
            .run_id
            .as_ref()
            .is_some_and(|rid| later.linked_run_id.as_ref() == Some(rid));
    };
    let a = &seed.identity;
    let b = &later.identity;
    pairs_eq(a.trace_id.as_deref(), b.trace_id.as_deref())
        || pairs_eq(a.run_id.as_deref(), b.run_id.as_deref())
        || pairs_eq(a.session.as_deref(), b.session.as_deref())
        || pairs_eq(a.principal.as_deref(), b.principal.as_deref())
        || pairs_eq(a.workload.as_deref(), b.workload.as_deref())
        || pairs_eq(
            seed.linked_run_id.as_deref(),
            later.linked_run_id.as_deref(),
        )
}

fn pairs_eq(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => !x.is_empty() && x == y,
        _ => false,
    }
}

/// Boolean view: true only when a typed continuation relation holds.
pub fn continued_after_signal(conclusion: Option<&ContinuationConclusion>) -> Option<bool> {
    conclusion.map(|c| c.relation.is_continuation())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{FindingKind, FindingSeverity};
    use chrono::Duration;

    #[test]
    fn unrelated_later_does_not_continue() {
        let t0 = Utc::now();
        let signal = IncidentSignal {
            ref_id: "find-1".into(),
            kind: "boundary.violation".into(),
            summary: "unexpected destination https://evil.example".into(),
            at: t0,
            run_id: Some("r1".into()),
        };
        let mut later = BoundaryFinding {
            schema: "blackbox.boundary.finding/v1".into(),
            id: "find-2".into(),
            run_id: "r1".into(),
            kind: FindingKind::BehaviorTransition,
            detector: "package_install".into(),
            severity: FindingSeverity::Warn,
            summary: "unrelated package install".into(),
            evidence_event_ids: vec![],
            external_evidence_ids: vec![],
            token: Some("package_install".into()),
            disposition: None,
            recommendation: None,
            created_at: t0 + Duration::seconds(30),
            confidence_note: "deterministic_detector".into(),
            decision: None,
        };
        // Ensure different technique from signal.
        later.detector = "package_install".into();
        let findings = vec![("r1".into(), vec![later])];
        let conclusion = evaluate_continuation(ContinuationInputs {
            signal: &signal,
            findings_by_run: &findings,
            external: &[],
            edges: &[],
        });
        let c = conclusion.expect("later activity");
        // package_install finding has different kind than boundary.violation — if
        // technique match fires via summary it shouldn't for this token.
        assert_eq!(c.relation, ContinuationRelation::UnrelatedLaterActivity);
        assert!(!c.relation.is_continuation());
        assert_eq!(continued_after_signal(Some(&c)), Some(false));
    }

    #[test]
    fn same_destination_continues() {
        let t0 = Utc::now();
        let signal = IncidentSignal {
            ref_id: "ext-1".into(),
            kind: "external_evidence".into(),
            summary: "http_request https://evil.example".into(),
            at: t0,
            run_id: Some("r1".into()),
        };
        let mut e1 = ExternalEvidenceEvent::new("proxy", "proxy", "1", crate::evidence::EvidenceAction::HttpRequest);
        e1.id = "ext-1".into();
        e1.destination = Some("https://evil.example".into());
        e1.occurred_at = Some(t0);
        let mut e2 = ExternalEvidenceEvent::new("proxy", "proxy", "2", crate::evidence::EvidenceAction::HttpRequest);
        e2.id = "ext-2".into();
        e2.destination = Some("https://evil.example".into());
        e2.occurred_at = Some(t0 + Duration::seconds(10));
        let c = evaluate_continuation(ContinuationInputs {
            signal: &signal,
            findings_by_run: &[],
            external: &[e1, e2],
            edges: &[],
        })
        .unwrap();
        assert_eq!(c.relation, ContinuationRelation::SameDestination);
        assert!(c.relation.is_continuation());
        assert_eq!(c.continuation_evidence_id, "ext-2");
    }
}
