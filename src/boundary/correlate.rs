//! Evidence correlation edges and multi-signal join (1.7 Phase D).

#![allow(missing_docs)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::event::Confidence;
use crate::evidence::{EvidenceAction, ExternalEvidenceEvent};

/// Schema for evidence graph edges.
pub const EVIDENCE_EDGE_SCHEMA: &str = "blackbox.evidence.edge/v1";

/// Relation types between evidence entities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRelation {
    Spawn,
    Delegation,
    CredentialUse,
    NetworkConnection,
    ArtifactDerivation,
    PolicyViolation,
    RemoteEffect,
    SameTraceId,
    SameProcess,
    SameWorkload,
    TemporalProximity,
    Other(String),
}

impl EvidenceRelation {
    /// Stable string form.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Spawn => "spawn",
            Self::Delegation => "delegation",
            Self::CredentialUse => "credential_use",
            Self::NetworkConnection => "network_connection",
            Self::ArtifactDerivation => "artifact_derivation",
            Self::PolicyViolation => "policy_violation",
            Self::RemoteEffect => "remote_effect",
            Self::SameTraceId => "same_trace_id",
            Self::SameProcess => "same_process",
            Self::SameWorkload => "same_workload",
            Self::TemporalProximity => "temporal_proximity",
            Self::Other(s) => s.as_str(),
        }
    }
}

/// Entity kinds that can appear as edge endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Run,
    Event,
    ExternalEvidence,
    ContainmentReceipt,
    ProvenanceRecord,
    Credential,
    Artifact,
    Incident,
    Other(String),
}

impl EntityKind {
    /// Stable string form.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Run => "run",
            Self::Event => "event",
            Self::ExternalEvidence => "external_evidence",
            Self::ContainmentReceipt => "containment_receipt",
            Self::ProvenanceRecord => "provenance_record",
            Self::Credential => "credential",
            Self::Artifact => "artifact",
            Self::Incident => "incident",
            Self::Other(s) => s.as_str(),
        }
    }
}

/// Directed evidence edge with explicit confidence and reasons.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEdge {
    pub schema: String,
    pub id: String,
    pub from_kind: EntityKind,
    pub from_id: String,
    pub to_kind: EntityKind,
    pub to_id: String,
    pub relation: EvidenceRelation,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
}

impl EvidenceEdge {
    /// Create a new edge.
    pub fn new(
        from_kind: EntityKind,
        from_id: impl Into<String>,
        to_kind: EntityKind,
        to_id: impl Into<String>,
        relation: EvidenceRelation,
        confidence: Confidence,
    ) -> Self {
        Self {
            schema: EVIDENCE_EDGE_SCHEMA.into(),
            id: format!("edge-{}", Uuid::new_v4()),
            from_kind,
            from_id: from_id.into(),
            to_kind,
            to_id: to_id.into(),
            relation,
            confidence,
            reasons: Vec::new(),
            created_at: Utc::now(),
            run_id: None,
        }
    }

    /// Temporal proximity alone must never become confirmed.
    pub fn is_valid_confidence(&self) -> bool {
        if matches!(self.relation, EvidenceRelation::TemporalProximity) {
            !matches!(self.confidence, Confidence::Confirmed)
        } else {
            true
        }
    }
}

/// Inputs for correlating external evidence to a run.
#[derive(Debug, Clone, Default)]
pub struct CorrelationContext {
    pub run_id: String,
    pub trace_id: Option<String>,
    pub host: Option<String>,
    pub pids: Vec<i64>,
    pub workload: Option<String>,
}

/// Correlate one external event to a run using multi-signal join.
///
/// Confidence policy:
/// - matching cooperative `trace_id` alone → at most `strongly_correlated`
///   (forged IDs are possible)
/// - matching trace_id + process/workload → may reach `confirmed` only with
///   additional non-cooperative signal
/// - temporal proximity alone → `weakly_correlated` max
pub fn correlate_external_event(
    ev: &ExternalEvidenceEvent,
    ctx: &CorrelationContext,
) -> Option<EvidenceEdge> {
    let mut reasons = Vec::new();
    let mut score = 0i32;

    let mut trace_match = false;
    if let (Some(ref want), Some(ref got)) = (&ctx.trace_id, &ev.identity.trace_id) {
        if want == got {
            trace_match = true;
            score += 2;
            reasons.push("matching_trace_id".into());
        } else {
            reasons.push("conflicting_trace_id".into());
            // conflicting cooperative id — do not auto-link as confirmed
            score -= 1;
        }
    }
    if let Some(ref rid) = ev.identity.run_id {
        if rid == &ctx.run_id {
            score += 3;
            reasons.push("matching_run_id".into());
        }
    }
    if let Some(ref linked) = ev.linked_run_id {
        if linked == &ctx.run_id {
            score += 2;
            reasons.push("import_linked_run_id".into());
        }
    }
    if let (Some(ref want), Some(ref got)) = (&ctx.host, &ev.identity.host) {
        if want == got {
            score += 1;
            reasons.push("matching_host".into());
        }
    }
    if let (Some(ref want), Some(ref got)) = (&ctx.workload, &ev.identity.workload) {
        if want == got {
            score += 2;
            reasons.push("matching_workload".into());
        }
    }
    if let Some(pid) = ev.identity.pid {
        if ctx.pids.contains(&pid) {
            score += 2;
            reasons.push("matching_pid".into());
        }
    }

    // Prefer semantic relation from action; identity match is not temporal-only.
    let relation = match &ev.action {
        EvidenceAction::NetworkConnect
        | EvidenceAction::HttpRequest
        | EvidenceAction::DnsQuery
        | EvidenceAction::ProxyDeny
        | EvidenceAction::ProxyAllow => EvidenceRelation::NetworkConnection,
        EvidenceAction::CredentialAccess => EvidenceRelation::CredentialUse,
        EvidenceAction::ProcessExec => EvidenceRelation::Spawn,
        _ if reasons.iter().any(|r| r == "matching_run_id") || trace_match => {
            EvidenceRelation::SameTraceId
        }
        _ => EvidenceRelation::TemporalProximity,
    };

    if reasons.is_empty() && score <= 0 {
        return None;
    }

    // Cap confidence: never upgrade temporal-only to confirmed.
    // Cooperative trace_id alone never reaches confirmed (closed residual risk).
    // Integrity-unverified sensor data cannot become Confirmed either.
    let integrity_trusted = matches!(
        ev.integrity,
        crate::evidence::EvidenceIntegrity::HashOk
            | crate::evidence::EvidenceIntegrity::SignedVerified
    );
    let confidence = if reasons.iter().any(|r| r == "matching_run_id") && integrity_trusted {
        Confidence::Confirmed
    } else if reasons.iter().any(|r| r == "matching_run_id") {
        // Operator/agent-supplied run_id on unverified sensor feed.
        reasons.push("unverified_integrity_caps_confidence".into());
        Confidence::StronglyCorrelated
    } else if score >= 4
        && reasons
            .iter()
            .any(|r| r == "matching_pid" || r == "matching_workload")
        && trace_match
        && integrity_trusted
    {
        Confidence::Confirmed
    } else if score >= 3 || trace_match {
        Confidence::StronglyCorrelated
    } else if score >= 1 {
        Confidence::WeaklyCorrelated
    } else {
        Confidence::Unknown
    };

    // Enforce temporal proximity cap.
    let confidence = if matches!(relation, EvidenceRelation::TemporalProximity)
        && matches!(
            confidence,
            Confidence::Confirmed | Confidence::StronglyCorrelated
        )
    {
        Confidence::WeaklyCorrelated
    } else {
        confidence
    };

    // Forged/conflict: never confirmed.
    let confidence = if reasons.iter().any(|r| r == "conflicting_trace_id") {
        match confidence {
            Confidence::Confirmed | Confidence::StronglyCorrelated => {
                Confidence::WeaklyCorrelated
            }
            other => other,
        }
    } else {
        confidence
    };

    // Signed-invalid feeds: max unknown/weak if somehow accepted.
    let confidence = if matches!(
        ev.integrity,
        crate::evidence::EvidenceIntegrity::SignedInvalid
    ) {
        reasons.push("signed_invalid_integrity".into());
        Confidence::Unknown
    } else {
        confidence
    };

    if matches!(confidence, Confidence::Unknown) && score < 1 {
        return None;
    }

    let mut edge = EvidenceEdge::new(
        EntityKind::Run,
        ctx.run_id.clone(),
        EntityKind::ExternalEvidence,
        ev.id.clone(),
        relation,
        confidence,
    );
    edge.reasons = reasons;
    edge.run_id = Some(ctx.run_id.clone());
    debug_assert!(edge.is_valid_confidence());
    Some(edge)
}

/// Correlate a batch of external events to a run.
pub fn correlate_external_batch(
    events: &[ExternalEvidenceEvent],
    ctx: &CorrelationContext,
) -> Vec<EvidenceEdge> {
    events
        .iter()
        .filter_map(|e| correlate_external_event(e, ctx))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::ExternalEvidenceEvent;

    #[test]
    fn trace_id_alone_not_confirmed() {
        let mut ev = ExternalEvidenceEvent::new("otel", "otel", "1", EvidenceAction::HttpRequest);
        ev.identity.trace_id = Some("t-1".into());
        let ctx = CorrelationContext {
            run_id: "r1".into(),
            trace_id: Some("t-1".into()),
            ..Default::default()
        };
        let edge = correlate_external_event(&ev, &ctx).unwrap();
        assert!(!matches!(edge.confidence, Confidence::Confirmed));
        assert!(matches!(
            edge.confidence,
            Confidence::StronglyCorrelated | Confidence::WeaklyCorrelated
        ));
    }

    #[test]
    fn run_id_match_can_confirm_when_integrity_ok() {
        use crate::evidence::EvidenceIntegrity;
        let mut ev = ExternalEvidenceEvent::new("proxy", "proxy", "2", EvidenceAction::ProxyDeny);
        ev.identity.run_id = Some("r1".into());
        ev.integrity = EvidenceIntegrity::HashOk;
        let ctx = CorrelationContext {
            run_id: "r1".into(),
            ..Default::default()
        };
        let edge = correlate_external_event(&ev, &ctx).unwrap();
        assert!(matches!(edge.confidence, Confidence::Confirmed));
    }

    #[test]
    fn run_id_unverified_caps_to_strongly_correlated() {
        // Default integrity is Unverified — must not reach Confirmed alone.
        let mut ev = ExternalEvidenceEvent::new("proxy", "proxy", "2", EvidenceAction::ProxyDeny);
        ev.identity.run_id = Some("r1".into());
        let ctx = CorrelationContext {
            run_id: "r1".into(),
            ..Default::default()
        };
        let edge = correlate_external_event(&ev, &ctx).unwrap();
        assert!(matches!(edge.confidence, Confidence::StronglyCorrelated));
        assert!(edge
            .reasons
            .iter()
            .any(|r| r == "unverified_integrity_caps_confidence"));
    }

    #[test]
    fn multi_signal_trace_pid_workload_confirmed_only_with_integrity() {
        use crate::evidence::EvidenceIntegrity;
        let mut ev = ExternalEvidenceEvent::new("otel", "otel", "3", EvidenceAction::HttpRequest);
        ev.identity.trace_id = Some("t-1".into());
        ev.identity.pid = Some(42);
        ev.identity.workload = Some("agent".into());
        let ctx = CorrelationContext {
            run_id: "r1".into(),
            trace_id: Some("t-1".into()),
            pids: vec![42],
            workload: Some("agent".into()),
            ..Default::default()
        };
        // Unverified: capped below Confirmed.
        let edge = correlate_external_event(&ev, &ctx).unwrap();
        assert!(!matches!(edge.confidence, Confidence::Confirmed));

        ev.integrity = EvidenceIntegrity::HashOk;
        let edge = correlate_external_event(&ev, &ctx).unwrap();
        assert!(matches!(edge.confidence, Confidence::Confirmed));
    }

    #[test]
    fn signed_invalid_never_correlates_confidently() {
        use crate::evidence::EvidenceIntegrity;
        let mut ev = ExternalEvidenceEvent::new("proxy", "proxy", "4", EvidenceAction::ProxyDeny);
        ev.identity.run_id = Some("r1".into());
        ev.integrity = EvidenceIntegrity::SignedInvalid;
        let ctx = CorrelationContext {
            run_id: "r1".into(),
            ..Default::default()
        };
        let edge = correlate_external_event(&ev, &ctx).unwrap();
        assert!(matches!(edge.confidence, Confidence::Unknown));
        assert!(edge.reasons.iter().any(|r| r == "signed_invalid_integrity"));
    }

    #[test]
    fn temporal_proximity_never_confirmed() {
        let mut edge = EvidenceEdge::new(
            EntityKind::Run,
            "r",
            EntityKind::ExternalEvidence,
            "e",
            EvidenceRelation::TemporalProximity,
            Confidence::Confirmed,
        );
        assert!(!edge.is_valid_confidence());
        edge.confidence = Confidence::WeaklyCorrelated;
        assert!(edge.is_valid_confidence());
    }
}
