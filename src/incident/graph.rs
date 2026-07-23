//! Cross-run incident graph: discovery, reuse, earliest signal.

#![allow(missing_docs)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::boundary::{BoundaryFinding, EntityKind, EvidenceEdge, EvidenceRelation};
use crate::core::event::Confidence;
use crate::evidence::ExternalEvidenceEvent;

use super::model::Incident;

/// Node in an incident reconstruction graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentNode {
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<DateTime<Utc>>,
}

/// Technique / destination / credential reuse across runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TechniqueReuse {
    pub technique: String,
    /// First run/event that exhibited it.
    pub first_run_id: String,
    pub first_ref: String,
    /// Later runs that reused it.
    pub reused_by_runs: Vec<String>,
}

/// Earliest actionable signal within an incident.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentSignal {
    pub ref_id: String,
    pub kind: String,
    pub summary: String,
    pub at: DateTime<Utc>,
    pub run_id: Option<String>,
}

/// The incident-level flow represented by a correlation edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentFlowKind {
    Delegation,
    CredentialUse,
    ArtifactDerivation,
}

impl IncidentFlowKind {
    /// Stable string form used by JSON and operator views.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delegation => "delegation",
            Self::CredentialUse => "credential_use",
            Self::ArtifactDerivation => "artifact_derivation",
        }
    }

    fn from_relation(relation: &EvidenceRelation) -> Option<Self> {
        match relation {
            EvidenceRelation::Delegation => Some(Self::Delegation),
            EvidenceRelation::CredentialUse => Some(Self::CredentialUse),
            EvidenceRelation::ArtifactDerivation => Some(Self::ArtifactDerivation),
            _ => None,
        }
    }
}

/// Explicit incident flow derived from an evidence edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentFlow {
    pub kind: IncidentFlowKind,
    pub edge_id: String,
    pub from_kind: EntityKind,
    pub from_id: String,
    pub to_kind: EntityKind,
    pub to_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    pub at: DateTime<Utc>,
}

/// Exact incident flow totals, independent of serialized detail limits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentFlowCounts {
    pub total: usize,
    pub delegation: usize,
    pub credential_use: usize,
    pub artifact_derivation: usize,
}

impl IncidentFlowCounts {
    fn record(&mut self, kind: IncidentFlowKind) {
        self.total += 1;
        match kind {
            IncidentFlowKind::Delegation => self.delegation += 1,
            IncidentFlowKind::CredentialUse => self.credential_use += 1,
            IncidentFlowKind::ArtifactDerivation => self.artifact_derivation += 1,
        }
    }
}

impl IncidentFlow {
    fn from_edge(edge: &EvidenceEdge) -> Option<Self> {
        Some(Self {
            kind: IncidentFlowKind::from_relation(&edge.relation)?,
            edge_id: edge.id.clone(),
            from_kind: edge.from_kind.clone(),
            from_id: edge.from_id.clone(),
            to_kind: edge.to_kind.clone(),
            to_id: edge.to_id.clone(),
            run_id: edge.run_id.clone(),
            confidence: edge.confidence,
            reasons: edge.reasons.clone(),
            at: edge.created_at,
        })
    }
}

/// Maximum serialized detail retained in a reconstructed graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentGraphLimits {
    pub nodes: usize,
    pub edges: usize,
    pub flows: usize,
    pub techniques: usize,
}

impl Default for IncidentGraphLimits {
    fn default() -> Self {
        Self {
            nodes: 2_000,
            edges: 2_000,
            flows: 2_000,
            techniques: 1_000,
        }
    }
}

/// Total versus serialized detail for one graph collection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentDetailCount {
    pub total: usize,
    pub included: usize,
    pub truncated: usize,
}

impl IncidentDetailCount {
    fn from_total(total: usize, included: usize) -> Self {
        Self {
            total,
            included,
            truncated: total.saturating_sub(included),
        }
    }
}

/// Honest totals for detail omitted by graph limits.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentGraphTruncation {
    pub nodes: IncidentDetailCount,
    pub edges: IncidentDetailCount,
    pub flows: IncidentDetailCount,
    pub techniques: IncidentDetailCount,
}

impl IncidentGraphTruncation {
    /// Whether any graph detail was omitted.
    pub fn is_truncated(&self) -> bool {
        self.nodes.truncated > 0
            || self.edges.truncated > 0
            || self.flows.truncated > 0
            || self.techniques.truncated > 0
    }
}

/// Full graph summary for an incident.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentGraph {
    pub schema: String,
    pub incident_id: String,
    pub nodes: Vec<IncidentNode>,
    pub edges: Vec<EvidenceEdge>,
    /// Explicit delegation, credential-use, and artifact-derivation flows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flows: Vec<IncidentFlow>,
    pub techniques: Vec<TechniqueReuse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earliest_signal: Option<IncidentSignal>,
    /// True only when a typed continuation relation holds (1.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continued_after_signal: Option<bool>,
    /// Cited continuation conclusion (1.8). Unrelated later activity is explicit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<super::continuation::ContinuationConclusion>,
    pub run_count: usize,
    pub evidence_count: usize,
    pub finding_count: usize,
    /// Exact source totals; these do not shrink when graph detail is truncated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_counts: Option<IncidentFlowCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub technique_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse_count: Option<usize>,
    /// False for legacy v1 payloads whose omitted detail cannot be quantified.
    #[serde(default)]
    pub counts_exact: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_limits: Option<IncidentGraphLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncation: Option<IncidentGraphTruncation>,
}

impl IncidentGraph {
    /// Exact total for v2 graphs, or the known included lower bound for legacy v1.
    pub fn edge_total(&self) -> usize {
        self.edge_count.unwrap_or(self.edges.len())
    }

    /// Exact total for v2 graphs, or the known included lower bound for legacy v1.
    pub fn flow_total(&self) -> usize {
        self.flow_count.unwrap_or_else(|| {
            if self.flows.is_empty() {
                self.edges
                    .iter()
                    .filter(|edge| IncidentFlowKind::from_relation(&edge.relation).is_some())
                    .count()
            } else {
                self.flows.len()
            }
        })
    }

    /// Exact total for v2 graphs, or the known included lower bound for legacy v1.
    pub fn technique_total(&self) -> usize {
        self.technique_count.unwrap_or(self.techniques.len())
    }

    /// Exact total for v2 graphs, or the known included lower bound for legacy v1.
    pub fn reuse_total(&self) -> usize {
        self.reuse_count.unwrap_or_else(|| {
            self.techniques
                .iter()
                .filter(|technique| !technique.reused_by_runs.is_empty())
                .count()
        })
    }

    /// Some(true/false) for v2 graphs; None when legacy truncation is unknowable.
    pub fn is_detail_truncated(&self) -> Option<bool> {
        self.truncation
            .as_ref()
            .map(IncidentGraphTruncation::is_truncated)
    }
}

/// Inputs assembled by the CLI / store layer.
#[derive(Debug, Clone, Default)]
pub struct GraphInputs {
    pub findings_by_run: Vec<(String, Vec<BoundaryFinding>)>,
    pub external: Vec<ExternalEvidenceEvent>,
    pub edges: Vec<EvidenceEdge>,
    /// (run_id, ended_at) for continued-activity check.
    pub run_end_times: Vec<(String, Option<DateTime<Utc>>)>,
}

fn record_technique(
    techniques: &mut std::collections::BTreeMap<String, TechniqueReuse>,
    first_seen: &mut std::collections::BTreeMap<String, DateTime<Utc>>,
    technique: String,
    run_id: String,
    reference: String,
    at: DateTime<Utc>,
) {
    match first_seen.get(&technique).copied() {
        None => {
            first_seen.insert(technique.clone(), at);
            techniques.insert(
                technique.clone(),
                TechniqueReuse {
                    technique,
                    first_run_id: run_id,
                    first_ref: reference,
                    reused_by_runs: Vec::new(),
                },
            );
        }
        Some(previous)
            if at < previous
                || (at == previous
                    && techniques
                        .get(&technique)
                        .is_some_and(|entry| reference < entry.first_ref)) =>
        {
            first_seen.insert(technique.clone(), at);
            if let Some(entry) = techniques.get_mut(&technique) {
                let old_first = std::mem::replace(&mut entry.first_run_id, run_id);
                entry.first_ref = reference;
                if old_first != entry.first_run_id && !entry.reused_by_runs.contains(&old_first) {
                    entry.reused_by_runs.push(old_first);
                }
            }
        }
        Some(_) => {
            if let Some(entry) = techniques.get_mut(&technique) {
                if entry.first_run_id != run_id && !entry.reused_by_runs.contains(&run_id) {
                    entry.reused_by_runs.push(run_id);
                }
            }
        }
    }
}

/// Build incident graph: first discovery, reuse, earliest signal, continued activity.
pub fn build_incident_graph(incident: &Incident, inputs: &GraphInputs) -> IncidentGraph {
    build_incident_graph_with_limits(incident, inputs, IncidentGraphLimits::default())
}

/// Build an incident graph with explicit serialized-detail limits.
pub fn build_incident_graph_with_limits(
    incident: &Incident,
    inputs: &GraphInputs,
    limits: IncidentGraphLimits,
) -> IncidentGraph {
    let mut nodes = Vec::new();
    let mut node_count = 0usize;
    let run_ids: Vec<String> = incident
        .run_ids()
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    for rid in &run_ids {
        node_count += 1;
        if nodes.len() < limits.nodes {
            nodes.push(IncidentNode {
                kind: "run".into(),
                id: rid.clone(),
                run_id: Some(rid.clone()),
                label: Some(format!("run {rid}")),
                at: None,
            });
        }
    }

    let mut techniques: std::collections::BTreeMap<String, TechniqueReuse> =
        std::collections::BTreeMap::new();
    let mut first_seen = std::collections::BTreeMap::new();
    let mut earliest_signal: Option<IncidentSignal> = None;
    let mut finding_count = 0usize;

    for (run_id, findings) in &inputs.findings_by_run {
        for f in findings {
            finding_count += 1;
            node_count += 1;
            if nodes.len() < limits.nodes {
                nodes.push(IncidentNode {
                    kind: f.kind.as_str().into(),
                    id: f.id.clone(),
                    run_id: Some(run_id.clone()),
                    label: Some(f.summary.clone()),
                    at: Some(f.created_at),
                });
            }
            let tech = f.token.clone().unwrap_or_else(|| f.detector.clone());
            record_technique(
                &mut techniques,
                &mut first_seen,
                tech,
                run_id.clone(),
                f.id.clone(),
                f.created_at,
            );

            if matches!(
                f.severity,
                crate::boundary::FindingSeverity::High | crate::boundary::FindingSeverity::Critical
            ) {
                let signal = IncidentSignal {
                    ref_id: f.id.clone(),
                    kind: f.kind.as_str().into(),
                    summary: f.summary.clone(),
                    at: f.created_at,
                    run_id: Some(run_id.clone()),
                };
                let replace = earliest_signal
                    .as_ref()
                    .map(|current| {
                        (signal.at, signal.ref_id.as_str()) < (current.at, current.ref_id.as_str())
                    })
                    .unwrap_or(true);
                if replace {
                    earliest_signal = Some(signal);
                }
            }
        }
    }

    for ev in &inputs.external {
        node_count += 1;
        if nodes.len() < limits.nodes {
            nodes.push(IncidentNode {
                kind: "external_evidence".into(),
                id: ev.id.clone(),
                run_id: ev.linked_run_id.clone(),
                label: Some(format!(
                    "{} {}",
                    ev.action.as_str(),
                    ev.destination.as_deref().unwrap_or("")
                )),
                at: Some(ev.occurred_at.or(ev.observed_at).unwrap_or(ev.ingested_at)),
            });
        }
        if let Some(ref dest) = ev.destination {
            let tech = format!("dest:{dest}");
            let rid = ev.linked_run_id.clone().unwrap_or_else(|| "unknown".into());
            record_technique(
                &mut techniques,
                &mut first_seen,
                tech,
                rid,
                ev.id.clone(),
                ev.occurred_at.or(ev.observed_at).unwrap_or(ev.ingested_at),
            );
        }
    }

    // Credential / network edges as techniques.
    let mut ordered_edges: Vec<_> = inputs.edges.iter().collect();
    ordered_edges.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.id.cmp(&right.id))
    });

    for e in &ordered_edges {
        if matches!(
            e.relation,
            EvidenceRelation::CredentialUse | EvidenceRelation::PolicyViolation
        ) {
            let tech = e.relation.as_str().to_string();
            let rid = e.run_id.clone().unwrap_or_else(|| "unknown".into());
            record_technique(
                &mut techniques,
                &mut first_seen,
                tech,
                rid,
                e.id.clone(),
                e.created_at,
            );
        }
    }

    // 1.8: continuation requires a typed entity relationship. Unrelated later
    // activity alone must not set continued_after_signal=true.
    let continuation = earliest_signal.as_ref().and_then(|sig| {
        super::continuation::evaluate_continuation(super::continuation::ContinuationInputs {
            signal: sig,
            findings_by_run: &inputs.findings_by_run,
            external: &inputs.external,
            edges: &inputs.edges,
        })
    });
    // Some(false) when a signal exists but no typed continuation (or only unrelated later).
    let continued_after_signal = earliest_signal.as_ref().map(|_| {
        continuation
            .as_ref()
            .map(|c| c.relation.is_continuation())
            .unwrap_or(false)
    });

    for technique in techniques.values_mut() {
        technique.reused_by_runs.sort();
        technique.reused_by_runs.dedup();
    }

    let technique_count = techniques.len();
    let reuse_count = techniques
        .values()
        .filter(|technique| !technique.reused_by_runs.is_empty())
        .count();
    let techniques: Vec<_> = techniques.into_values().take(limits.techniques).collect();
    let edge_count = ordered_edges.len();
    let edges: Vec<_> = ordered_edges
        .iter()
        .take(limits.edges)
        .map(|edge| (*edge).clone())
        .collect();
    let mut flow_counts = IncidentFlowCounts::default();
    let mut flows = Vec::with_capacity(limits.flows.min(ordered_edges.len()));
    for edge in ordered_edges {
        if let Some(flow) = IncidentFlow::from_edge(edge) {
            flow_counts.record(flow.kind);
            if flows.len() < limits.flows {
                flows.push(flow);
            }
        }
    }
    let flow_count = flow_counts.total;
    let truncation = IncidentGraphTruncation {
        nodes: IncidentDetailCount::from_total(node_count, nodes.len()),
        edges: IncidentDetailCount::from_total(edge_count, edges.len()),
        flows: IncidentDetailCount::from_total(flow_count, flows.len()),
        techniques: IncidentDetailCount::from_total(technique_count, techniques.len()),
    };

    IncidentGraph {
        schema: "blackbox.incident.graph/v2".into(),
        incident_id: incident.id.clone(),
        nodes,
        edges,
        flows,
        techniques,
        earliest_signal,
        continued_after_signal,
        continuation,
        run_count: run_ids.len(),
        evidence_count: inputs.external.len(),
        finding_count,
        edge_count: Some(edge_count),
        flow_count: Some(flow_count),
        flow_counts: Some(flow_counts),
        technique_count: Some(technique_count),
        reuse_count: Some(reuse_count),
        counts_exact: true,
        detail_limits: Some(limits),
        truncation: Some(truncation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{BoundaryFinding, FindingKind, FindingSeverity};
    use crate::incident::{attach_to_incident, Incident, IncidentAttachmentKind};

    #[test]
    fn earliest_signal_and_reuse() {
        let mut inc = Incident::new(Some("swarm".into()));
        attach_to_incident(&mut inc, IncidentAttachmentKind::Run, "r1", None::<String>);
        attach_to_incident(&mut inc, IncidentAttachmentKind::Run, "r2", None::<String>);

        let t0 = Utc::now();
        let f1 = BoundaryFinding {
            schema: "blackbox.boundary.finding/v1".into(),
            id: "find-1".into(),
            run_id: "r1".into(),
            kind: FindingKind::BoundaryViolation,
            detector: "unexpected_destination".into(),
            severity: FindingSeverity::Critical,
            summary: "egress".into(),
            evidence_event_ids: vec![],
            external_evidence_ids: vec![],
            token: Some("public_network".into()),
            disposition: None,
            recommendation: None,
            created_at: t0,
            confidence_note: "deterministic_detector".into(),
            decision: None,
        };
        let mut f2 = f1.clone();
        f2.id = "find-2".into();
        f2.run_id = "r2".into();
        f2.created_at = t0 + chrono::Duration::seconds(30);

        let graph = build_incident_graph(
            &inc,
            &GraphInputs {
                findings_by_run: vec![("r2".into(), vec![f2]), ("r1".into(), vec![f1])],
                ..Default::default()
            },
        );
        assert_eq!(graph.run_count, 2);
        assert!(graph
            .techniques
            .iter()
            .any(|t| t.technique == "public_network" && t.reused_by_runs.contains(&"r2".into())));
        assert_eq!(
            graph.earliest_signal.as_ref().map(|s| s.ref_id.as_str()),
            Some("find-1")
        );
        assert_eq!(graph.continued_after_signal, Some(true));
    }

    #[test]
    fn run_end_alone_is_not_continued_activity() {
        let mut incident = Incident::new(Some("single".into()));
        attach_to_incident(
            &mut incident,
            IncidentAttachmentKind::Run,
            "r1",
            None::<String>,
        );
        let at = Utc::now();
        let finding = BoundaryFinding {
            schema: "blackbox.boundary.finding/v1".into(),
            id: "find-1".into(),
            run_id: "r1".into(),
            kind: FindingKind::BoundaryViolation,
            detector: "credential_access".into(),
            severity: FindingSeverity::Critical,
            summary: "credential access".into(),
            evidence_event_ids: vec![],
            external_evidence_ids: vec![],
            token: None,
            disposition: None,
            recommendation: None,
            created_at: at,
            confidence_note: "deterministic_detector".into(),
            decision: None,
        };
        let graph = build_incident_graph(
            &incident,
            &GraphInputs {
                findings_by_run: vec![("r1".into(), vec![finding])],
                run_end_times: vec![("r1".into(), Some(at + chrono::Duration::seconds(10)))],
                ..Default::default()
            },
        );
        assert_eq!(graph.continued_after_signal, Some(false));
    }
}
