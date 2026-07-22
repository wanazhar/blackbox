//! Cross-run incident graph: discovery, reuse, earliest signal.

#![allow(missing_docs)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::boundary::{BoundaryFinding, EvidenceEdge, EvidenceRelation};
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

/// Full graph summary for an incident.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentGraph {
    pub schema: String,
    pub incident_id: String,
    pub nodes: Vec<IncidentNode>,
    pub edges: Vec<EvidenceEdge>,
    pub techniques: Vec<TechniqueReuse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earliest_signal: Option<IncidentSignal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continued_after_signal: Option<bool>,
    pub run_count: usize,
    pub evidence_count: usize,
    pub finding_count: usize,
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
        Some(previous) if at < previous => {
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
    let mut nodes = Vec::new();
    let run_ids: Vec<String> = incident
        .run_ids()
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    for rid in &run_ids {
        nodes.push(IncidentNode {
            kind: "run".into(),
            id: rid.clone(),
            run_id: Some(rid.clone()),
            label: Some(format!("run {rid}")),
            at: None,
        });
    }

    let mut techniques: std::collections::BTreeMap<String, TechniqueReuse> =
        std::collections::BTreeMap::new();
    let mut first_seen = std::collections::BTreeMap::new();
    let mut signals: Vec<IncidentSignal> = Vec::new();
    let mut finding_count = 0usize;

    for (run_id, findings) in &inputs.findings_by_run {
        for f in findings {
            finding_count += 1;
            nodes.push(IncidentNode {
                kind: f.kind.as_str().into(),
                id: f.id.clone(),
                run_id: Some(run_id.clone()),
                label: Some(f.summary.clone()),
                at: Some(f.created_at),
            });
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
                signals.push(IncidentSignal {
                    ref_id: f.id.clone(),
                    kind: f.kind.as_str().into(),
                    summary: f.summary.clone(),
                    at: f.created_at,
                    run_id: Some(run_id.clone()),
                });
            }
        }
    }

    for ev in &inputs.external {
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
    for e in &inputs.edges {
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

    signals.sort_by_key(|s| s.at);
    let earliest_signal = signals.into_iter().next();
    let continued_after_signal = earliest_signal.as_ref().map(|sig| {
        // A run ending after a signal is not itself evidence of continued
        // execution. Require a later finding or external observation.
        let after_finding = inputs.findings_by_run.iter().any(|(_, fs)| {
            fs.iter()
                .any(|f| f.created_at > sig.at && f.id != sig.ref_id)
        });
        let after_ext = inputs
            .external
            .iter()
            .any(|e| e.occurred_at.or(e.observed_at).unwrap_or(e.ingested_at) > sig.at);
        after_finding || after_ext
    });

    for technique in techniques.values_mut() {
        technique.reused_by_runs.sort();
        technique.reused_by_runs.dedup();
    }

    IncidentGraph {
        schema: "blackbox.incident.graph/v1".into(),
        incident_id: incident.id.clone(),
        nodes,
        edges: inputs.edges.clone(),
        techniques: techniques.into_values().collect(),
        earliest_signal,
        continued_after_signal,
        run_count: run_ids.len(),
        evidence_count: inputs.external.len(),
        finding_count,
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
