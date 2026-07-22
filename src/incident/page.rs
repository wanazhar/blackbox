//! Cursor pagination and aggregates for incidents (1.7 scale).
#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::graph::IncidentGraph;
use super::model::Incident;

/// Opaque cursor for incident listing (newest first).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncidentPageCursor {
    pub created_at: DateTime<Utc>,
    pub id: String,
}

/// One page of incidents.
#[derive(Debug, Clone, Serialize)]
pub struct IncidentPage {
    pub incidents: Vec<Incident>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// Encode cursor as URL-safe base64 JSON.
pub fn encode_incident_cursor(c: &IncidentPageCursor) -> String {
    // DateTime and String serialization are infallible for this concrete type;
    // do not silently emit an empty, unusable cursor if that contract changes.
    let json = serde_json::to_vec(c).expect("incident cursor serialization must succeed");
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, json)
}

/// Decode incident cursor.
pub fn decode_incident_cursor(s: &str) -> Option<IncidentPageCursor> {
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Incremental aggregates for an incident (recomputable).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IncidentAggregates {
    pub schema: String,
    pub incident_id: String,
    pub run_count: usize,
    pub attachment_count: usize,
    pub finding_count: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub external_evidence_count: usize,
    pub technique_count: usize,
    pub reuse_count: usize,
    /// False means counts are known lower bounds from a legacy graph payload.
    #[serde(default)]
    pub counts_exact: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earliest_signal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continued_after_signal: Option<bool>,
    pub updated_at: DateTime<Utc>,
}

impl IncidentAggregates {
    pub fn new(incident_id: impl Into<String>) -> Self {
        Self {
            schema: "blackbox.incident.aggregates/v1".into(),
            incident_id: incident_id.into(),
            updated_at: Utc::now(),
            ..Default::default()
        }
    }
}

/// Build aggregates from an incident + optional graph-ish inputs.
pub fn compute_incident_aggregates(
    incident: &Incident,
    finding_count: usize,
    critical_findings: usize,
    high_findings: usize,
    external_evidence_count: usize,
    technique_count: usize,
    reuse_count: usize,
) -> IncidentAggregates {
    let mut a = IncidentAggregates::new(&incident.id);
    a.run_count = incident.run_ids().len();
    a.attachment_count = incident.attachments.len();
    a.finding_count = finding_count;
    a.critical_findings = critical_findings;
    a.high_findings = high_findings;
    a.external_evidence_count = external_evidence_count;
    a.technique_count = technique_count;
    a.reuse_count = reuse_count;
    a.counts_exact = true;
    a.earliest_signal_id = incident.earliest_signal_id.clone();
    a.continued_after_signal = incident.continued_after_signal;
    a.updated_at = Utc::now();
    a
}

/// Build aggregates using the graph's pre-truncation totals.
pub fn compute_incident_aggregates_from_graph(
    incident: &Incident,
    graph: &IncidentGraph,
    critical_findings: usize,
    high_findings: usize,
) -> IncidentAggregates {
    let mut aggregates = compute_incident_aggregates(
        incident,
        graph.finding_count,
        critical_findings,
        high_findings,
        graph.evidence_count,
        graph.technique_total(),
        graph.reuse_total(),
    );
    aggregates.counts_exact = graph.counts_exact;
    aggregates
}

/// Page a pre-sorted (newest first) incident slice with cursor.
pub fn page_incidents(
    all: &[Incident],
    cursor: Option<&IncidentPageCursor>,
    limit: usize,
) -> IncidentPage {
    let limit = limit.clamp(1, 500);
    let start = if let Some(c) = cursor {
        all.iter()
            .position(|i| {
                i.created_at < c.created_at
                    || (i.created_at == c.created_at && i.id.as_str() < c.id.as_str())
            })
            .unwrap_or(all.len())
    } else {
        0
    };
    let end = (start + limit).min(all.len());
    let slice = &all[start..end];
    let has_more = end < all.len();
    let next_cursor = if has_more {
        slice.last().map(|i| {
            encode_incident_cursor(&IncidentPageCursor {
                created_at: i.created_at,
                id: i.id.clone(),
            })
        })
    } else {
        None
    };
    IncidentPage {
        incidents: slice.to_vec(),
        next_cursor,
        has_more,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::{attach_to_incident, Incident, IncidentAttachmentKind};

    #[test]
    fn pages_with_cursor() {
        let mut items = Vec::new();
        for i in 0..25 {
            let mut inc = Incident::new(Some(format!("t{i}")));
            // Force ordering by adjusting created_at slightly
            inc.created_at = Utc::now() - chrono::Duration::seconds(i as i64);
            inc.id = format!("inc-{i:02}");
            items.push(inc);
        }
        // newest first
        items.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));

        let p1 = page_incidents(&items, None, 10);
        assert_eq!(p1.incidents.len(), 10);
        assert!(p1.has_more);
        let cur = decode_incident_cursor(p1.next_cursor.as_deref().unwrap()).unwrap();
        let p2 = page_incidents(&items, Some(&cur), 10);
        assert_eq!(p2.incidents.len(), 10);
        assert!(!p1
            .incidents
            .iter()
            .any(|i| p2.incidents.iter().any(|j| j.id == i.id)));
    }

    #[test]
    fn aggregates_counts_runs() {
        let mut i = Incident::new(Some("x".into()));
        attach_to_incident(&mut i, IncidentAttachmentKind::Run, "r1", None::<String>);
        attach_to_incident(&mut i, IncidentAttachmentKind::Run, "r2", None::<String>);
        let a = compute_incident_aggregates(&i, 3, 1, 2, 5, 2, 1);
        assert_eq!(a.run_count, 2);
        assert_eq!(a.finding_count, 3);
        assert_eq!(a.critical_findings, 1);
        assert!(a.counts_exact);
    }
}
