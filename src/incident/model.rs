//! Incident object model.

#![allow(missing_docs)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Schema for incident objects.
pub const INCIDENT_SCHEMA: &str = "blackbox.incident/v1";

/// What an attachment references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentAttachmentKind {
    Run,
    ExternalEvidence,
    Finding,
    ProvenanceRecord,
    ContainmentReceipt,
    Edge,
    Note,
}

impl IncidentAttachmentKind {
    /// Stable string form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::ExternalEvidence => "external_evidence",
            Self::Finding => "finding",
            Self::ProvenanceRecord => "provenance_record",
            Self::ContainmentReceipt => "containment_receipt",
            Self::Edge => "edge",
            Self::Note => "note",
        }
    }
}

/// Explicit attachment with provenance of why it was linked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentAttachment {
    pub kind: IncidentAttachmentKind,
    pub ref_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub attached_at: DateTime<Utc>,
}

/// Multi-run incident spanning runs and external evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub schema: String,
    /// Semantic output layer (1.8 layered-output contract).
    #[serde(default = "default_incident_evidence_layer")]
    pub evidence_layer: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<IncidentAttachment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Earliest actionable signal id when computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earliest_signal_id: Option<String>,
    /// Whether execution continued after earliest signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continued_after_signal: Option<bool>,
}

impl Incident {
    /// Create an empty incident.
    pub fn new(title: impl Into<Option<String>>) -> Self {
        Self {
            schema: INCIDENT_SCHEMA.into(),
            evidence_layer: default_incident_evidence_layer(),
            id: format!("inc-{}", Uuid::new_v4()),
            title: title.into(),
            created_at: Utc::now(),
            updated_at: None,
            attachments: Vec::new(),
            tags: Vec::new(),
            summary: None,
            earliest_signal_id: None,
            continued_after_signal: None,
        }
    }

    /// Run ids attached to this incident.
    pub fn run_ids(&self) -> Vec<&str> {
        self.attachments
            .iter()
            .filter(|a| matches!(a.kind, IncidentAttachmentKind::Run))
            .map(|a| a.ref_id.as_str())
            .collect()
    }
}

fn default_incident_evidence_layer() -> String {
    "incident_interpretation".into()
}

/// Attach a reference to an incident (mutates).
pub fn attach_to_incident(
    incident: &mut Incident,
    kind: IncidentAttachmentKind,
    ref_id: impl Into<String>,
    reason: impl Into<Option<String>>,
) {
    incident.attachments.push(IncidentAttachment {
        kind,
        ref_id: ref_id.into(),
        reason: reason.into(),
        attached_at: Utc::now(),
    });
    incident.updated_at = Some(Utc::now());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_run() {
        let mut i = Incident::new(Some("test".into()));
        attach_to_incident(
            &mut i,
            IncidentAttachmentKind::Run,
            "r1",
            Some("seed".into()),
        );
        assert_eq!(i.run_ids(), vec!["r1"]);
    }
}
