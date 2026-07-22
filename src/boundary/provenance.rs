//! Artifact and answer provenance records + gates (1.7 Phase G).

#![allow(missing_docs)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::evidence::{EvidenceAction, ExternalEvidenceEvent};

/// Schema for provenance records.
pub const PROVENANCE_SCHEMA: &str = "blackbox.provenance/v1";
/// Schema for provenance evaluation reports.
pub const PROVENANCE_EVAL_SCHEMA: &str = "blackbox.provenance.eval/v1";

/// What the provenance record describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    BenchmarkInput,
    BenchmarkOutput,
    RetrievedMaterial,
    GeneratedArtifact,
    VerificationData,
    ModelWeights,
    Dataset,
    Other(String),
}

impl ProvenanceKind {
    /// Stable string form.
    pub fn as_str(&self) -> &str {
        match self {
            Self::BenchmarkInput => "benchmark_input",
            Self::BenchmarkOutput => "benchmark_output",
            Self::RetrievedMaterial => "retrieved_material",
            Self::GeneratedArtifact => "generated_artifact",
            Self::VerificationData => "verification_data",
            Self::ModelWeights => "model_weights",
            Self::Dataset => "dataset",
            Self::Other(s) => s.as_str(),
        }
    }
}

/// Provenance validity (independent of task correctness).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceStatus {
    /// Declared path; consistent with observation.
    Valid,
    /// Undeclared external source observed.
    InvalidUndeclaredSource,
    /// Network used outside allowed provenance path.
    InvalidNetwork,
    /// Credential used outside declared path.
    InvalidCredential,
    /// Lineage broken / incomplete.
    InvalidLineage,
    /// Required observation missing.
    InsufficientEvidence,
    /// Not evaluated.
    NotEvaluated,
}

impl ProvenanceStatus {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::InvalidUndeclaredSource => "invalid_undeclared_source",
            Self::InvalidNetwork => "invalid_network",
            Self::InvalidCredential => "invalid_credential",
            Self::InvalidLineage => "invalid_lineage",
            Self::InsufficientEvidence => "insufficient_evidence",
            Self::NotEvaluated => "not_evaluated",
        }
    }

    /// Fail a provenance gate.
    pub fn is_gate_failure(self) -> bool {
        !matches!(self, Self::Valid | Self::NotEvaluated)
    }
}

/// One provenance record for an artifact or answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub schema: String,
    pub id: String,
    pub run_id: String,
    pub kind: ProvenanceKind,
    /// Declared sources (URLs, dataset ids, local paths relative).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_sources: Vec<String>,
    /// Observed sources (from capture / external evidence).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_sources: Vec<String>,
    /// Content hash of the artifact when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    pub status: ProvenanceStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl ProvenanceRecord {
    /// Create a new record in not-evaluated state.
    pub fn new(run_id: impl Into<String>, kind: ProvenanceKind) -> Self {
        Self {
            schema: PROVENANCE_SCHEMA.into(),
            id: format!("prov-{}", Uuid::new_v4()),
            run_id: run_id.into(),
            kind,
            declared_sources: Vec::new(),
            observed_sources: Vec::new(),
            content_hash: None,
            status: ProvenanceStatus::NotEvaluated,
            reasons: Vec::new(),
            created_at: Utc::now(),
            summary: None,
        }
    }
}

/// Combined task vs provenance outcome (they are independent).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceGateReport {
    pub schema: String,
    pub run_id: String,
    /// Task correctness (from verification / exit) — optional input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_passed: Option<bool>,
    pub provenance_status: ProvenanceStatus,
    /// True when provenance fails the gate (independent of task_passed).
    pub provenance_gate_failed: bool,
    /// True only when both task and provenance pass.
    pub overall_passed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub record_ids: Vec<String>,
}

/// Evaluate provenance for a run given records and optional external evidence.
///
/// A correct benchmark answer (`task_passed = true`) can still fail the
/// provenance gate when undeclared sources or prohibited network paths appear.
pub fn evaluate_provenance(
    run_id: &str,
    records: &[ProvenanceRecord],
    external: &[ExternalEvidenceEvent],
    allowed_sources: &[String],
    task_passed: Option<bool>,
    require_observation: bool,
) -> ProvenanceGateReport {
    let mut reasons = Vec::new();
    let mut status = ProvenanceStatus::Valid;
    let mut record_ids: Vec<String> = records.iter().map(|r| r.id.clone()).collect();

    let observation_missing = require_observation
        && records
            .iter()
            .all(|record| record.observed_sources.is_empty() && record.content_hash.is_none());
    if observation_missing {
        status = ProvenanceStatus::InsufficientEvidence;
        reasons.push("no observed provenance evidence and observation required".into());
    }

    for r in records {
        match r.status {
            ProvenanceStatus::InvalidUndeclaredSource => {
                status = ProvenanceStatus::InvalidUndeclaredSource;
                reasons.push(format!("record {} undeclared source", r.id));
            }
            ProvenanceStatus::InvalidNetwork => {
                status = ProvenanceStatus::InvalidNetwork;
                reasons.push(format!("record {} invalid network", r.id));
            }
            ProvenanceStatus::InvalidCredential => {
                status = ProvenanceStatus::InvalidCredential;
                reasons.push(format!("record {} invalid credential", r.id));
            }
            ProvenanceStatus::InvalidLineage => {
                status = ProvenanceStatus::InvalidLineage;
                reasons.push(format!("record {} invalid lineage", r.id));
            }
            ProvenanceStatus::InsufficientEvidence => {
                if !matches!(
                    status,
                    ProvenanceStatus::InvalidUndeclaredSource
                        | ProvenanceStatus::InvalidNetwork
                        | ProvenanceStatus::InvalidCredential
                        | ProvenanceStatus::InvalidLineage
                ) {
                    status = ProvenanceStatus::InsufficientEvidence;
                }
                reasons.push(format!("record {} insufficient evidence", r.id));
            }
            ProvenanceStatus::Valid | ProvenanceStatus::NotEvaluated => {
                // Check declared vs observed.
                for obs in &r.observed_sources {
                    let declared = r.declared_sources.iter().any(|d| d == obs)
                        || allowed_sources.iter().any(|a| obs.contains(a));
                    if !declared {
                        status = ProvenanceStatus::InvalidUndeclaredSource;
                        reasons.push(format!(
                            "undeclared observed source {obs:?} on record {}",
                            r.id
                        ));
                    }
                }
            }
        }
    }

    // External evidence: network retrieval without declared path.
    for ev in external {
        if matches!(
            ev.action,
            EvidenceAction::HttpRequest | EvidenceAction::NetworkConnect | EvidenceAction::DnsQuery
        ) {
            if let Some(ref dest) = ev.destination {
                let allowed = allowed_sources.iter().any(|a| dest.contains(a))
                    || records
                        .iter()
                        .any(|r| r.declared_sources.iter().any(|d| dest.contains(d)));
                if !allowed {
                    status = ProvenanceStatus::InvalidNetwork;
                    reasons.push(format!(
                        "external network {} not in declared provenance",
                        dest
                    ));
                    record_ids.push(ev.id.clone());
                }
            }
        }
        if matches!(ev.action, EvidenceAction::CredentialAccess) {
            status = ProvenanceStatus::InvalidCredential;
            reasons.push("credential access during answer acquisition".into());
            record_ids.push(ev.id.clone());
        }
    }

    let provenance_gate_failed = status.is_gate_failure();
    let overall_passed = match task_passed {
        Some(true) => !provenance_gate_failed,
        Some(false) => false,
        None => !provenance_gate_failed,
    };

    ProvenanceGateReport {
        schema: PROVENANCE_EVAL_SCHEMA.into(),
        run_id: run_id.into(),
        task_passed,
        provenance_status: status,
        provenance_gate_failed,
        overall_passed,
        reasons,
        record_ids,
    }
}

/// Auto-build a benchmark-output record from observed external destinations.
pub fn record_from_observations(
    run_id: &str,
    declared: &[String],
    observed: &[String],
) -> ProvenanceRecord {
    let mut r = ProvenanceRecord::new(run_id, ProvenanceKind::BenchmarkOutput);
    r.declared_sources = declared.to_vec();
    r.observed_sources = observed.to_vec();
    let undeclared: Vec<_> = observed
        .iter()
        .filter(|o| {
            !declared
                .iter()
                .any(|d| o.contains(d) || d.contains(o.as_str()))
        })
        .cloned()
        .collect();
    if undeclared.is_empty() {
        r.status = ProvenanceStatus::Valid;
        r.summary = Some("all observed sources declared".into());
    } else {
        r.status = ProvenanceStatus::InvalidUndeclaredSource;
        r.reasons = undeclared
            .into_iter()
            .map(|u| format!("undeclared:{u}"))
            .collect();
        r.summary = Some("answer path includes undeclared sources".into());
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::ExternalEvidenceEvent;

    #[test]
    fn correct_answer_fails_on_undeclared_network() {
        let mut r = ProvenanceRecord::new("r1", ProvenanceKind::BenchmarkOutput);
        r.declared_sources.push("local-dataset".into());
        r.status = ProvenanceStatus::Valid;

        let mut ext =
            ExternalEvidenceEvent::new("proxy", "proxy", "1", EvidenceAction::HttpRequest);
        ext.destination = Some("https://answers.leaked.example/q1".into());

        let report = evaluate_provenance(
            "r1",
            &[r],
            &[ext],
            &["local-dataset".into()],
            Some(true),
            false,
        );
        assert!(report.task_passed.unwrap());
        assert!(report.provenance_gate_failed);
        assert!(!report.overall_passed);
        assert_eq!(report.provenance_status, ProvenanceStatus::InvalidNetwork);
    }

    #[test]
    fn declared_path_passes() {
        let r = record_from_observations(
            "r1",
            &["dataset://case-1".into()],
            &["dataset://case-1".into()],
        );
        assert_eq!(r.status, ProvenanceStatus::Valid);
        let report = evaluate_provenance("r1", &[r], &[], &[], Some(true), true);
        assert!(report.overall_passed);
    }
}
