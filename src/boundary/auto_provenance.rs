//! Auto provenance records from experiment metadata + observed telemetry (1.7).
#![allow(missing_docs)]

use crate::boundary::{
    record_from_observations, ProvenanceKind, ProvenanceRecord, ProvenanceStatus,
};
use crate::evidence::{EvidenceAction, ExternalEvidenceEvent};
use crate::experiment::RunExperimentMeta;

/// Build declared sources from experiment metadata.
pub fn declared_sources_from_experiment(meta: &RunExperimentMeta) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(ref ds) = meta.dataset_case {
        if !ds.is_empty() {
            // Canonical dataset URI form for eval cases.
            if ds.contains("://") {
                out.push(ds.clone());
            } else {
                out.push(format!("dataset://{ds}"));
                out.push(ds.clone());
            }
        }
    }
    if let Some(ref task) = meta.task_id {
        if !task.is_empty() {
            out.push(format!("task://{task}"));
        }
    }
    if let Some(ref seed) = meta.seed {
        if !seed.is_empty() {
            out.push(format!("seed://{seed}"));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Collect observed external sources (destinations / objects) from evidence.
pub fn observed_sources_from_evidence(external: &[ExternalEvidenceEvent]) -> Vec<String> {
    let mut out = Vec::new();
    for e in external {
        if let Some(ref d) = e.destination {
            if !d.is_empty() {
                out.push(d.clone());
            }
        }
        match &e.action {
            EvidenceAction::HttpRequest
            | EvidenceAction::NetworkConnect
            | EvidenceAction::DnsQuery
            | EvidenceAction::ProxyAllow
            | EvidenceAction::ProxyDeny => {
                if let Some(ref o) = e.object {
                    if !o.is_empty() {
                        out.push(o.clone());
                    }
                }
            }
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Auto-build a benchmark-output provenance record when experiment metadata
/// provides declared dataset/task sources.
///
/// Returns `None` when there is nothing to declare (no experiment linkage).
pub fn auto_provenance_record(
    run_id: &str,
    meta: Option<&RunExperimentMeta>,
    external: &[ExternalEvidenceEvent],
) -> Option<ProvenanceRecord> {
    let meta = meta?;
    let declared = declared_sources_from_experiment(meta);
    if declared.is_empty() && meta.dataset_case.is_none() {
        return None;
    }
    let observed = observed_sources_from_evidence(external);
    let observed_n = observed.len();
    let mut rec = if declared.is_empty() {
        let mut r = ProvenanceRecord::new(run_id, ProvenanceKind::BenchmarkOutput);
        r.observed_sources = observed;
        if r.observed_sources.is_empty() {
            r.status = ProvenanceStatus::InsufficientEvidence;
            r.reasons
                .push("experiment linked but no declared dataset_case and no observed sources".into());
        } else {
            r.status = ProvenanceStatus::InvalidUndeclaredSource;
            r.reasons
                .push("observed sources without declared dataset_case".into());
        }
        r
    } else {
        record_from_observations(run_id, &declared, &observed)
    };
    rec.summary = Some(format!(
        "auto from experiment meta (dataset_case={:?}, observed={})",
        meta.dataset_case, observed_n
    ));
    Some(rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experiment::RunExperimentMeta;

    #[test]
    fn declares_dataset_case() {
        let meta = RunExperimentMeta {
            dataset_case: Some("case-42".into()),
            task_id: Some("t1".into()),
            ..Default::default()
        };
        let d = declared_sources_from_experiment(&meta);
        assert!(d.iter().any(|s| s.contains("case-42")));
        assert!(d.iter().any(|s| s.contains("task://t1")));
    }

    #[test]
    fn undeclared_network_invalidates() {
        let meta = RunExperimentMeta {
            dataset_case: Some("case-1".into()),
            ..Default::default()
        };
        let mut ext = ExternalEvidenceEvent::new(
            "proxy",
            "proxy",
            "1",
            EvidenceAction::HttpRequest,
        );
        ext.destination = Some("https://cheat.example/a".into());
        let rec = auto_provenance_record("r1", Some(&meta), &[ext]).unwrap();
        assert_eq!(rec.status, ProvenanceStatus::InvalidUndeclaredSource);
    }

    #[test]
    fn declared_only_valid_when_no_extra() {
        let meta = RunExperimentMeta {
            dataset_case: Some("case-1".into()),
            ..Default::default()
        };
        let rec = auto_provenance_record("r1", Some(&meta), &[]).unwrap();
        assert_eq!(rec.status, ProvenanceStatus::Valid);
    }
}
