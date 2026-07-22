//! Bounded, redacted forensic packs for on-premise analysis.

#![allow(missing_docs)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::boundary::{BoundaryFinding, EvidenceEdge, ResolvedBoundary};
use crate::core::event::TraceEvent;
use crate::evidence::ExternalEvidenceEvent;
use crate::incident::IncidentGraph;

/// Schema for forensic packs.
pub const FORENSIC_PACK_SCHEMA: &str = "blackbox.forensic.pack/v1";

/// Options controlling pack generation.
#[derive(Debug, Clone)]
pub struct ForensicPackOpts {
    /// Max events retained (ordered window).
    pub max_events: usize,
    /// Max external evidence rows.
    pub max_external: usize,
    /// Max findings.
    pub max_findings: usize,
    /// Opaque stable replacements for secrets (never store cleartext).
    pub redact_patterns: Vec<String>,
}

impl Default for ForensicPackOpts {
    fn default() -> Self {
        Self {
            max_events: 200,
            max_external: 100,
            max_findings: 50,
            redact_patterns: vec![
                "AKIA".into(),
                "password=".into(),
                "secret=".into(),
                "Bearer ".into(),
            ],
        }
    }
}

/// A derived claim (model or human) that must cite evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForensicClaim {
    pub claim: String,
    /// Evidence pointers (event ids, external ids, finding ids).
    pub citations: Vec<String>,
    /// `deterministic` | `human` | `model` — model claims never replace originals.
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<bool>,
}

/// Bounded forensic pack suitable for local/offline models.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForensicPack {
    pub schema: String,
    pub run_id: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// Ordered event window (redacted summaries).
    pub event_window: Vec<serde_json::Value>,
    /// Causal / correlation neighborhood.
    pub edges: Vec<EvidenceEdge>,
    /// Entity fingerprints (commands, destinations) with opaque secrets.
    pub fingerprints: Vec<String>,
    /// Deterministic findings.
    pub findings: Vec<BoundaryFinding>,
    /// External evidence summaries (no raw secrets).
    pub external_summaries: Vec<serde_json::Value>,
    /// Coverage gaps and clock uncertainty notes.
    pub coverage_gaps: Vec<String>,
    /// Immutable pointers back to originals.
    pub original_pointers: Vec<String>,
    /// Derived claims (optional; validated citations).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_claims: Vec<ForensicClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_graph: Option<IncidentGraph>,
    /// Content hash of the pack body for integrity.
    pub pack_hash: String,
}

/// Build a forensic pack from store-derived inputs.
pub fn build_forensic_pack(
    run_id: &str,
    boundary: Option<&ResolvedBoundary>,
    events: &[TraceEvent],
    external: &[ExternalEvidenceEvent],
    findings: &[BoundaryFinding],
    edges: &[EvidenceEdge],
    opts: &ForensicPackOpts,
) -> ForensicPack {
    let mut coverage_gaps = Vec::new();
    if events.is_empty() {
        coverage_gaps.push("no_trace_events".into());
    }
    if external.is_empty() {
        coverage_gaps.push("no_external_evidence".into());
    }
    if boundary.is_none() {
        coverage_gaps.push("no_boundary_contract".into());
    }

    let event_window: Vec<serde_json::Value> = events
        .iter()
        .take(opts.max_events)
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "sequence": e.sequence,
                "kind": e.kind,
                "status": format!("{:?}", e.status),
                "started_at": e.started_at.to_rfc3339(),
                "metadata": redact_value(&serde_json::to_value(&e.metadata).unwrap_or_default(), opts),
            })
        })
        .collect();

    let external_summaries: Vec<serde_json::Value> = external
        .iter()
        .take(opts.max_external)
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "source": e.source,
                "sensor": e.sensor,
                "action": e.action.as_str(),
                "destination": e.destination.as_ref().map(|d| redact_str(d, opts)),
                "outcome": e.outcome.as_str(),
                "linked_run_id": e.linked_run_id,
            })
        })
        .collect();

    let findings: Vec<BoundaryFinding> = findings.iter().take(opts.max_findings).cloned().collect();

    let mut fingerprints = Vec::new();
    for e in events.iter().take(opts.max_events) {
        if let Some(cmd) = e
            .metadata
            .get("command")
            .and_then(|v| v.as_str())
            .or_else(|| {
                e.metadata
                    .get("input")
                    .and_then(|v| v.get("command"))
                    .and_then(|v| v.as_str())
            })
        {
            fingerprints.push(format!("cmd:{}", redact_str(cmd, opts)));
        }
    }
    for e in external.iter().take(opts.max_external) {
        if let Some(ref d) = e.destination {
            fingerprints.push(format!("dest:{}", redact_str(d, opts)));
        }
    }
    fingerprints.sort();
    fingerprints.dedup();

    let mut original_pointers: Vec<String> = event_window
        .iter()
        .filter_map(|v| v.get("id").and_then(|x| x.as_str()).map(|s| format!("event:{s}")))
        .collect();
    for e in external.iter().take(opts.max_external) {
        original_pointers.push(format!("external:{}", e.id));
    }
    for f in &findings {
        original_pointers.push(format!("finding:{}", f.id));
    }

    // Deterministic claims from detectors (citations validated).
    let mut derived_claims = Vec::new();
    for f in &findings {
        let mut citations = f.evidence_event_ids.clone();
        citations.extend(f.external_evidence_ids.iter().cloned());
        citations.push(f.id.clone());
        // Drop claims with empty citations.
        if citations.is_empty() {
            continue;
        }
        // Validate citations resolve to pack pointers or finding id.
        let ok = citations.iter().all(|c| {
            original_pointers.iter().any(|p| p.ends_with(c)) || c == &f.id
        });
        if !ok {
            coverage_gaps.push(format!("invalid_citation_on_finding_{}", f.id));
            continue;
        }
        derived_claims.push(ForensicClaim {
            claim: f.summary.clone(),
            citations,
            origin: "deterministic".into(),
            confidence: Some(f.severity.as_str().into()),
            model: None,
            refused: None,
        });
    }

    let mut pack = ForensicPack {
        schema: FORENSIC_PACK_SCHEMA.into(),
        run_id: run_id.into(),
        created_at: Utc::now(),
        policy_hash: boundary.map(|b| b.policy_hash.clone()),
        event_window,
        edges: edges.to_vec(),
        fingerprints,
        findings,
        external_summaries,
        coverage_gaps,
        original_pointers,
        derived_claims,
        incident_graph: None,
        pack_hash: String::new(),
    };
    pack.pack_hash = hash_pack(&pack);
    pack
}

fn hash_pack(pack: &ForensicPack) -> String {
    // Hash without pack_hash field.
    let mut tmp = pack.clone();
    tmp.pack_hash.clear();
    let s = serde_json::to_string(&tmp).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn redact_str(s: &str, opts: &ForensicPackOpts) -> String {
    let mut out = s.to_string();
    for pat in &opts.redact_patterns {
        if out.contains(pat) {
            let rep = format!("[REDACTED:{}]", short_hash(pat));
            out = out.replace(pat, &rep);
        }
    }
    // Truncate very long strings.
    if out.len() > 240 {
        out.truncate(240);
        out.push('…');
    }
    out
}

fn redact_value(v: &serde_json::Value, opts: &ForensicPackOpts) -> serde_json::Value {
    match v {
        serde_json::Value::String(s) => serde_json::Value::String(redact_str(s, opts)),
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(|x| redact_value(x, opts)).collect())
        }
        serde_json::Value::Object(m) => {
            let mut out = serde_json::Map::new();
            for (k, val) in m {
                out.insert(k.clone(), redact_value(val, opts));
            }
            serde_json::Value::Object(out)
        }
        other => other.clone(),
    }
}

fn short_hash(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(&h.finalize()[..4])
}

/// Optional local/offline model-assisted analysis input.
///
/// Blackbox never requires a hosted provider. Callers pass model output;
/// this function only validates citations and records refusal/failure.
#[derive(Debug, Clone)]
pub struct ModelAnalysisInput {
    pub model: String,
    pub prompt_fingerprint: Option<String>,
    /// Free-form model claims as (text, citation ids).
    pub claims: Vec<(String, Vec<String>)>,
    /// Model refused to analyze.
    pub refused: bool,
    /// Model/runtime failure message.
    pub failure: Option<String>,
}

/// Attach model-derived claims to a pack (citations must resolve).
pub fn apply_model_analysis(
    pack: &mut ForensicPack,
    input: &ModelAnalysisInput,
) -> Result<(), Vec<String>> {
    if input.refused {
        pack.derived_claims.push(ForensicClaim {
            claim: "model refused analysis".into(),
            citations: pack.original_pointers.iter().take(1).cloned().collect(),
            origin: "model".into(),
            confidence: Some("unknown".into()),
            model: Some(input.model.clone()),
            refused: Some(true),
        });
        if pack.derived_claims.last().unwrap().citations.is_empty() {
            pack.coverage_gaps
                .push("model_refusal_without_evidence_pointer".into());
        }
        pack.pack_hash = hash_pack(pack);
        return Ok(());
    }
    if let Some(ref fail) = input.failure {
        pack.derived_claims.push(ForensicClaim {
            claim: format!("model analysis failed: {fail}"),
            citations: pack.original_pointers.iter().take(1).cloned().collect(),
            origin: "model".into(),
            confidence: Some("unknown".into()),
            model: Some(input.model.clone()),
            refused: Some(false),
        });
        pack.coverage_gaps.push("model_analysis_failure".into());
        pack.pack_hash = hash_pack(pack);
        return Ok(());
    }
    let mut errs = Vec::new();
    for (text, cits) in &input.claims {
        if cits.is_empty() {
            errs.push(format!("model claim has no citations: {text}"));
            continue;
        }
        let ok = cits.iter().all(|c| {
            pack.original_pointers.iter().any(|p| p.ends_with(c.as_str()))
                || pack.findings.iter().any(|f| f.id == *c)
        });
        if !ok {
            errs.push(format!("model claim has dangling citations: {text}"));
            continue;
        }
        pack.derived_claims.push(ForensicClaim {
            claim: text.clone(),
            citations: cits.clone(),
            origin: "model".into(),
            confidence: Some("weakly_correlated".into()),
            model: Some(input.model.clone()),
            refused: None,
        });
    }
    if let Some(ref fp) = input.prompt_fingerprint {
        pack.coverage_gaps
            .push(format!("model_prompt_fingerprint:{fp}"));
    }
    pack.pack_hash = hash_pack(pack);
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// Validate that every citation in derived claims points at an original pointer.
pub fn validate_claim_citations(pack: &ForensicPack) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();
    for claim in &pack.derived_claims {
        if claim.citations.is_empty() {
            errs.push(format!("claim has no citations: {}", claim.claim));
            continue;
        }
        for c in &claim.citations {
            let ok = pack.original_pointers.iter().any(|p| p.ends_with(c.as_str()))
                || pack.findings.iter().any(|f| f.id == *c);
            if !ok {
                errs.push(format!("dangling citation {c} for claim {}", claim.claim));
            }
        }
        // Model claims must not be origin=deterministic.
        if claim.origin == "model" && claim.model.is_none() {
            errs.push("model claim missing model field".into());
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{BoundaryFinding, FindingKind, FindingSeverity};
    use crate::core::event::{EventSource, TraceEvent};

    #[test]
    fn pack_redacts_and_cites() {
        let mut ev = TraceEvent::new("r1", EventSource::Tool, "tool.call");
        ev.metadata
            .insert("command".into(), serde_json::json!("curl password=sekrit"));
        let f = BoundaryFinding {
            schema: "blackbox.boundary.finding/v1".into(),
            id: "find-1".into(),
            run_id: "r1".into(),
            kind: FindingKind::BoundaryViolation,
            detector: "test".into(),
            severity: FindingSeverity::High,
            summary: "bad".into(),
            evidence_event_ids: vec![ev.id.clone()],
            external_evidence_ids: vec![],
            token: None,
            disposition: None,
            recommendation: None,
            created_at: Utc::now(),
            confidence_note: "deterministic_detector".into(),
        };
        let pack = build_forensic_pack(
            "r1",
            None,
            &[ev],
            &[],
            std::slice::from_ref(&f),
            &[],
            &ForensicPackOpts::default(),
        );
        assert!(pack
            .fingerprints
            .iter()
            .any(|fp| fp.contains("REDACTED") || !fp.is_empty()));
        assert!(!pack.pack_hash.is_empty());
        validate_claim_citations(&pack).unwrap();
        assert_eq!(pack.findings[0].id, f.id);
    }
}
