//! Bounded, redacted forensic packs for on-premise analysis.

#![allow(missing_docs)]
use std::collections::HashMap;
use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::boundary::{BoundaryFinding, EvidenceEdge, ResolvedBoundary};
use crate::core::event::TraceEvent;
use crate::evidence::ExternalEvidenceEvent;
use crate::incident::IncidentGraph;
use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;

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
    /// Fingerprint of the exact prompt/template used to produce a model claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_fingerprint: Option<String>,
    /// Fingerprint of inference/runtime configuration used for the model claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_fingerprint: Option<String>,
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

    let findings: Vec<BoundaryFinding> = findings
        .iter()
        .take(opts.max_findings)
        .map(|f| {
            let mut f = f.clone();
            f.summary = redact_str(&f.summary, opts);
            if let Some(ref rec) = f.recommendation {
                f.recommendation = Some(redact_str(rec, opts));
            }
            f
        })
        .collect();

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
        .filter_map(|v| {
            v.get("id")
                .and_then(|x| x.as_str())
                .map(|s| format!("event:{s}"))
        })
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
        let mut citations: Vec<String> = f
            .evidence_event_ids
            .iter()
            .map(|id| format!("event:{id}"))
            .collect();
        citations.extend(
            f.external_evidence_ids
                .iter()
                .map(|id| format!("external:{id}")),
        );
        citations.push(format!("finding:{}", f.id));
        // Drop claims with empty citations.
        if citations.is_empty() {
            continue;
        }
        // Validate citations resolve to pack pointers or finding id.
        let ok = citations.iter().all(|c| original_pointers.contains(c));
        if !ok {
            coverage_gaps.push(format!("invalid_citation_on_finding_{}", f.id));
            continue;
        }
        derived_claims.push(ForensicClaim {
            // Summary already redacted on findings above.
            claim: f.summary.clone(),
            citations,
            origin: "deterministic".into(),
            confidence: Some(f.severity.as_str().into()),
            model: None,
            prompt_fingerprint: None,
            configuration_fingerprint: None,
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
    sanitize_pack_content(&mut pack, opts);
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

/// Validate the pack schema, content hash, and exact typed citations.
pub fn validate_forensic_pack(pack: &ForensicPack) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if pack.schema != FORENSIC_PACK_SCHEMA {
        errors.push(format!("unsupported forensic pack schema {}", pack.schema));
    }
    if hash_pack(pack) != pack.pack_hash {
        errors.push("pack_hash mismatch".into());
    }
    if let Err(mut citation_errors) = validate_claim_citations(pack) {
        errors.append(&mut citation_errors);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn pack_scanner() -> &'static SecretScanner {
    static SCANNER: OnceLock<SecretScanner> = OnceLock::new();
    SCANNER.get_or_init(|| SecretScanner::new(RedactionConfig::default()))
}

fn redact_str(s: &str, opts: &ForensicPackOpts) -> String {
    // Full SecretScanner first (API keys, JWTs, PEMs, connection strings, …).
    let mut out = pack_scanner().redact(s);
    // Operator/extra substring patterns (opaque stable tags for incident sharing).
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

struct StablePackRedactor<'a> {
    opts: &'a ForensicPackOpts,
    replacements: HashMap<String, String>,
    namespace: String,
    next_replacement: usize,
}

impl<'a> StablePackRedactor<'a> {
    fn new(opts: &'a ForensicPackOpts) -> Self {
        Self {
            opts,
            replacements: HashMap::new(),
            namespace: uuid::Uuid::new_v4().simple().to_string()[..8].to_string(),
            next_replacement: 0,
        }
    }

    fn redact(&mut self, value: &str) -> String {
        let mut spans = pack_scanner().find_spans(value);
        for pattern in &self.opts.redact_patterns {
            if pattern.is_empty() {
                continue;
            }
            spans.extend(
                value
                    .match_indices(pattern)
                    .map(|(start, matched)| (start, start + matched.len())),
            );
        }
        spans.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| right.1.cmp(&left.1)));
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for span in spans {
            if let Some(previous) = merged.last_mut() {
                if span.0 <= previous.1 {
                    previous.1 = previous.1.max(span.1);
                    continue;
                }
            }
            merged.push(span);
        }
        if merged.is_empty() {
            return value.to_string();
        }

        let mut output = String::with_capacity(value.len());
        let mut cursor = 0;
        for (start, end) in merged {
            output.push_str(&value[cursor..start]);
            let secret = &value[start..end];
            let replacement = self
                .replacements
                .entry(secret.to_string())
                .or_insert_with(|| {
                    self.next_replacement += 1;
                    format!("[REDACTED:{}:{:04}]", self.namespace, self.next_replacement)
                });
            output.push_str(replacement);
            cursor = end;
        }
        output.push_str(&value[cursor..]);
        output
    }
}

fn sanitize_json_value(value: &mut serde_json::Value, redactor: &mut StablePackRedactor<'_>) {
    match value {
        serde_json::Value::String(text) => *text = redactor.redact(text),
        serde_json::Value::Array(items) => {
            for item in items {
                sanitize_json_value(item, redactor);
            }
        }
        serde_json::Value::Object(map) => {
            let entries = std::mem::take(map);
            for (key, mut child) in entries {
                let safe_key = redactor.redact(&key);
                sanitize_json_value(&mut child, redactor);
                map.insert(safe_key, child);
            }
        }
        _ => {}
    }
}

fn sanitize_pack_content(pack: &mut ForensicPack, opts: &ForensicPackOpts) {
    let existing_hash = std::mem::take(&mut pack.pack_hash);
    let mut value = serde_json::to_value(&*pack)
        .expect("ForensicPack serialization to serde_json::Value is infallible");
    let mut redactor = StablePackRedactor::new(opts);
    sanitize_json_value(&mut value, &mut redactor);
    *pack =
        serde_json::from_value(value).expect("sanitized ForensicPack must retain its schema shape");
    pack.pack_hash = existing_hash;
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
    /// Exact prompt bytes; Blackbox computes the recorded SHA-256 fingerprint.
    pub prompt: Vec<u8>,
    /// Exact configuration bytes; Blackbox computes the recorded SHA-256 fingerprint.
    pub configuration: Vec<u8>,
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
    validate_forensic_pack(pack)?;

    let mut provenance_errors = Vec::new();
    if input.model.trim().is_empty() {
        provenance_errors.push("model identifier is empty".into());
    }
    if input.prompt.is_empty() {
        provenance_errors.push("model prompt input is empty".into());
    }
    if input.configuration.is_empty() {
        provenance_errors.push("model configuration input is empty".into());
    }
    if !provenance_errors.is_empty() {
        return Err(provenance_errors);
    }

    if (input.refused || input.failure.is_some()) && pack.original_pointers.is_empty() {
        return Err(vec![
            "model refusal/failure requires at least one original evidence pointer".into(),
        ]);
    }

    let prompt_fingerprint = sha256_fingerprint(&input.prompt);
    let configuration_fingerprint = sha256_fingerprint(&input.configuration);
    let mut candidate = pack.clone();

    if input.refused {
        candidate.derived_claims.push(ForensicClaim {
            claim: "model refused analysis".into(),
            citations: candidate
                .original_pointers
                .iter()
                .take(1)
                .cloned()
                .collect(),
            origin: "model".into(),
            confidence: Some("unknown".into()),
            model: Some(input.model.clone()),
            prompt_fingerprint: Some(prompt_fingerprint),
            configuration_fingerprint: Some(configuration_fingerprint),
            refused: Some(true),
        });
        sanitize_pack_content(&mut candidate, &ForensicPackOpts::default());
        candidate.pack_hash = hash_pack(&candidate);
        validate_forensic_pack(&candidate)?;
        *pack = candidate;
        return Ok(());
    }
    if let Some(ref fail) = input.failure {
        candidate.derived_claims.push(ForensicClaim {
            claim: format!("model analysis failed: {fail}"),
            citations: candidate
                .original_pointers
                .iter()
                .take(1)
                .cloned()
                .collect(),
            origin: "model".into(),
            confidence: Some("unknown".into()),
            model: Some(input.model.clone()),
            prompt_fingerprint: Some(prompt_fingerprint),
            configuration_fingerprint: Some(configuration_fingerprint),
            refused: Some(false),
        });
        candidate
            .coverage_gaps
            .push("model_analysis_failure".into());
        sanitize_pack_content(&mut candidate, &ForensicPackOpts::default());
        candidate.pack_hash = hash_pack(&candidate);
        validate_forensic_pack(&candidate)?;
        *pack = candidate;
        return Ok(());
    }
    let mut errs = Vec::new();
    for (text, cits) in &input.claims {
        if cits.is_empty() {
            errs.push(format!("model claim has no citations: {text}"));
            continue;
        }
        let ok = cits.iter().all(|c| pack.original_pointers.contains(c));
        if !ok {
            errs.push(format!("model claim has dangling citations: {text}"));
            continue;
        }
        candidate.derived_claims.push(ForensicClaim {
            claim: text.clone(),
            citations: cits.clone(),
            origin: "model".into(),
            confidence: Some("weakly_correlated".into()),
            model: Some(input.model.clone()),
            prompt_fingerprint: Some(prompt_fingerprint.clone()),
            configuration_fingerprint: Some(configuration_fingerprint.clone()),
            refused: None,
        });
    }
    if errs.is_empty() {
        sanitize_pack_content(&mut candidate, &ForensicPackOpts::default());
        candidate.pack_hash = hash_pack(&candidate);
        validate_forensic_pack(&candidate)?;
        *pack = candidate;
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
            let ok = pack.original_pointers.contains(c);
            if !ok {
                errs.push(format!("dangling citation {c} for claim {}", claim.claim));
            }
        }
        // Model claims must not be origin=deterministic.
        if claim.origin == "model" && claim.model.is_none() {
            errs.push("model claim missing model field".into());
        }
        if claim.origin == "model"
            && !claim
                .prompt_fingerprint
                .as_deref()
                .is_some_and(is_sha256_fingerprint)
        {
            errs.push("model claim missing or invalid prompt fingerprint".into());
        }
        if claim.origin == "model"
            && !claim
                .configuration_fingerprint
                .as_deref()
                .is_some_and(is_sha256_fingerprint)
        {
            errs.push("model claim missing or invalid configuration fingerprint".into());
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

fn sha256_fingerprint(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn is_sha256_fingerprint(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{
        BoundaryFinding, EntityKind, EvidenceRelation, FindingKind, FindingSeverity,
    };
    use crate::core::event::{Confidence, EventSource, TraceEvent};
    use crate::evidence::{EvidenceAction, ExternalEvidenceEvent};
    use crate::incident::{
        attach_to_incident, build_incident_graph, GraphInputs, Incident, IncidentAttachmentKind,
    };

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

    #[test]
    fn pack_secret_scanner_redacts_api_keys() {
        let mut ev = TraceEvent::new("r1", EventSource::Tool, "tool.call");
        // OpenAI-shaped key (matches SecretScanner BASE_PATTERNS), not only substring tags.
        let secret = "sk-abcdefghijklmnopqrstuvwxyz012345";
        ev.metadata.insert(
            "command".into(),
            serde_json::json!(format!("export KEY={secret}")),
        );
        let pack = build_forensic_pack(
            "r1",
            None,
            &[ev],
            &[],
            &[],
            &[],
            &ForensicPackOpts {
                // No substring patterns that would catch sk- alone.
                redact_patterns: vec![],
                ..Default::default()
            },
        );
        let dumped = serde_json::to_string(&pack).unwrap();
        assert!(
            !dumped.contains(secret),
            "forensic pack must not leak API key material: {dumped}"
        );
        assert!(
            dumped.contains("REDACTED")
                || pack.fingerprints.iter().any(|fp| fp.contains("REDACTED")),
            "expected SecretScanner redaction markers"
        );
    }

    #[test]
    fn model_claim_records_reproducibility_provenance() {
        let ev = TraceEvent::new("r1", EventSource::Tool, "tool.call");
        let event_id = ev.id.clone();
        let mut pack = build_forensic_pack(
            "r1",
            None,
            &[ev],
            &[],
            &[],
            &[],
            &ForensicPackOpts::default(),
        );
        let original_hash = pack.pack_hash.clone();

        apply_model_analysis(
            &mut pack,
            &ModelAnalysisInput {
                model: "local/model@sha256:1234".into(),
                prompt: b"exact prompt bytes".to_vec(),
                configuration: br#"{"temperature":0}"#.to_vec(),
                claims: vec![(
                    "derived observation".into(),
                    vec![format!("event:{event_id}")],
                )],
                refused: false,
                failure: None,
            },
        )
        .unwrap();

        let claim = pack.derived_claims.last().unwrap();
        assert_eq!(claim.origin, "model");
        assert_eq!(claim.model.as_deref(), Some("local/model@sha256:1234"));
        assert_eq!(
            claim.prompt_fingerprint.as_deref(),
            Some(sha256_fingerprint(b"exact prompt bytes").as_str())
        );
        assert_eq!(
            claim.configuration_fingerprint.as_deref(),
            Some(sha256_fingerprint(br#"{"temperature":0}"#).as_str())
        );
        assert_ne!(pack.pack_hash, original_hash);
        validate_forensic_pack(&pack).unwrap();
    }

    #[test]
    fn model_analysis_rejects_missing_reproducibility_provenance() {
        let ev = TraceEvent::new("r1", EventSource::Tool, "tool.call");
        let mut pack = build_forensic_pack(
            "r1",
            None,
            &[ev],
            &[],
            &[],
            &[],
            &ForensicPackOpts::default(),
        );
        let before = pack.clone();

        let errors = apply_model_analysis(
            &mut pack,
            &ModelAnalysisInput {
                model: "local".into(),
                prompt: Vec::new(),
                configuration: Vec::new(),
                claims: vec![],
                refused: true,
                failure: None,
            },
        )
        .unwrap_err();

        assert!(errors.iter().any(|e| e.contains("prompt input")));
        assert!(errors.iter().any(|e| e.contains("configuration input")));
        assert_eq!(pack, before, "invalid analysis must be mutation-free");
    }

    #[test]
    fn model_analysis_rejects_tampered_pack_and_suffix_citations() {
        let ev = TraceEvent::new("r1", EventSource::Tool, "tool.call");
        let mut pack = build_forensic_pack(
            "r1",
            None,
            &[ev],
            &[],
            &[],
            &[],
            &ForensicPackOpts::default(),
        );
        let suffix = pack.original_pointers[0]
            .chars()
            .last()
            .unwrap()
            .to_string();
        let before = pack.clone();
        let errors = apply_model_analysis(
            &mut pack,
            &ModelAnalysisInput {
                model: "local".into(),
                prompt: b"prompt".to_vec(),
                configuration: b"config".to_vec(),
                claims: vec![("suffix-only".into(), vec![suffix])],
                refused: false,
                failure: None,
            },
        )
        .unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.contains("dangling citations")));
        assert_eq!(pack, before);

        pack.coverage_gaps.push("tampered".into());
        let tampered = pack.clone();
        let errors = apply_model_analysis(
            &mut pack,
            &ModelAnalysisInput {
                model: "local".into(),
                prompt: b"prompt".to_vec(),
                configuration: b"config".to_vec(),
                claims: vec![],
                refused: true,
                failure: None,
            },
        )
        .unwrap_err();
        assert!(errors.iter().any(|error| error == "pack_hash mismatch"));
        assert_eq!(pack, tampered, "tampered input must remain untouched");
    }

    #[test]
    fn prompt_and_configuration_bytes_determine_fingerprints() {
        let event = TraceEvent::new("r1", EventSource::Tool, "tool.call");
        let pointer = format!("event:{}", event.id);
        let base = build_forensic_pack(
            "r1",
            None,
            &[event],
            &[],
            &[],
            &[],
            &ForensicPackOpts::default(),
        );
        let mut first = base.clone();
        let mut second = base;
        for (pack, prompt, config) in [
            (&mut first, b"prompt-a".as_slice(), b"config-a".as_slice()),
            (&mut second, b"prompt-b".as_slice(), b"config-b".as_slice()),
        ] {
            apply_model_analysis(
                pack,
                &ModelAnalysisInput {
                    model: "local".into(),
                    prompt: prompt.to_vec(),
                    configuration: config.to_vec(),
                    claims: vec![("claim".into(), vec![pointer.clone()])],
                    refused: false,
                    failure: None,
                },
            )
            .unwrap();
        }
        assert_ne!(
            first.derived_claims[0].prompt_fingerprint,
            second.derived_claims[0].prompt_fingerprint
        );
        assert_ne!(
            first.derived_claims[0].configuration_fingerprint,
            second.derived_claims[0].configuration_fingerprint
        );

        first.derived_claims[0].prompt_fingerprint = Some("not-a-hash".into());
        first.pack_hash = hash_pack(&first);
        let errors = validate_forensic_pack(&first).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.contains("invalid prompt fingerprint")));
    }

    #[test]
    fn complete_pack_serialization_redacts_every_hostile_field_family() {
        let secret = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let mut event = TraceEvent::new(secret, EventSource::Tool, secret);
        event.id = secret.into();
        event.parent_event_id = Some(secret.into());
        event
            .metadata
            .insert(secret.into(), serde_json::json!(secret));

        let mut external =
            ExternalEvidenceEvent::new(secret, secret, secret, EvidenceAction::CredentialAccess);
        external.schema = secret.into();
        external.id = secret.into();
        external.destination = Some(secret.into());
        external.object = Some(secret.into());
        external.linked_run_id = Some(secret.into());
        external.identity.principal = Some(secret.into());
        external
            .attributes
            .insert(secret.into(), serde_json::json!(secret));

        let finding = BoundaryFinding {
            schema: secret.into(),
            id: secret.into(),
            run_id: secret.into(),
            kind: FindingKind::BoundaryViolation,
            detector: secret.into(),
            severity: FindingSeverity::High,
            summary: secret.into(),
            evidence_event_ids: vec![secret.into()],
            external_evidence_ids: vec![secret.into()],
            token: Some(secret.into()),
            disposition: None,
            recommendation: Some(secret.into()),
            created_at: Utc::now(),
            confidence_note: secret.into(),
        };
        let mut edge = EvidenceEdge::new(
            EntityKind::Other(secret.into()),
            secret,
            EntityKind::Other(secret.into()),
            secret,
            EvidenceRelation::Other(secret.into()),
            Confidence::StronglyCorrelated,
        );
        edge.schema = secret.into();
        edge.id = secret.into();
        edge.reasons = vec![secret.into()];
        edge.run_id = Some(secret.into());

        let mut pack = build_forensic_pack(
            secret,
            None,
            &[event],
            &[external],
            &[finding],
            std::slice::from_ref(&edge),
            &ForensicPackOpts::default(),
        );
        assert!(!serde_json::to_string(&pack).unwrap().contains(secret));
        validate_forensic_pack(&pack).unwrap();

        let mut incident = Incident::new(Some(secret.into()));
        incident.id = secret.into();
        attach_to_incident(
            &mut incident,
            IncidentAttachmentKind::Run,
            secret,
            Some(secret.into()),
        );
        let mut graph = build_incident_graph(
            &incident,
            &GraphInputs {
                edges: vec![edge],
                ..Default::default()
            },
        );
        graph.schema = secret.into();
        graph.incident_id = secret.into();
        graph.earliest_signal = Some(crate::incident::IncidentSignal {
            ref_id: secret.into(),
            kind: secret.into(),
            summary: secret.into(),
            at: Utc::now(),
            run_id: Some(secret.into()),
        });
        graph.techniques.push(crate::incident::TechniqueReuse {
            technique: secret.into(),
            first_run_id: secret.into(),
            first_ref: secret.into(),
            reused_by_runs: vec![secret.into()],
        });
        pack.incident_graph = Some(graph);
        sanitize_pack_content(&mut pack, &ForensicPackOpts::default());
        pack.pack_hash = hash_pack(&pack);
        validate_forensic_pack(&pack).unwrap();

        let pointer = pack.original_pointers[0].clone();
        apply_model_analysis(
            &mut pack,
            &ModelAnalysisInput {
                model: secret.into(),
                prompt: b"prompt".to_vec(),
                configuration: b"configuration".to_vec(),
                claims: vec![(secret.into(), vec![pointer])],
                refused: false,
                failure: None,
            },
        )
        .unwrap();
        let serialized = serde_json::to_string(&pack).unwrap();
        assert!(
            !serialized.contains(secret),
            "hostile pack leaked: {serialized}"
        );
        validate_forensic_pack(&pack).unwrap();

        let mut failure_pack = pack.clone();
        apply_model_analysis(
            &mut failure_pack,
            &ModelAnalysisInput {
                model: secret.into(),
                prompt: b"prompt".to_vec(),
                configuration: b"configuration".to_vec(),
                claims: vec![],
                refused: false,
                failure: Some(secret.into()),
            },
        )
        .unwrap();
        assert!(!serde_json::to_string(&failure_pack)
            .unwrap()
            .contains(secret));
        validate_forensic_pack(&failure_pack).unwrap();
    }
}
