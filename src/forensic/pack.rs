//! Bounded, redacted forensic packs for on-premise analysis.

#![allow(missing_docs)]
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::boundary::{
    BoundaryFinding, ContainmentReceipt, EvidenceEdge, ProvenanceRecord, ResolvedBoundary,
};
use crate::core::event::TraceEvent;
use crate::evidence::ExternalEvidenceEvent;
use crate::incident::IncidentGraph;
use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;

/// Schema for forensic packs.
pub const FORENSIC_PACK_SCHEMA: &str = "blackbox.forensic.pack/v1";

/// Default selection strategy (1.8 citation-complete).
pub const SELECTION_STRATEGY_HEAD_TAIL_CITED_GRAPH: &str = "head_tail_cited_graph_neighborhood";

type HmacSha256 = Hmac<Sha256>;

/// How secret replacements are generated across packs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SecretTokenMode {
    /// Per-pack random namespace; equality across packs is not meaningful.
    #[default]
    Unlinkable,
    /// Project-keyed HMAC identifiers; equal secrets match across packs.
    ProjectCorrelatable { key: Vec<u8> },
}

/// Options controlling pack generation.
#[derive(Debug, Clone)]
pub struct ForensicPackOpts {
    /// Max events retained (head+tail+cited budget).
    pub max_events: usize,
    /// Max external evidence rows.
    pub max_external: usize,
    /// Max findings.
    pub max_findings: usize,
    /// Head slice size for ordered event/external windows.
    pub head_count: usize,
    /// Tail slice size for ordered event/external windows.
    pub tail_count: usize,
    /// Opaque stable replacements for secrets (never store cleartext).
    pub redact_patterns: Vec<String>,
    /// Secret token correlation mode (default unlinkable).
    pub secret_token_mode: SecretTokenMode,
}

impl Default for ForensicPackOpts {
    fn default() -> Self {
        Self {
            max_events: 200,
            max_external: 100,
            max_findings: 50,
            head_count: 40,
            tail_count: 40,
            redact_patterns: vec![
                "AKIA".into(),
                "password=".into(),
                "secret=".into(),
                "Bearer ".into(),
            ],
            secret_token_mode: SecretTokenMode::Unlinkable,
        }
    }
}

/// Exact forensic pack scope accounting (1.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicPackScope {
    pub events_total: usize,
    pub events_included: usize,
    pub findings_total: usize,
    pub findings_included: usize,
    pub external_total: usize,
    pub external_included: usize,
    pub edges_total: usize,
    pub edges_included: usize,
    #[serde(default)]
    pub containment_total: usize,
    #[serde(default)]
    pub containment_included: usize,
    #[serde(default)]
    pub provenance_total: usize,
    #[serde(default)]
    pub provenance_included: usize,
    pub strategy: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable_citations: Vec<UnavailableCitation>,
}

/// A finding citation that could not be materialized into the pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnavailableCitation {
    pub finding_id: String,
    pub citation: String,
    pub reason: String,
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
    /// Present when a cited evidence row could not be included (1.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub citation_unavailable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub citation_unavailable_reason: Option<String>,
}

/// Bounded forensic pack suitable for local/offline models.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForensicPack {
    pub schema: String,
    /// Explicit semantic layer for each heterogeneous pack collection.
    #[serde(default = "forensic_evidence_layers")]
    pub evidence_layers: BTreeMap<String, String>,
    pub run_id: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// Exact totals / included / strategy (1.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ForensicPackScope>,
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
    /// Selected containment receipts needed to interpret boundary claims.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub containment_receipts: Vec<ContainmentReceipt>,
    /// Selected provenance records needed to interpret answer lineage.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance_records: Vec<ProvenanceRecord>,
    /// Effective required-evidence tokens from the resolved policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_evidence: Vec<String>,
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
    match build_forensic_pack_result(
        run_id, boundary, events, external, findings, edges, opts, None,
    ) {
        Ok(pack) => pack,
        Err(errs) => {
            // Fall back to an honest empty pack rather than panicking.
            let safe_run_id = if pack_scanner().find_spans(run_id).is_empty() {
                run_id.to_string()
            } else {
                "invalid-structural-run-id".into()
            };
            let mut pack = ForensicPack {
                schema: FORENSIC_PACK_SCHEMA.into(),
                evidence_layers: forensic_evidence_layers(),
                run_id: safe_run_id,
                created_at: Utc::now(),
                policy_hash: boundary
                    .map(|resolved| resolved.policy_hash.clone())
                    .filter(|hash| pack_scanner().find_spans(hash).is_empty()),
                scope: Some(ForensicPackScope {
                    events_total: events.len(),
                    events_included: 0,
                    findings_total: findings.len(),
                    findings_included: 0,
                    external_total: external.len(),
                    external_included: 0,
                    edges_total: edges.len(),
                    edges_included: 0,
                    containment_total: 0,
                    containment_included: 0,
                    provenance_total: 0,
                    provenance_included: 0,
                    strategy: SELECTION_STRATEGY_HEAD_TAIL_CITED_GRAPH.into(),
                    limitations: errs,
                    unavailable_citations: vec![],
                }),
                event_window: vec![],
                edges: vec![],
                fingerprints: vec![],
                findings: vec![],
                external_summaries: vec![],
                coverage_gaps: vec!["pack_build_error".into()],
                original_pointers: vec![],
                derived_claims: vec![],
                containment_receipts: vec![],
                provenance_records: vec![],
                required_evidence: vec![],
                incident_graph: None,
                pack_hash: String::new(),
            };
            pack.pack_hash = hash_pack(&pack);
            pack
        }
    }
}

/// Fallible pack builder (user redaction patterns must not panic).
#[allow(clippy::too_many_arguments)]
pub fn build_forensic_pack_result(
    run_id: &str,
    boundary: Option<&ResolvedBoundary>,
    events: &[TraceEvent],
    external: &[ExternalEvidenceEvent],
    findings: &[BoundaryFinding],
    edges: &[EvidenceEdge],
    opts: &ForensicPackOpts,
    incident_graph: Option<&IncidentGraph>,
) -> Result<ForensicPack, Vec<String>> {
    build_forensic_pack_with_trust_result(
        run_id,
        boundary,
        events,
        external,
        findings,
        edges,
        &[],
        &[],
        opts,
        incident_graph,
    )
}

/// Build a pack including containment and provenance records selected from the
/// store. The legacy builder remains available for callers without trust data.
#[allow(clippy::too_many_arguments)]
pub fn build_forensic_pack_with_trust(
    run_id: &str,
    boundary: Option<&ResolvedBoundary>,
    events: &[TraceEvent],
    external: &[ExternalEvidenceEvent],
    findings: &[BoundaryFinding],
    edges: &[EvidenceEdge],
    containment: &[ContainmentReceipt],
    provenance: &[ProvenanceRecord],
    opts: &ForensicPackOpts,
) -> ForensicPack {
    build_forensic_pack_with_trust_result(
        run_id,
        boundary,
        events,
        external,
        findings,
        edges,
        containment,
        provenance,
        opts,
        None,
    )
    .unwrap_or_else(|errors| {
        let mut pack =
            build_forensic_pack(run_id, boundary, events, external, findings, edges, opts);
        if let Some(scope) = pack.scope.as_mut() {
            scope.containment_total = containment.len();
            scope.provenance_total = provenance.len();
            scope.limitations.extend(errors);
        }
        pack.pack_hash = hash_pack(&pack);
        pack
    })
}

/// Fallible full-trust pack builder.
#[allow(clippy::too_many_arguments)]
pub fn build_forensic_pack_with_trust_result(
    run_id: &str,
    boundary: Option<&ResolvedBoundary>,
    events: &[TraceEvent],
    external: &[ExternalEvidenceEvent],
    findings: &[BoundaryFinding],
    edges: &[EvidenceEdge],
    containment: &[ContainmentReceipt],
    provenance: &[ProvenanceRecord],
    opts: &ForensicPackOpts,
    incident_graph: Option<&IncidentGraph>,
) -> Result<ForensicPack, Vec<String>> {
    if matches!(
        &opts.secret_token_mode,
        SecretTokenMode::ProjectCorrelatable { key } if key.is_empty()
    ) {
        return Err(vec![
            "project_correlatable_secret_tokens_require_nonempty_hmac_key".into(),
        ]);
    }
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

    // ── Selection: head/tail + cited + graph neighborhood ─────────────
    let selection = select_pack_material(events, external, findings, edges, opts, incident_graph);

    let event_by_id: HashMap<&str, &TraceEvent> =
        events.iter().map(|e| (e.id.as_str(), e)).collect();
    let external_by_id: HashMap<&str, &ExternalEvidenceEvent> =
        external.iter().map(|e| (e.id.as_str(), e)).collect();
    let finding_by_id: HashMap<&str, &BoundaryFinding> =
        findings.iter().map(|f| (f.id.as_str(), f)).collect();

    let mut event_window = Vec::new();
    for e in events
        .iter()
        .filter(|event| selection.event_ids.contains(&event.id))
    {
        event_window.push(serde_json::json!({
            "id": e.id,
            "sequence": e.sequence,
            "kind": e.kind,
            "status": format!("{:?}", e.status),
            "started_at": e.started_at.to_rfc3339(),
            "metadata": redact_value(
                &serde_json::to_value(&e.metadata).unwrap_or_default(),
                opts,
            ),
        }));
    }

    let mut external_summaries = Vec::new();
    for e in external
        .iter()
        .filter(|event| selection.external_ids.contains(&event.id))
    {
        external_summaries.push(serde_json::json!({
            "id": e.id,
            "source": e.source,
            "sensor": e.sensor,
            "action": e.action.as_str(),
            "destination": e.destination.as_ref().map(|d| redact_str(d, opts)),
            "outcome": e.outcome.as_str(),
            "linked_run_id": e.linked_run_id,
        }));
    }

    let mut selected_findings: Vec<BoundaryFinding> = Vec::new();
    for id in &selection.finding_ids {
        let Some(f) = finding_by_id.get(id.as_str()) else {
            continue;
        };
        let mut f = (*f).clone();
        f.summary = redact_str(&f.summary, opts);
        if let Some(ref rec) = f.recommendation {
            f.recommendation = Some(redact_str(rec, opts));
        }
        selected_findings.push(f);
    }

    let selected_edges: Vec<EvidenceEdge> = edges
        .iter()
        .filter(|e| selection.edge_ids.contains(&e.id))
        .cloned()
        .collect();
    let selected_containment = select_head_tail(
        containment,
        opts.max_external,
        opts.head_count,
        opts.tail_count,
    );
    let selected_provenance = select_head_tail(
        provenance,
        opts.max_external,
        opts.head_count,
        opts.tail_count,
    );

    let mut fingerprints = Vec::new();
    for id in &selection.event_ids {
        let Some(e) = event_by_id.get(id.as_str()) else {
            continue;
        };
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
    for id in &selection.external_ids {
        let Some(e) = external_by_id.get(id.as_str()) else {
            continue;
        };
        if let Some(ref d) = e.destination {
            fingerprints.push(format!("dest:{}", redact_str(d, opts)));
        }
    }
    fingerprints.sort();
    fingerprints.dedup();

    let mut original_pointers: Vec<String> = selection
        .event_ids
        .iter()
        .map(|id| format!("event:{id}"))
        .collect();
    for id in &selection.external_ids {
        original_pointers.push(format!("external:{id}"));
    }
    for id in &selection.finding_ids {
        original_pointers.push(format!("finding:{id}"));
    }
    original_pointers.extend(
        selected_containment
            .iter()
            .map(|receipt| format!("receipt:{}", receipt.id)),
    );
    original_pointers.extend(
        selected_provenance
            .iter()
            .map(|record| format!("provenance:{}", record.id)),
    );
    original_pointers.sort();
    original_pointers.dedup();

    // Deterministic claims — every included finding must cite or declare unavailable.
    let mut derived_claims = Vec::new();
    let mut unavailable_citations = Vec::new();
    for f in &selected_findings {
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

        let mut missing = Vec::new();
        for c in &citations {
            if c.starts_with("finding:") {
                continue;
            }
            if !original_pointers.contains(c) {
                // Try to recover cited material still present in full inputs.
                if let Some(id) = c.strip_prefix("event:") {
                    if event_by_id.contains_key(id) && !selection.event_ids.contains(id) {
                        // Budget excluded it — mark unavailable.
                        missing.push((c.clone(), "excluded_by_event_budget".to_string()));
                    } else if !event_by_id.contains_key(id) {
                        missing.push((c.clone(), "source_event_not_in_store".to_string()));
                    }
                } else if let Some(id) = c.strip_prefix("external:") {
                    if external_by_id.contains_key(id) && !selection.external_ids.contains(id) {
                        missing.push((c.clone(), "excluded_by_external_budget".to_string()));
                    } else if !external_by_id.contains_key(id) {
                        missing.push((c.clone(), "source_external_not_in_store".to_string()));
                    }
                } else {
                    missing.push((c.clone(), "unknown_citation_form".to_string()));
                }
            }
        }

        if missing.is_empty() {
            derived_claims.push(ForensicClaim {
                claim: f.summary.clone(),
                citations,
                origin: "deterministic".into(),
                confidence: Some(f.severity.as_str().into()),
                model: None,
                prompt_fingerprint: None,
                configuration_fingerprint: None,
                refused: None,
                citation_unavailable: None,
                citation_unavailable_reason: None,
            });
        } else {
            for (citation, reason) in &missing {
                unavailable_citations.push(UnavailableCitation {
                    finding_id: f.id.clone(),
                    citation: citation.clone(),
                    reason: reason.clone(),
                });
            }
            let reason = missing
                .iter()
                .map(|(c, r)| format!("{c}:{r}"))
                .collect::<Vec<_>>()
                .join("; ");
            coverage_gaps.push(format!("citation_unavailable_on_finding_{}", f.id));
            // Still serialize the finding claim with explicit unavailability.
            derived_claims.push(ForensicClaim {
                claim: f.summary.clone(),
                citations: citations
                    .into_iter()
                    .filter(|c| original_pointers.contains(c) || c.starts_with("finding:"))
                    .collect(),
                origin: "deterministic".into(),
                confidence: Some(f.severity.as_str().into()),
                model: None,
                prompt_fingerprint: None,
                configuration_fingerprint: None,
                refused: None,
                citation_unavailable: Some(true),
                citation_unavailable_reason: Some(reason),
            });
        }
    }

    let mut limitations = selection.limitations.clone();
    if selection.event_ids.len() < events.len() {
        limitations.push("events_truncated".into());
    }
    if selection.external_ids.len() < external.len() {
        limitations.push("external_truncated".into());
    }
    if selection.finding_ids.len() < findings.len() {
        limitations.push("findings_truncated".into());
    }
    if selected_containment.len() < containment.len() {
        limitations.push("containment_receipts_truncated".into());
    }
    if selected_provenance.len() < provenance.len() {
        limitations.push("provenance_records_truncated".into());
    }

    let scope = ForensicPackScope {
        events_total: events.len(),
        events_included: selection.event_ids.len(),
        findings_total: findings.len(),
        findings_included: selection.finding_ids.len(),
        external_total: external.len(),
        external_included: selection.external_ids.len(),
        edges_total: edges.len(),
        edges_included: selected_edges.len(),
        containment_total: containment.len(),
        containment_included: selected_containment.len(),
        provenance_total: provenance.len(),
        provenance_included: selected_provenance.len(),
        strategy: SELECTION_STRATEGY_HEAD_TAIL_CITED_GRAPH.into(),
        limitations,
        unavailable_citations,
    };

    let mut pack = ForensicPack {
        schema: FORENSIC_PACK_SCHEMA.into(),
        evidence_layers: forensic_evidence_layers(),
        run_id: run_id.into(),
        created_at: Utc::now(),
        policy_hash: boundary.map(|b| b.policy_hash.clone()),
        scope: Some(scope),
        event_window,
        edges: selected_edges,
        fingerprints,
        findings: selected_findings,
        external_summaries,
        coverage_gaps,
        original_pointers,
        derived_claims,
        containment_receipts: selected_containment,
        provenance_records: selected_provenance,
        required_evidence: boundary
            .map(|resolved| resolved.contract.required_evidence.clone())
            .unwrap_or_default(),
        incident_graph: incident_graph.cloned(),
        pack_hash: String::new(),
    };
    sanitize_pack_content(&mut pack, opts)?;
    pack.pack_hash = hash_pack(&pack);
    Ok(pack)
}

fn forensic_evidence_layers() -> BTreeMap<String, String> {
    [
        ("event_window", "observation"),
        ("external_summaries", "observation"),
        ("fingerprints", "normalized_fact"),
        ("edges", "correlation"),
        ("findings", "findings"),
        ("incident_graph", "incident_interpretation"),
        ("derived_claims", "claim"),
        ("containment_receipts", "observation"),
        ("provenance_records", "observation"),
        ("required_evidence", "normalized_fact"),
    ]
    .into_iter()
    .map(|(field, layer)| (field.into(), layer.into()))
    .collect()
}

fn select_head_tail<T: Clone>(
    values: &[T],
    max: usize,
    head_count: usize,
    tail_count: usize,
) -> Vec<T> {
    if values.len() <= max {
        return values.to_vec();
    }
    let (head, tail) = bounded_head_tail_counts(max, head_count, tail_count);
    values
        .iter()
        .take(head)
        .chain(
            values
                .iter()
                .rev()
                .take(tail)
                .collect::<Vec<_>>()
                .into_iter()
                .rev(),
        )
        .cloned()
        .collect()
}

struct PackSelection {
    event_ids: BTreeSet<String>,
    external_ids: BTreeSet<String>,
    finding_ids: BTreeSet<String>,
    edge_ids: BTreeSet<String>,
    limitations: Vec<String>,
}

fn select_pack_material(
    events: &[TraceEvent],
    external: &[ExternalEvidenceEvent],
    findings: &[BoundaryFinding],
    edges: &[EvidenceEdge],
    opts: &ForensicPackOpts,
    incident_graph: Option<&IncidentGraph>,
) -> PackSelection {
    let mut event_ids = BTreeSet::new();
    let mut external_ids = BTreeSet::new();
    let mut finding_ids = BTreeSet::new();
    let mut edge_ids = BTreeSet::new();
    let mut limitations = Vec::new();

    // Head + tail events by sequence/order in input.
    let (head_n, tail_n) =
        bounded_head_tail_counts(opts.max_events, opts.head_count, opts.tail_count);
    for e in events.iter().take(head_n) {
        event_ids.insert(e.id.clone());
    }
    if events.len() > head_n {
        for e in events.iter().rev().take(tail_n) {
            event_ids.insert(e.id.clone());
        }
    }

    let (external_head_n, external_tail_n) =
        bounded_head_tail_counts(opts.max_external, opts.head_count, opts.tail_count);
    for e in external.iter().take(external_head_n) {
        external_ids.insert(e.id.clone());
    }
    if external.len() > external_head_n {
        for e in external.iter().rev().take(external_tail_n) {
            external_ids.insert(e.id.clone());
        }
    }

    // Prefer high-severity findings first, then chronological.
    let mut ranked: Vec<&BoundaryFinding> = findings.iter().collect();
    ranked.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then(a.created_at.cmp(&b.created_at))
            .then(a.id.cmp(&b.id))
    });
    for f in ranked.iter().take(opts.max_findings) {
        finding_ids.insert(f.id.clone());
        for id in &f.evidence_event_ids {
            event_ids.insert(id.clone());
        }
        for id in &f.external_evidence_ids {
            external_ids.insert(id.clone());
        }
    }

    // Earliest signal + continuation evidence from graph.
    if let Some(graph) = incident_graph {
        if let Some(ref sig) = graph.earliest_signal {
            absorb_ref(
                &mut event_ids,
                &mut external_ids,
                &mut finding_ids,
                &sig.ref_id,
            );
        }
        if let Some(ref cont) = graph.continuation {
            absorb_ref(
                &mut event_ids,
                &mut external_ids,
                &mut finding_ids,
                &cont.initial_signal_id,
            );
            absorb_ref(
                &mut event_ids,
                &mut external_ids,
                &mut finding_ids,
                &cont.continuation_evidence_id,
            );
            if edges
                .iter()
                .any(|edge| edge.id == cont.continuation_evidence_id)
            {
                edge_ids.insert(cont.continuation_evidence_id.clone());
            }
        }
    }

    // Graph neighborhood: edges touching selected entities.
    let mut selected_entities: HashSet<String> = HashSet::new();
    selected_entities.extend(event_ids.iter().cloned());
    selected_entities.extend(external_ids.iter().cloned());
    selected_entities.extend(finding_ids.iter().cloned());

    for edge in edges {
        let touches =
            selected_entities.contains(&edge.from_id) || selected_entities.contains(&edge.to_id);
        if touches {
            edge_ids.insert(edge.id.clone());
            // Nearest neighbors
            absorb_ref(
                &mut event_ids,
                &mut external_ids,
                &mut finding_ids,
                &edge.from_id,
            );
            absorb_ref(
                &mut event_ids,
                &mut external_ids,
                &mut finding_ids,
                &edge.to_id,
            );
            selected_entities.insert(edge.from_id.clone());
            selected_entities.insert(edge.to_id.clone());
        }
    }

    // `absorb_ref` accepts bare typed references and tentatively places them
    // in each collection. Resolve those candidates against the actual inputs
    // before budgets and exact scope accounting.
    let valid_events: HashSet<&str> = events.iter().map(|event| event.id.as_str()).collect();
    let valid_external: HashSet<&str> = external.iter().map(|event| event.id.as_str()).collect();
    let valid_findings: HashSet<&str> =
        findings.iter().map(|finding| finding.id.as_str()).collect();
    event_ids.retain(|id| valid_events.contains(id.as_str()));
    external_ids.retain(|id| valid_external.contains(id.as_str()));
    finding_ids.retain(|id| valid_findings.contains(id.as_str()));

    // Enforce budgets while preserving cited material when possible.
    if event_ids.len() > opts.max_events {
        limitations.push(format!(
            "event_selection_exceeded_budget_{}_of_{}",
            event_ids.len(),
            opts.max_events
        ));
        // Keep cited by findings first, then head order from original list.
        let cited: HashSet<String> = findings
            .iter()
            .filter(|f| finding_ids.contains(&f.id))
            .flat_map(|f| f.evidence_event_ids.iter().cloned())
            .collect();
        let mut kept = BTreeSet::new();
        for id in &cited {
            if event_ids.contains(id) {
                kept.insert(id.clone());
            }
        }
        let remaining = opts.max_events.saturating_sub(kept.len());
        let (head, tail) = bounded_head_tail_counts(remaining, opts.head_count, opts.tail_count);
        for e in events
            .iter()
            .take(head)
            .chain(events.iter().rev().take(tail))
        {
            if event_ids.contains(&e.id) {
                kept.insert(e.id.clone());
            }
        }
        event_ids = kept;
    }
    if external_ids.len() > opts.max_external {
        limitations.push(format!(
            "external_selection_exceeded_budget_{}_of_{}",
            external_ids.len(),
            opts.max_external
        ));
        let cited: HashSet<String> = findings
            .iter()
            .filter(|f| finding_ids.contains(&f.id))
            .flat_map(|f| f.external_evidence_ids.iter().cloned())
            .collect();
        let mut kept = BTreeSet::new();
        for id in &cited {
            if external_ids.contains(id) {
                kept.insert(id.clone());
            }
        }
        let remaining = opts.max_external.saturating_sub(kept.len());
        let (head, tail) = bounded_head_tail_counts(remaining, opts.head_count, opts.tail_count);
        for e in external
            .iter()
            .take(head)
            .chain(external.iter().rev().take(tail))
        {
            if external_ids.contains(&e.id) {
                kept.insert(e.id.clone());
            }
        }
        external_ids = kept;
    }

    PackSelection {
        event_ids,
        external_ids,
        finding_ids,
        edge_ids,
        limitations,
    }
}

fn absorb_ref(
    events: &mut BTreeSet<String>,
    external: &mut BTreeSet<String>,
    findings: &mut BTreeSet<String>,
    id: &str,
) {
    if let Some(rest) = id.strip_prefix("event:") {
        events.insert(rest.to_string());
    } else if let Some(rest) = id.strip_prefix("external:") {
        external.insert(rest.to_string());
    } else if let Some(rest) = id.strip_prefix("finding:") {
        findings.insert(rest.to_string());
    } else {
        // Bare id — try all sets (selection filters by presence later).
        events.insert(id.to_string());
        external.insert(id.to_string());
        findings.insert(id.to_string());
    }
}

fn severity_rank(s: crate::boundary::FindingSeverity) -> u8 {
    match s {
        crate::boundary::FindingSeverity::Critical => 4,
        crate::boundary::FindingSeverity::High => 3,
        crate::boundary::FindingSeverity::Warn => 2,
        crate::boundary::FindingSeverity::Info => 1,
    }
}

fn bounded_head_tail_counts(max: usize, head: usize, tail: usize) -> (usize, usize) {
    let requested = head.saturating_add(tail);
    if requested <= max {
        return (head, tail);
    }
    if max == 0 || requested == 0 {
        return (0, 0);
    }
    let mut bounded_head = max.saturating_mul(head) / requested;
    if head > 0 && bounded_head == 0 {
        bounded_head = 1;
    }
    if tail > 0 && bounded_head == max && max > 1 {
        bounded_head -= 1;
    }
    (bounded_head, max - bounded_head)
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

/// Keys whose string values are free-form content eligible for user patterns.
fn is_freeform_key(key: &str) -> bool {
    matches!(
        key,
        "summary"
            | "recommendation"
            | "claim"
            | "destination"
            | "object"
            | "command"
            | "metadata"
            | "reasons"
            | "coverage_gaps"
            | "fingerprints"
            | "label"
            | "title"
            | "note"
            | "failure"
            | "technique"
            | "principal"
            | "attributes"
            | "limitations"
            | "citation_unavailable_reason"
    )
}

/// Structural values that must never be rewritten by user patterns.
fn is_structural_value(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    // Citation pointers and schema ids.
    if value.starts_with("event:")
        || value.starts_with("external:")
        || value.starts_with("finding:")
        || value.starts_with("blackbox.")
        || value.starts_with("sha256:")
        || value.starts_with("[REDACTED:")
    {
        return true;
    }
    // Known enum / strategy tokens.
    matches!(
        value,
        "info"
            | "warn"
            | "high"
            | "critical"
            | "deterministic"
            | "human"
            | "model"
            | "deterministic_detector"
            | "head_tail_cited_graph_neighborhood"
            | "boundary.violation"
            | "behavior.transition"
            | "success"
            | "failure"
            | "denied"
            | "unknown"
            | "confirmed"
            | "strongly_correlated"
            | "weakly_correlated"
    )
}

fn redact_str(s: &str, opts: &ForensicPackOpts) -> String {
    let mut redactor = StablePackRedactor::new(opts);
    let mut out = redactor.redact_freeform(s);
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

    fn token_for(&mut self, secret: &str) -> String {
        if let Some(existing) = self.replacements.get(secret) {
            return existing.clone();
        }
        let token = match &self.opts.secret_token_mode {
            SecretTokenMode::Unlinkable => {
                self.next_replacement += 1;
                format!("[REDACTED:{}:{:04}]", self.namespace, self.next_replacement)
            }
            SecretTokenMode::ProjectCorrelatable { key } => {
                let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
                    return "[REDACTED:hmac-error]".into();
                };
                mac.update(secret.as_bytes());
                let digest = mac.finalize().into_bytes();
                format!("[REDACTED:hmac:{}]", hex::encode(&digest[..8]))
            }
        };
        self.replacements.insert(secret.to_string(), token.clone());
        token
    }

    /// Redact secrets + user patterns in free-form text.
    fn redact_freeform(&mut self, value: &str) -> String {
        self.redact_with_user_patterns(value, true)
    }

    fn redact_with_user_patterns(&mut self, value: &str, apply_user_patterns: bool) -> String {
        if is_structural_value(value) && !apply_user_patterns {
            // Still strip embedded secrets that look like API keys inside structural ids.
        }
        let mut spans = pack_scanner().find_spans(value);
        if apply_user_patterns {
            for pattern in &self.opts.redact_patterns {
                if pattern.is_empty() {
                    continue;
                }
                // User patterns must not target pure structural tokens alone when
                // the entire value is structural (e.g. pattern "schema").
                if is_structural_value(value) && value == pattern.as_str() {
                    continue;
                }
                spans.extend(
                    value
                        .match_indices(pattern)
                        .map(|(start, matched)| (start, start + matched.len())),
                );
            }
        }
        spans.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| right.1.cmp(&left.1)));
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for span in spans {
            if span.0 >= span.1 || span.1 > value.len() {
                continue;
            }
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
            // Never rewrite pure citation prefixes mid-string incorrectly; if span
            // is exactly a structural token, skip.
            if is_structural_value(secret) {
                output.push_str(secret);
            } else {
                let replacement = self.token_for(secret);
                output.push_str(&replacement);
            }
            cursor = end;
        }
        output.push_str(&value[cursor..]);
        output
    }
}

fn sanitize_json_value(
    value: &mut serde_json::Value,
    redactor: &mut StablePackRedactor<'_>,
    parent_key: Option<&str>,
    freeform_container: bool,
) {
    match value {
        serde_json::Value::String(text) => {
            let freeform = freeform_container || parent_key.is_some_and(is_freeform_key);
            *text = if freeform {
                redactor.redact_freeform(text)
            } else {
                text.clone()
            };
        }
        serde_json::Value::Array(items) => {
            for item in items {
                sanitize_json_value(item, redactor, parent_key, freeform_container);
            }
        }
        serde_json::Value::Object(map) => {
            let entries = std::mem::take(map);
            let child_freeform_container = freeform_container
                || parent_key.is_some_and(|key| {
                    matches!(key, "metadata" | "attributes" | "labels" | "extensions")
                });
            for (key, mut child) in entries {
                // Object keys are structural at every depth. They are never
                // rewritten, including operator-controlled metadata maps.
                sanitize_json_value(&mut child, redactor, Some(&key), child_freeform_container);
                map.insert(key, child);
            }
        }
        _ => {}
    }
}

fn sanitize_pack_content(
    pack: &mut ForensicPack,
    opts: &ForensicPackOpts,
) -> Result<(), Vec<String>> {
    let existing_hash = pack.pack_hash.clone();
    let mut value =
        serde_json::to_value(&*pack).map_err(|e| vec![format!("serialize_pack:{e}")])?;
    let mut structural_errors = Vec::new();
    reject_secret_structure(&value, "$", None, false, &mut structural_errors);
    if !structural_errors.is_empty() {
        return Err(structural_errors);
    }
    let mut redactor = StablePackRedactor::new(opts);
    sanitize_json_value(&mut value, &mut redactor, None, false);
    let mut restored: ForensicPack = serde_json::from_value(value).map_err(|e| {
        vec![format!(
            "typed_redaction_corrupted_pack_schema:{e}; user patterns must not mutate structure"
        )]
    })?;
    restored.pack_hash = existing_hash;
    *pack = restored;
    Ok(())
}

fn reject_secret_structure(
    value: &serde_json::Value,
    path: &str,
    parent_key: Option<&str>,
    freeform_container: bool,
    errors: &mut Vec<String>,
) {
    match value {
        serde_json::Value::String(text) => {
            let freeform = freeform_container || parent_key.is_some_and(is_freeform_key);
            if !freeform && !pack_scanner().find_spans(text).is_empty() {
                errors.push(format!("secret_detected_in_structural_value:{path}"));
            }
        }
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_secret_structure(
                    value,
                    &format!("{path}[{index}]"),
                    parent_key,
                    freeform_container,
                    errors,
                );
            }
        }
        serde_json::Value::Object(map) => {
            let child_freeform_container = freeform_container
                || parent_key.is_some_and(|key| {
                    matches!(key, "metadata" | "attributes" | "labels" | "extensions")
                });
            for (key, value) in map {
                if !pack_scanner().find_spans(key).is_empty() {
                    errors.push(format!(
                        "secret_detected_in_structural_field_name:{path}.<?>"
                    ));
                }
                reject_secret_structure(
                    value,
                    &format!(
                        "{path}.{}",
                        if pack_scanner().find_spans(key).is_empty() {
                            key.as_str()
                        } else {
                            "<?>"
                        }
                    ),
                    Some(key),
                    child_freeform_container,
                    errors,
                );
            }
        }
        _ => {}
    }
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
                // Preserve keys.
                out.insert(k.clone(), redact_value(val, opts));
            }
            serde_json::Value::Object(out)
        }
        other => other.clone(),
    }
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
            citation_unavailable: None,
            citation_unavailable_reason: None,
        });
        sanitize_pack_content(&mut candidate, &ForensicPackOpts::default())?;
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
            citation_unavailable: None,
            citation_unavailable_reason: None,
        });
        candidate
            .coverage_gaps
            .push("model_analysis_failure".into());
        sanitize_pack_content(&mut candidate, &ForensicPackOpts::default())?;
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
            citation_unavailable: None,
            citation_unavailable_reason: None,
        });
    }
    if errs.is_empty() {
        sanitize_pack_content(&mut candidate, &ForensicPackOpts::default())?;
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
        if claim.citations.is_empty() && !claim.citation_unavailable.unwrap_or(false) {
            errs.push(format!("claim has no citations: {}", claim.claim));
            continue;
        }
        if claim.citation_unavailable.unwrap_or(false)
            && claim
                .citation_unavailable_reason
                .as_ref()
                .is_none_or(|r| r.is_empty())
        {
            errs.push(format!(
                "claim marks citation_unavailable without reason: {}",
                claim.claim
            ));
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
            decision: None,
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
            decision: None,
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
        let before = pack.clone();
        let errors = sanitize_pack_content(&mut pack, &ForensicPackOpts::default())
            .expect_err("structural secret values must fail closed, not be rewritten");
        assert!(errors
            .iter()
            .any(|error| error.contains("secret_detected_in_structural_value")));
        assert_eq!(pack, before, "failed typed redaction must not mutate input");
    }

    #[test]
    fn citation_complete_includes_mid_stream_evidence() {
        // Many events; cited one is in the middle (outside naive first-N).
        let mut events = Vec::new();
        for i in 0..50 {
            let mut ev = TraceEvent::new("r1", EventSource::Tool, "tool.call");
            ev.id = format!("ev-{i:03}");
            ev.sequence = i as u64;
            events.push(ev);
        }
        let cited_id = "ev-025".to_string();
        let f = BoundaryFinding {
            schema: "blackbox.boundary.finding/v1".into(),
            id: "find-mid".into(),
            run_id: "r1".into(),
            kind: FindingKind::BoundaryViolation,
            detector: "test".into(),
            severity: FindingSeverity::High,
            summary: "mid".into(),
            evidence_event_ids: vec![cited_id.clone()],
            external_evidence_ids: vec![],
            token: None,
            disposition: None,
            recommendation: None,
            created_at: Utc::now(),
            confidence_note: "deterministic_detector".into(),
            decision: None,
        };
        let pack = build_forensic_pack(
            "r1",
            None,
            &events,
            &[],
            std::slice::from_ref(&f),
            &[],
            &ForensicPackOpts {
                max_events: 20,
                head_count: 5,
                tail_count: 5,
                ..Default::default()
            },
        );
        let scope = pack.scope.as_ref().expect("scope");
        assert_eq!(scope.events_total, 50);
        assert!(scope.events_included <= 20);
        assert_eq!(scope.strategy, SELECTION_STRATEGY_HEAD_TAIL_CITED_GRAPH);
        assert_eq!(pack.event_window.first().unwrap()["id"], "ev-000");
        assert_eq!(pack.event_window.last().unwrap()["id"], "ev-049");
        assert!(
            pack.original_pointers
                .iter()
                .any(|p| p == &format!("event:{cited_id}")),
            "cited mid-stream event must be included: {:?}",
            pack.original_pointers
        );
        validate_claim_citations(&pack).unwrap();
        assert_eq!(pack.findings.len(), 1);
    }

    #[test]
    fn typed_redaction_preserves_field_names_and_rejects_panic() {
        let ev = TraceEvent::new("r1", EventSource::Tool, "tool.call");
        let pack = build_forensic_pack_result(
            "r1",
            None,
            &[ev],
            &[],
            &[],
            &[],
            &ForensicPackOpts {
                // Patterns that look like structural tokens must not corrupt schema.
                redact_patterns: vec![
                    "schema".into(),
                    "id".into(),
                    "run_id".into(),
                    "finding".into(),
                ],
                ..Default::default()
            },
            None,
        )
        .expect("user patterns must not fail pack construction");
        let v = serde_json::to_value(&pack).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("schema"));
        assert!(obj.contains_key("run_id"));
        assert!(obj.contains_key("findings"));
        assert_eq!(pack.schema, FORENSIC_PACK_SCHEMA);
        validate_forensic_pack(&pack).unwrap();
    }

    #[test]
    fn hmac_secret_tokens_correlate_across_packs() {
        let secret = "password=super-secret-value";
        let key = b"project-hmac-key-32-bytes-long!!".to_vec();
        let mut ev1 = TraceEvent::new("r1", EventSource::Tool, "tool.call");
        ev1.metadata.insert(
            "command".into(),
            serde_json::json!(format!("echo {secret}")),
        );
        let mut ev2 = TraceEvent::new("r2", EventSource::Tool, "tool.call");
        ev2.metadata
            .insert("command".into(), serde_json::json!(format!("run {secret}")));
        let opts = ForensicPackOpts {
            secret_token_mode: SecretTokenMode::ProjectCorrelatable { key },
            redact_patterns: vec!["password=".into()],
            ..Default::default()
        };
        let p1 = build_forensic_pack("r1", None, &[ev1], &[], &[], &[], &opts);
        let p2 = build_forensic_pack("r2", None, &[ev2], &[], &[], &[], &opts);
        let s1 = serde_json::to_string(&p1).unwrap();
        let s2 = serde_json::to_string(&p2).unwrap();
        assert!(!s1.contains(secret) && !s2.contains(secret));
        // Extract HMAC tokens.
        let re = regex::Regex::new(r"\[REDACTED:hmac:[0-9a-f]+\]").unwrap();
        let t1 = re.find(&s1).map(|m| m.as_str().to_string());
        let t2 = re.find(&s2).map(|m| m.as_str().to_string());
        assert!(t1.is_some() && t2.is_some());
        assert_eq!(t1, t2, "same secret must share HMAC token across packs");
    }

    #[test]
    fn unlinkable_tokens_differ_across_packs() {
        let secret = "password=another-secret";
        let mut ev1 = TraceEvent::new("r1", EventSource::Tool, "tool.call");
        ev1.metadata
            .insert("command".into(), serde_json::json!(secret));
        let mut ev2 = TraceEvent::new("r2", EventSource::Tool, "tool.call");
        ev2.metadata
            .insert("command".into(), serde_json::json!(secret));
        let opts = ForensicPackOpts {
            secret_token_mode: SecretTokenMode::Unlinkable,
            redact_patterns: vec!["password=".into()],
            ..Default::default()
        };
        let p1 = build_forensic_pack("r1", None, &[ev1], &[], &[], &[], &opts);
        let p2 = build_forensic_pack("r2", None, &[ev2], &[], &[], &[], &opts);
        let s1 = serde_json::to_string(&p1).unwrap();
        let s2 = serde_json::to_string(&p2).unwrap();
        let re = regex::Regex::new(r"\[REDACTED:[0-9a-f]{8}:\d{4}\]").unwrap();
        let t1 = re.find(&s1).map(|m| m.as_str().to_string());
        let t2 = re.find(&s2).map(|m| m.as_str().to_string());
        assert!(t1.is_some() && t2.is_some());
        assert_ne!(t1, t2, "unlinkable mode must not correlate across packs");
    }

    #[test]
    fn scope_reports_exact_totals() {
        let events: Vec<_> = (0..10)
            .map(|i| {
                let mut e = TraceEvent::new("r1", EventSource::Tool, "tool.call");
                e.id = format!("e{i}");
                e
            })
            .collect();
        let pack = build_forensic_pack(
            "r1",
            None,
            &events,
            &[],
            &[],
            &[],
            &ForensicPackOpts {
                max_events: 4,
                head_count: 2,
                tail_count: 2,
                ..Default::default()
            },
        );
        let scope = pack.scope.unwrap();
        assert_eq!(scope.events_total, 10);
        assert_eq!(scope.events_included, 4);
        assert!(scope
            .limitations
            .iter()
            .any(|l| l.contains("truncated") || l.contains("events")));
    }
}
