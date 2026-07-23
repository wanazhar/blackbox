//! Deterministic boundary violation and behavior-transition detectors (1.7 Phase E).

#![allow(missing_docs)]
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::event::{Confidence, EventSource, EventStatus, SideEffect, TraceEvent};
use crate::evidence::{EvidenceAction, EvidenceIntegrity, EvidenceOutcome, ExternalEvidenceEvent};

use super::contract::BoundaryContract;
use super::finding::{
    DecisionInput, EvidenceIntegrityClass, FindingDecision, ObservedEffect, ViolationState,
};
use super::selector::{match_path_selector, observation_looks_public_network, ResourceSelector};
use super::vocab::Disposition;

/// Severity recommendation (defined in finding calibration module).
pub use super::finding::FindingSeverity;

/// Schema for boundary findings.
pub const BOUNDARY_FINDING_SCHEMA: &str = "blackbox.boundary.finding/v1";

/// Finding class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    BoundaryViolation,
    BehaviorTransition,
}

impl FindingKind {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BoundaryViolation => "boundary.violation",
            Self::BehaviorTransition => "behavior.transition",
        }
    }
}

/// Deterministic boundary/behavior finding with evidence citations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundaryFinding {
    pub schema: String,
    pub id: String,
    pub run_id: String,
    pub kind: FindingKind,
    /// Detector name (e.g. `unexpected_destination`, `credential_access`).
    pub detector: String,
    pub severity: FindingSeverity,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_evidence_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<Disposition>,
    /// Response recommendation (never auto-enforced).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Algorithm repeatability note only — not confidence evidence (1.8).
    #[serde(default)]
    pub confidence_note: String,
    /// Calibrated decision object (1.8). Additive; older packs omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<FindingDecision>,
}

impl BoundaryFinding {
    fn new(
        run_id: impl Into<String>,
        kind: FindingKind,
        detector: impl Into<String>,
        severity: FindingSeverity,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            schema: BOUNDARY_FINDING_SCHEMA.into(),
            id: format!("find-{}", Uuid::new_v4()),
            run_id: run_id.into(),
            kind,
            detector: detector.into(),
            severity,
            summary: summary.into(),
            evidence_event_ids: Vec::new(),
            external_evidence_ids: Vec::new(),
            token: None,
            disposition: None,
            recommendation: None,
            created_at: Utc::now(),
            // Repeatability of the detector algorithm — not evidence confidence.
            confidence_note: "deterministic_detector".into(),
            decision: None,
        }
    }

    fn apply_decision(&mut self, decision: FindingDecision) {
        self.severity = decision.severity;
        self.disposition = Some(decision.policy_disposition);
        self.decision = Some(decision);
    }

    /// Convert to a first-class trace event for persistence.
    pub fn to_trace_event(&self, sequence: u64) -> TraceEvent {
        let mut ev = TraceEvent::new(&self.run_id, EventSource::System, self.kind.as_str());
        ev.sequence = sequence;
        ev.started_at = self.created_at;
        ev.status = EventStatus::Success;
        ev.side_effect = SideEffect::None;
        ev.metadata
            .insert("finding_id".into(), serde_json::json!(self.id));
        ev.metadata
            .insert("detector".into(), serde_json::json!(self.detector));
        ev.metadata
            .insert("severity".into(), serde_json::json!(self.severity.as_str()));
        ev.metadata
            .insert("summary".into(), serde_json::json!(self.summary));
        if let Some(ref t) = self.token {
            ev.metadata.insert("token".into(), serde_json::json!(t));
        }
        if !self.evidence_event_ids.is_empty() {
            ev.metadata.insert(
                "evidence_event_ids".into(),
                serde_json::json!(self.evidence_event_ids),
            );
        }
        if !self.external_evidence_ids.is_empty() {
            ev.metadata.insert(
                "external_evidence_ids".into(),
                serde_json::json!(self.external_evidence_ids),
            );
        }
        ev
    }
}

/// Inputs for deterministic detection.
#[derive(Debug, Clone, Default)]
pub struct DetectInputs<'a> {
    pub run_id: &'a str,
    pub contract: Option<&'a BoundaryContract>,
    pub events: &'a [TraceEvent],
    pub external: &'a [ExternalEvidenceEvent],
}

/// Run all deterministic detectors. Model-assisted interpretation is out of scope.
pub fn detect_boundary_findings(inputs: DetectInputs<'_>) -> Vec<BoundaryFinding> {
    let mut out = Vec::new();
    out.extend(detect_unexpected_destinations(&inputs));
    out.extend(detect_credential_activity(&inputs));
    out.extend(detect_public_network_probe(&inputs));
    out.extend(detect_package_install(&inputs));
    out.extend(detect_privilege_signals(&inputs));
    out.extend(detect_poisoned_material(&inputs));
    out.extend(detect_persistence_after_exit(&inputs));
    out.extend(detect_abnormal_fanout(&inputs));
    out.extend(detect_deceptive_telemetry(&inputs));
    out.extend(detect_behavior_transitions(&inputs));
    normalize_finding_times(&inputs, &mut out);
    out.extend(detect_execution_after_violation(&inputs, &out));
    // Sort: critical first, preserve earliest evidence by retaining insertion order within severity.
    out.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then(a.created_at.cmp(&b.created_at))
    });
    out
}

fn external_time(event: &ExternalEvidenceEvent) -> DateTime<Utc> {
    event
        .occurred_at
        .or(event.observed_at)
        .unwrap_or(event.ingested_at)
}

fn normalize_finding_times(inputs: &DetectInputs<'_>, findings: &mut [BoundaryFinding]) {
    for finding in findings {
        // This transition becomes provable only at the continued activity, not
        // at the earlier terminal marker also cited by the finding.
        if matches!(
            finding.detector.as_str(),
            "persistence_after_exit" | "abnormal_fanout"
        ) {
            continue;
        }
        let event_times = finding.evidence_event_ids.iter().filter_map(|id| {
            inputs
                .events
                .iter()
                .find(|event| event.id == *id)
                .map(|event| event.started_at)
        });
        let external_times = finding.external_evidence_ids.iter().filter_map(|id| {
            inputs
                .external
                .iter()
                .find(|event| event.id == *id)
                .map(external_time)
        });
        if let Some(at) = event_times.chain(external_times).min() {
            finding.created_at = at;
        }
    }
}

fn severity_rank(s: FindingSeverity) -> u8 {
    match s {
        FindingSeverity::Critical => 4,
        FindingSeverity::High => 3,
        FindingSeverity::Warn => 2,
        FindingSeverity::Info => 1,
    }
}

fn disposition_of(contract: Option<&BoundaryContract>, token: &str) -> Disposition {
    contract
        .map(|c| c.disposition_of(token))
        .unwrap_or(Disposition::Unknown)
}

fn is_hard_or_approval(d: Disposition) -> bool {
    matches!(
        d,
        Disposition::HardProhibition | Disposition::ApprovalRequired
    )
}

fn destination_allowed(contract: Option<&BoundaryContract>, dest: &str) -> bool {
    let Some(c) = contract else {
        return false;
    };
    if c.allowed.network_allows(dest).is_allow() {
        return true;
    }
    // Disposition on the raw destination string (class token form).
    c.disposition_of(dest) == Disposition::Allowed
}

fn detect_unexpected_destinations(inputs: &DetectInputs<'_>) -> Vec<BoundaryFinding> {
    let mut out = Vec::new();
    let contract = inputs.contract;
    for ev in inputs.external {
        let Some(ref dest) = ev.destination else {
            continue;
        };
        let looks_public = observation_looks_public_network(dest)
            || dest == "public_network"
            || dest.contains("githubusercontent");
        let allowed = destination_allowed(contract, dest);
        let d = disposition_of(contract, "public_network");
        if looks_public && !allowed && is_hard_or_approval(d) {
            let integrity = EvidenceIntegrityClass::from_evidence(ev.integrity);
            let decision = FindingDecision::calibrate(DecisionInput {
                observation: &format!("destination {dest}"),
                policy_disposition: d,
                evidence_integrity: integrity,
                identity_confidence: identity_confidence_from_external(ev),
                correlation_confidence: correlation_from_external(ev),
                observed_effect: ObservedEffect::NetworkEgress,
                reasons: &[],
                force_violation_state: None,
            });
            let mut f = BoundaryFinding::new(
                inputs.run_id,
                FindingKind::BoundaryViolation,
                "unexpected_destination",
                decision.severity,
                format!("unexpected destination {dest}"),
            );
            f.external_evidence_ids.push(ev.id.clone());
            f.token = Some("public_network".into());
            f.recommendation =
                Some("investigate egress path; do not treat task success as containment".into());
            f.apply_decision(decision);
            out.push(f);
        }
        // Explicit prohibited class-token destinations only (exact), not substring.
        if let Some(c) = contract {
            for p in &c.prohibited {
                // Exact class-token match, or typed domain selector equality via disposition token.
                if dest == p.as_str() {
                    let mut f = BoundaryFinding::new(
                        inputs.run_id,
                        FindingKind::BoundaryViolation,
                        "prohibited_destination_token",
                        FindingSeverity::High,
                        format!("destination is prohibited token {p:?}"),
                    );
                    f.external_evidence_ids.push(ev.id.clone());
                    f.token = Some(p.clone());
                    f.disposition = Some(Disposition::HardProhibition);
                    out.push(f);
                }
            }
        }
    }
    // Tool events with network-ish metadata.
    for ev in inputs.events {
        if let Some(dest) = ev
            .metadata
            .get("destination")
            .or_else(|| ev.metadata.get("url"))
            .and_then(|v| v.as_str())
        {
            let d = disposition_of(contract, "public_network");
            if observation_looks_public_network(dest) && is_hard_or_approval(d) {
                let allowed = destination_allowed(contract, dest);
                if !allowed {
                    let decision = FindingDecision::calibrate(DecisionInput {
                        observation: &format!("tool/network destination {dest}"),
                        policy_disposition: d,
                        evidence_integrity: EvidenceIntegrityClass::Unverified,
                        identity_confidence: Confidence::Unknown,
                        correlation_confidence: Confidence::WeaklyCorrelated,
                        observed_effect: ObservedEffect::NetworkEgress,
                        reasons: &[],
                        force_violation_state: None,
                    });
                    let mut f = BoundaryFinding::new(
                        inputs.run_id,
                        FindingKind::BoundaryViolation,
                        "unexpected_destination",
                        decision.severity,
                        format!("tool/network destination {dest}"),
                    );
                    f.evidence_event_ids.push(ev.id.clone());
                    f.token = Some("public_network".into());
                    f.apply_decision(decision);
                    out.push(f);
                }
            }
        }
    }
    out
}

fn identity_confidence_from_external(ev: &ExternalEvidenceEvent) -> Confidence {
    if ev.identity.trace_id.is_some() || ev.identity.run_id.is_some() || ev.linked_run_id.is_some()
    {
        Confidence::StronglyCorrelated
    } else if ev.identity.principal.is_some() || ev.identity.workload.is_some() {
        Confidence::WeaklyCorrelated
    } else {
        Confidence::Unknown
    }
}

fn correlation_from_external(ev: &ExternalEvidenceEvent) -> Confidence {
    match ev.integrity {
        EvidenceIntegrity::SignedVerified => Confidence::Confirmed,
        EvidenceIntegrity::HashOk => Confidence::StronglyCorrelated,
        EvidenceIntegrity::Transformed => Confidence::WeaklyCorrelated,
        EvidenceIntegrity::Unverified | EvidenceIntegrity::SignedInvalid => {
            if ev.linked_run_id.is_some() {
                Confidence::WeaklyCorrelated
            } else {
                Confidence::Unknown
            }
        }
    }
}

/// Credential-related path prefixes matched as typed path selectors (not free-form docs).
fn credential_path_selectors() -> [ResourceSelector; 4] {
    [
        ResourceSelector::PathPrefix {
            value: "/.ssh".into(),
        },
        ResourceSelector::PathPrefix {
            value: "/.aws".into(),
        },
        ResourceSelector::PathPrefix {
            value: "/credentials".into(),
        },
        ResourceSelector::PathExact {
            value: "id_rsa".into(),
        },
    ]
}

fn path_looks_like_credential_material(path: &str) -> bool {
    let p = path.trim();
    if p.is_empty() {
        return false;
    }
    // Home-relative forms.
    let candidates = [
        p.to_string(),
        p.trim_start_matches('~').to_string(),
        if let Some(rest) = p.strip_prefix("~/") {
            format!("/{rest}")
        } else {
            p.to_string()
        },
    ];
    for cand in &candidates {
        // Match common suffixes via path_prefix against parent segments.
        if cand.contains("/.ssh/")
            || cand.ends_with("/.ssh")
            || cand.contains("/.aws/")
            || cand.ends_with("/.aws")
            || cand.ends_with("/id_rsa")
            || cand.ends_with("id_rsa")
            || cand.contains("/credentials/")
            || cand.ends_with("/credentials")
        {
            // Still require path-shaped observations (has path separator or exact key file).
            if cand.contains('/') || cand == "id_rsa" {
                // Exclude pure documentation sentences.
                if cand.contains(' ') {
                    return false;
                }
                return true;
            }
        }
        for sel in &credential_path_selectors() {
            if match_path_selector(sel, cand).is_allow() {
                return true;
            }
        }
    }
    false
}

fn detect_credential_activity(inputs: &DetectInputs<'_>) -> Vec<BoundaryFinding> {
    let mut out = Vec::new();
    let d = disposition_of(inputs.contract, "production_credentials");
    for ev in inputs.external {
        if matches!(ev.action, EvidenceAction::CredentialAccess) {
            let integrity = EvidenceIntegrityClass::from_evidence(ev.integrity);
            // Allowed synthetic credential access is not a violation.
            let decision = FindingDecision::calibrate(DecisionInput {
                observation: "credential access observed in external evidence",
                policy_disposition: d,
                evidence_integrity: integrity,
                identity_confidence: identity_confidence_from_external(ev),
                correlation_confidence: correlation_from_external(ev),
                observed_effect: ObservedEffect::CredentialUse,
                reasons: &[],
                force_violation_state: None,
            });
            // Info findings for allowed activity are useful but should not be violations.
            if matches!(decision.violation_state, ViolationState::Allowed) {
                let mut f = BoundaryFinding::new(
                    inputs.run_id,
                    FindingKind::BehaviorTransition,
                    "credential_access_allowed",
                    decision.severity,
                    "allowed credential access observed (not a violation)",
                );
                f.external_evidence_ids.push(ev.id.clone());
                f.token = Some("production_credentials".into());
                f.apply_decision(decision);
                out.push(f);
                continue;
            }
            let mut f = BoundaryFinding::new(
                inputs.run_id,
                FindingKind::BoundaryViolation,
                "credential_access",
                decision.severity,
                "credential access observed in external evidence",
            );
            f.external_evidence_ids.push(ev.id.clone());
            f.token = Some("production_credentials".into());
            f.recommendation = Some("rotate if production; preserve receipt chain".into());
            f.apply_decision(decision);
            out.push(f);
        }
    }
    for ev in inputs.events {
        let path = ev
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let tool = ev
            .metadata
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let kind = ev.kind.as_str();
        // Documentation / free-form text mentions are ambiguous, not verified reads.
        let is_doc_or_text = kind == "message" || kind == "assistant" || kind == "thinking";
        let path_hit = path_looks_like_credential_material(path);
        let tool_hit = tool == "secret" || tool.ends_with("_secret") || tool == "read_secret";
        if !path_hit && !tool_hit {
            // Substring mention in prose (e.g. path field holding a sentence).
            if path.contains(".ssh") || path.contains("id_rsa") || path.contains(".aws") {
                let decision = FindingDecision::calibrate(DecisionInput {
                    observation: &format!("documentation-like credential mention path={path}"),
                    policy_disposition: d,
                    evidence_integrity: EvidenceIntegrityClass::Unverified,
                    identity_confidence: Confidence::Unknown,
                    correlation_confidence: Confidence::Unknown,
                    observed_effect: ObservedEffect::None,
                    reasons: &[],
                    force_violation_state: Some(ViolationState::Ambiguous),
                });
                let mut f = BoundaryFinding::new(
                    inputs.run_id,
                    FindingKind::BehaviorTransition,
                    "credential_path_mention",
                    decision.severity,
                    format!("credential path mentioned in text path={path}"),
                );
                f.evidence_event_ids.push(ev.id.clone());
                f.token = Some("production_credentials".into());
                f.apply_decision(decision);
                out.push(f);
            }
            continue;
        }
        if is_doc_or_text && !tool_hit {
            let decision = FindingDecision::calibrate(DecisionInput {
                observation: &format!("documentation mention of credential path={path}"),
                policy_disposition: d,
                evidence_integrity: EvidenceIntegrityClass::Unverified,
                identity_confidence: Confidence::Unknown,
                correlation_confidence: Confidence::Unknown,
                observed_effect: ObservedEffect::None,
                reasons: &[],
                force_violation_state: Some(ViolationState::Ambiguous),
            });
            let mut f = BoundaryFinding::new(
                inputs.run_id,
                FindingKind::BehaviorTransition,
                "credential_path_mention",
                decision.severity,
                format!("credential path mentioned in documentation path={path}"),
            );
            f.evidence_event_ids.push(ev.id.clone());
            f.token = Some("production_credentials".into());
            f.apply_decision(decision);
            out.push(f);
            continue;
        }
        // Verified-looking filesystem / tool access.
        let decision = FindingDecision::calibrate(DecisionInput {
            observation: &format!("credential material access path={path} tool={tool}"),
            policy_disposition: d,
            evidence_integrity: EvidenceIntegrityClass::Unverified,
            identity_confidence: Confidence::WeaklyCorrelated,
            correlation_confidence: Confidence::StronglyCorrelated,
            observed_effect: ObservedEffect::CredentialUse,
            reasons: &[],
            force_violation_state: None,
        });
        let mut f = BoundaryFinding::new(
            inputs.run_id,
            FindingKind::BoundaryViolation,
            "credential_path_access",
            decision.severity,
            format!("possible credential material access path={path} tool={tool}"),
        );
        f.evidence_event_ids.push(ev.id.clone());
        f.token = Some("production_credentials".into());
        f.apply_decision(decision);
        out.push(f);
    }
    out
}

fn detect_public_network_probe(inputs: &DetectInputs<'_>) -> Vec<BoundaryFinding> {
    let mut out = Vec::new();
    for ev in inputs.external {
        if matches!(
            ev.action,
            EvidenceAction::NetworkConnect
                | EvidenceAction::DnsQuery
                | EvidenceAction::ProxyDeny
                | EvidenceAction::HttpRequest
        ) && matches!(
            ev.outcome,
            EvidenceOutcome::Denied | EvidenceOutcome::Failure
        ) {
            let mut f = BoundaryFinding::new(
                inputs.run_id,
                FindingKind::BehaviorTransition,
                "boundary_probing",
                FindingSeverity::Warn,
                format!(
                    "boundary probe-like {} outcome={}",
                    ev.action.as_str(),
                    ev.outcome.as_str()
                ),
            );
            f.external_evidence_ids.push(ev.id.clone());
            f.recommendation = Some("review whether probing is authorized research".into());
            out.push(f);
        }
    }
    out
}

fn detect_package_install(inputs: &DetectInputs<'_>) -> Vec<BoundaryFinding> {
    let mut out = Vec::new();
    let d = disposition_of(inputs.contract, "package_install");
    if !is_hard_or_approval(d) && !matches!(d, Disposition::Unknown) {
        return out;
    }
    for ev in inputs.external {
        if matches!(ev.action, EvidenceAction::PackageInstall) {
            let mut f = BoundaryFinding::new(
                inputs.run_id,
                FindingKind::BoundaryViolation,
                "package_install",
                FindingSeverity::High,
                "package install observed",
            );
            f.external_evidence_ids.push(ev.id.clone());
            f.token = Some("package_install".into());
            f.disposition = Some(d);
            out.push(f);
        }
    }
    for ev in inputs.events {
        if ev.kind == "tool.call" {
            let cmd = ev
                .metadata
                .get("input")
                .and_then(|v| v.get("command"))
                .and_then(|v| v.as_str())
                .or_else(|| ev.metadata.get("command").and_then(|v| v.as_str()))
                .unwrap_or("");
            if cmd.contains("pip install")
                || cmd.contains("npm install")
                || cmd.contains("apt-get")
                || cmd.contains("cargo install")
            {
                let mut f = BoundaryFinding::new(
                    inputs.run_id,
                    FindingKind::BoundaryViolation,
                    "package_install",
                    FindingSeverity::High,
                    format!("package install command: {cmd}"),
                );
                f.evidence_event_ids.push(ev.id.clone());
                f.token = Some("package_install".into());
                f.disposition = Some(d);
                out.push(f);
            }
        }
    }
    out
}

fn detect_privilege_signals(inputs: &DetectInputs<'_>) -> Vec<BoundaryFinding> {
    let mut out = Vec::new();
    for ev in inputs.events {
        let cmd = ev
            .metadata
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if cmd.contains("sudo ")
            || cmd.contains("chmod 777")
            || cmd.contains("setuid")
            || cmd.contains("nsenter")
        {
            let mut f = BoundaryFinding::new(
                inputs.run_id,
                FindingKind::BehaviorTransition,
                "privilege_capability_gain",
                FindingSeverity::High,
                format!("privilege-related command: {cmd}"),
            );
            f.evidence_event_ids.push(ev.id.clone());
            out.push(f);
        }
    }
    out
}

fn attribute_token<'a>(event: &'a ExternalEvidenceEvent, key: &str) -> Option<&'a str> {
    event
        .attributes
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
}

fn has_attribute_token(event: &ExternalEvidenceEvent, key: &str, values: &[&str]) -> bool {
    attribute_token(event, key).is_some_and(|value| {
        values
            .iter()
            .any(|candidate| value.eq_ignore_ascii_case(candidate))
    })
}

fn attribute_bool(event: &ExternalEvidenceEvent, key: &str) -> bool {
    event
        .attributes
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn attribute_i64(event: &ExternalEvidenceEvent, key: &str) -> Option<i64> {
    event
        .attributes
        .get(key)
        .and_then(serde_json::Value::as_i64)
}

/// Detect explicit integrity/verdict signals from content and supply-chain
/// sensors. Free-form content is deliberately not scanned: the detector needs
/// a machine-produced verdict and therefore remains deterministic.
fn detect_poisoned_material(inputs: &DetectInputs<'_>) -> Vec<BoundaryFinding> {
    let mut out = Vec::new();
    for event in inputs.external {
        let poisoned_input = has_attribute_token(
            event,
            "input_verdict",
            &["poisoned", "prompt_injection", "malicious"],
        ) || has_attribute_token(
            event,
            "content_verdict",
            &["poisoned", "prompt_injection", "malicious"],
        );
        let invalid_artifact = has_attribute_token(
            event,
            "artifact_integrity",
            &["mismatch", "invalid", "tampered"],
        ) || has_attribute_token(
            event,
            "supply_chain_verdict",
            &["malicious", "compromised", "poisoned"],
        );
        if !poisoned_input && !invalid_artifact {
            continue;
        }

        let (detector, token, summary) = if invalid_artifact {
            (
                "supply_chain_material_invalid",
                "package_install",
                "supply-chain sensor reported invalid or compromised material",
            )
        } else {
            (
                "poisoned_input_material",
                "undeclared_answer_sources",
                "content sensor reported poisoned or malicious input",
            )
        };
        let disposition = disposition_of(inputs.contract, token);
        let mut finding = BoundaryFinding::new(
            inputs.run_id,
            FindingKind::BoundaryViolation,
            detector,
            FindingSeverity::High,
            summary,
        );
        finding.external_evidence_ids.push(event.id.clone());
        finding.token = Some(token.into());
        finding.disposition = Some(disposition);
        finding.recommendation =
            Some("quarantine the cited material and verify its origin before reuse".into());
        out.push(finding);
    }
    out
}

fn same_run_or_session(event: &ExternalEvidenceEvent, marker: &ExternalEvidenceEvent) -> bool {
    let same = |left: Option<&str>, right: Option<&str>| {
        left.zip(right).is_some_and(|(left, right)| left == right)
    };
    same(
        event.identity.run_id.as_deref(),
        marker.identity.run_id.as_deref(),
    ) || same(
        event.identity.session.as_deref(),
        marker.identity.session.as_deref(),
    )
}

fn is_terminal_parent_marker(event: &ExternalEvidenceEvent) -> bool {
    matches!(event.action, EvidenceAction::ProcessExit)
        && attribute_bool(event, "lifecycle_terminal")
        && has_attribute_token(
            event,
            "process_role",
            &["supervised_root", "agent_parent", "run_root"],
        )
        && event.identity.pid.is_some()
}

fn causally_descends_from(event: &ExternalEvidenceEvent, marker: &ExternalEvidenceEvent) -> bool {
    let Some(parent_pid) = marker.identity.pid else {
        return false;
    };
    attribute_i64(event, "ancestor_pid") == Some(parent_pid)
        || attribute_i64(event, "parent_pid") == Some(parent_pid)
}

/// Detect activity associated with a run/session after its process-exit sensor
/// signal. Both the exit marker and continued activity are cited.
fn detect_persistence_after_exit(inputs: &DetectInputs<'_>) -> Vec<BoundaryFinding> {
    let mut out = Vec::new();
    for marker in inputs
        .external
        .iter()
        .filter(|event| is_terminal_parent_marker(event))
    {
        let marker_at = external_time(marker);
        let continued = inputs
            .external
            .iter()
            .filter(|event| {
                external_time(event) > marker_at
                    && same_run_or_session(event, marker)
                    && causally_descends_from(event, marker)
            })
            .filter(|event| {
                matches!(
                    event.action,
                    EvidenceAction::ProcessExec
                        | EvidenceAction::NetworkListen
                        | EvidenceAction::ContainerStart
                        | EvidenceAction::FileWrite
                )
            })
            .min_by_key(|event| external_time(event));
        let Some(continued) = continued else {
            continue;
        };
        let mut finding = BoundaryFinding::new(
            inputs.run_id,
            FindingKind::BehaviorTransition,
            "persistence_after_exit",
            FindingSeverity::Critical,
            "activity associated with the run continued after its process-exit signal",
        );
        finding.external_evidence_ids = vec![marker.id.clone(), continued.id.clone()];
        finding.created_at = external_time(continued);
        finding.token = Some("persistence".into());
        finding.disposition = Some(disposition_of(inputs.contract, "persistence"));
        finding.recommendation =
            Some("inspect surviving descendants, listeners, and persistence artifacts".into());
        out.push(finding);
    }
    out
}

fn fanout_parent(event: &ExternalEvidenceEvent) -> Option<String> {
    for key in ["delegator", "parent_workload", "parent_process"] {
        if let Some(value) = attribute_token(event, key) {
            return Some(format!("{key}:{value}"));
        }
    }
    if matches!(event.action, EvidenceAction::ContainerStart) {
        return event
            .identity
            .trace_id
            .as_deref()
            .map(|value| format!("trace:{value}"))
            .or_else(|| {
                event
                    .identity
                    .run_id
                    .as_deref()
                    .map(|value| format!("run:{value}"))
            });
    }
    None
}

fn fanout_child(event: &ExternalEvidenceEvent) -> Option<String> {
    event
        .identity
        .workload
        .as_deref()
        .or(event.identity.container.as_deref())
        .or(event.object.as_deref())
        .map(str::to_owned)
}

fn eligible_fanout_activity(event: &ExternalEvidenceEvent) -> bool {
    if has_attribute_token(
        event,
        "fanout_class",
        &["build_parallelism", "service_replicas"],
    ) {
        return false;
    }
    matches!(event.action, EvidenceAction::ContainerStart)
        || attribute_bool(event, "delegation")
        || has_attribute_token(event, "fanout_class", &["agent_delegation", "swarm"])
}

/// Eight distinct delegated/container workloads from one parent in a 30-second
/// window is the stable abnormal-fan-out threshold. Explicit build/service
/// classifications remain grouped but are excluded from abnormal delegation.
fn detect_abnormal_fanout(inputs: &DetectInputs<'_>) -> Vec<BoundaryFinding> {
    const FANOUT_THRESHOLD: usize = 8;
    const FANOUT_WINDOW_SECONDS: i64 = 30;
    let mut groups: BTreeMap<String, Vec<&ExternalEvidenceEvent>> = BTreeMap::new();
    for event in inputs.external {
        if !matches!(
            event.action,
            EvidenceAction::ContainerStart | EvidenceAction::ProcessExec
        ) {
            continue;
        }
        if let (Some(parent), Some(_)) = (fanout_parent(event), fanout_child(event)) {
            groups.entry(parent).or_default().push(event);
        }
    }

    let mut out = Vec::new();
    for (parent, events) in groups {
        let mut eligible: Vec<_> = events
            .into_iter()
            .filter(|event| eligible_fanout_activity(event))
            .collect();
        eligible.sort_by(|left, right| {
            external_time(left)
                .cmp(&external_time(right))
                .then(left.id.cmp(&right.id))
        });
        let mut left = 0usize;
        let mut child_counts = BTreeMap::<String, usize>::new();
        let mut proving_window = None;
        for right in 0..eligible.len() {
            if let Some(child) = fanout_child(eligible[right]) {
                *child_counts.entry(child).or_default() += 1;
            }
            while external_time(eligible[right]) - external_time(eligible[left])
                > chrono::Duration::seconds(FANOUT_WINDOW_SECONDS)
            {
                if let Some(child) = fanout_child(eligible[left]) {
                    if let Some(count) = child_counts.get_mut(&child) {
                        *count -= 1;
                        if *count == 0 {
                            child_counts.remove(&child);
                        }
                    }
                }
                left += 1;
            }
            if child_counts.len() >= FANOUT_THRESHOLD {
                proving_window = Some((left, right));
                break;
            }
        }
        let Some((left, right)) = proving_window else {
            continue;
        };
        let mut finding = BoundaryFinding::new(
            inputs.run_id,
            FindingKind::BehaviorTransition,
            "abnormal_fanout",
            FindingSeverity::High,
            format!(
                "parent {parent} created {} distinct delegated workloads (threshold {FANOUT_THRESHOLD})",
                child_counts.len()
            ),
        );
        finding.external_evidence_ids = eligible[left..=right]
            .iter()
            .take(32)
            .map(|event| event.id.clone())
            .collect();
        finding.created_at = external_time(eligible[right]);
        finding.token = Some("swarm_fanout".into());
        finding.disposition = Some(disposition_of(inputs.contract, "swarm_fanout"));
        finding.recommendation =
            Some("confirm delegation was authorized and inspect every cited workload".into());
        out.push(finding);
    }
    out
}

/// Detect invalid integrity results and internally contradictory telemetry.
/// Unsigned (`unverified`) evidence is a coverage limitation, not deception.
fn detect_deceptive_telemetry(inputs: &DetectInputs<'_>) -> Vec<BoundaryFinding> {
    let mut out = Vec::new();
    for event in inputs.external {
        let anomaly = attribute_token(event, crate::evidence::TELEMETRY_ANOMALY_ATTRIBUTE);
        let invalid_signature = matches!(
            event.integrity,
            crate::evidence::EvidenceIntegrity::SignedInvalid
        ) || anomaly
            == Some(crate::evidence::TELEMETRY_ANOMALY_SIGNED_INVALID);
        let source_identity_conflict =
            anomaly == Some(crate::evidence::TELEMETRY_ANOMALY_SOURCE_IDENTITY_CONFLICT);
        let identity_conflict = event
            .linked_run_id
            .as_ref()
            .zip(event.identity.run_id.as_ref())
            .is_some_and(|(linked, claimed)| linked != claimed);
        if invalid_signature || identity_conflict || source_identity_conflict {
            let detector = if source_identity_conflict {
                "telemetry_identity_conflict"
            } else {
                "telemetry_integrity_invalid"
            };
            let reason = if invalid_signature {
                "sensor evidence has an invalid signature"
            } else if source_identity_conflict {
                "sensor reused one source event identity for conflicting content"
            } else {
                "sensor evidence has conflicting linked and claimed run identities"
            };
            let mut finding = BoundaryFinding::new(
                inputs.run_id,
                FindingKind::BoundaryViolation,
                detector,
                FindingSeverity::High,
                reason,
            );
            finding.external_evidence_ids.push(event.id.clone());
            finding.token = Some("telemetry_integrity".into());
            finding.recommendation = Some(
                "exclude the cited record from confirmed claims and inspect the sensor".into(),
            );
            out.push(finding);
        }
    }

    let mut by_source_identity: BTreeMap<(&str, &str), &ExternalEvidenceEvent> = BTreeMap::new();
    for event in inputs.external {
        let key = (event.source.as_str(), event.source_event_id.as_str());
        if let Some(previous) = by_source_identity.get(&key) {
            let conflicts = previous.action != event.action
                || previous.outcome != event.outcome
                || previous.destination != event.destination
                || previous.object != event.object;
            if conflicts {
                let mut finding = BoundaryFinding::new(
                    inputs.run_id,
                    FindingKind::BoundaryViolation,
                    "telemetry_identity_conflict",
                    FindingSeverity::High,
                    format!(
                        "source {} reused event identity {} for conflicting records",
                        event.source, event.source_event_id
                    ),
                );
                finding.external_evidence_ids = vec![previous.id.clone(), event.id.clone()];
                finding.token = Some("telemetry_integrity".into());
                finding.recommendation = Some(
                    "preserve both records and inspect replay, collision, or sensor compromise"
                        .into(),
                );
                out.push(finding);
            }
        } else {
            by_source_identity.insert(key, event);
        }
    }
    out
}

fn detect_behavior_transitions(inputs: &DetectInputs<'_>) -> Vec<BoundaryFinding> {
    let mut out = Vec::new();
    // First error after a run of successes → transition marker.
    let mut saw_success = false;
    for ev in inputs.events {
        if matches!(ev.status, EventStatus::Success) {
            saw_success = true;
        }
        if saw_success && matches!(ev.status, EventStatus::Error) {
            let mut f = BoundaryFinding::new(
                inputs.run_id,
                FindingKind::BehaviorTransition,
                "success_to_error",
                FindingSeverity::Info,
                "behavior transition: success → error",
            );
            f.evidence_event_ids.push(ev.id.clone());
            out.push(f);
            break;
        }
    }
    out
}

fn detect_execution_after_violation(
    inputs: &DetectInputs<'_>,
    prior: &[BoundaryFinding],
) -> Vec<BoundaryFinding> {
    let first_violation = prior
        .iter()
        .filter(|f| matches!(f.kind, FindingKind::BoundaryViolation))
        .min_by_key(|f| f.created_at);
    let Some(v) = first_violation else {
        return Vec::new();
    };
    let after_event = inputs
        .events
        .iter()
        .filter(|event| event.started_at > v.created_at)
        .map(|event| (event.started_at, true, event.id.clone()));
    let after_external = inputs
        .external
        .iter()
        .map(|event| (external_time(event), false, event.id.clone()))
        .filter(|(at, _, _)| *at > v.created_at);
    if let Some((at, internal, evidence_id)) = after_event
        .chain(after_external)
        .min_by_key(|(at, _, _)| *at)
    {
        let mut f = BoundaryFinding::new(
            inputs.run_id,
            FindingKind::BehaviorTransition,
            "execution_after_violation",
            FindingSeverity::Critical,
            format!(
                "activity continued after earliest violation {} ({})",
                v.id, v.detector
            ),
        );
        f.created_at = at;
        if internal {
            f.evidence_event_ids.push(evidence_id);
        } else {
            f.external_evidence_ids.push(evidence_id);
        }
        f.recommendation = Some(
            "earliest actionable signal already raised; continued execution is material".into(),
        );
        return vec![f];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::BoundaryContract;
    use crate::evidence::ExternalEvidenceEvent;

    #[test]
    fn flags_public_destination_when_prohibited() {
        let c = BoundaryContract::eval_example();
        let mut ext =
            ExternalEvidenceEvent::new("proxy", "proxy", "1", EvidenceAction::HttpRequest);
        ext.destination = Some("https://evil.example/answer".into());
        let findings = detect_boundary_findings(DetectInputs {
            run_id: "r1",
            contract: Some(&c),
            events: &[],
            external: &[ext],
        });
        assert!(findings
            .iter()
            .any(|f| f.detector == "unexpected_destination"));
    }

    #[test]
    fn finding_to_trace_event_kind() {
        let f = BoundaryFinding::new(
            "r1",
            FindingKind::BoundaryViolation,
            "test",
            FindingSeverity::High,
            "x",
        );
        let ev = f.to_trace_event(42);
        assert_eq!(ev.kind, "boundary.violation");
        assert_eq!(ev.sequence, 42);
    }

    #[test]
    fn findings_use_evidence_chronology_and_detect_continued_activity() {
        let contract = BoundaryContract::eval_example();
        let t0 = Utc::now() - chrono::Duration::minutes(2);
        let t1 = t0 + chrono::Duration::seconds(30);
        let mut later =
            ExternalEvidenceEvent::new("proxy", "proxy", "later", EvidenceAction::HttpRequest);
        later.destination = Some("https://later.example/answer".into());
        later.occurred_at = Some(t1);
        let mut earlier =
            ExternalEvidenceEvent::new("proxy", "proxy", "earlier", EvidenceAction::HttpRequest);
        earlier.destination = Some("https://earlier.example/answer".into());
        earlier.occurred_at = Some(t0);

        let findings = detect_boundary_findings(DetectInputs {
            run_id: "r1",
            contract: Some(&contract),
            events: &[],
            external: &[later, earlier],
        });
        let earliest = findings
            .iter()
            .filter(|finding| matches!(finding.kind, FindingKind::BoundaryViolation))
            .min_by_key(|finding| finding.created_at)
            .unwrap();
        assert_eq!(earliest.created_at, t0);
        let continued = findings
            .iter()
            .find(|finding| finding.detector == "execution_after_violation")
            .unwrap();
        assert_eq!(continued.created_at, t1);
        assert_eq!(continued.external_evidence_ids.len(), 1);
    }

    #[test]
    fn persistence_finding_cites_exit_and_surviving_activity() {
        let t0 = Utc::now() - chrono::Duration::minutes(1);
        let mut exit =
            ExternalEvidenceEvent::new("audit", "process", "exit", EvidenceAction::ProcessExit);
        exit.id = "exit-evidence".into();
        exit.identity.trace_id = Some("same-trace".into());
        exit.identity.run_id = Some("same-run".into());
        exit.identity.pid = Some(42);
        exit.occurred_at = Some(t0);
        exit.attributes
            .insert("lifecycle_terminal".into(), serde_json::json!(true));
        exit.attributes
            .insert("process_role".into(), serde_json::json!("supervised_root"));
        let mut listener = ExternalEvidenceEvent::new(
            "audit",
            "network",
            "listener",
            EvidenceAction::NetworkListen,
        );
        listener.id = "listener-evidence".into();
        listener.identity.trace_id = Some("same-trace".into());
        listener.identity.run_id = Some("same-run".into());
        listener.occurred_at = Some(t0 + chrono::Duration::seconds(1));
        listener
            .attributes
            .insert("ancestor_pid".into(), serde_json::json!(42));
        let proving_time = external_time(&listener);

        let findings = detect_boundary_findings(DetectInputs {
            run_id: "r1",
            contract: None,
            events: &[],
            external: &[exit, listener],
        });
        let finding = findings
            .iter()
            .find(|finding| finding.detector == "persistence_after_exit")
            .expect("persistence finding");
        assert_eq!(
            finding.external_evidence_ids,
            ["exit-evidence", "listener-evidence"]
        );
        assert_eq!(finding.created_at, proving_time);
    }

    #[test]
    fn ordinary_child_exit_followed_by_same_trace_activity_is_clean() {
        let t0 = Utc::now() - chrono::Duration::minutes(1);
        let mut child_exit = ExternalEvidenceEvent::new(
            "audit",
            "process",
            "child-exit",
            EvidenceAction::ProcessExit,
        );
        child_exit.identity.trace_id = Some("same-trace".into());
        child_exit.identity.run_id = Some("same-run".into());
        child_exit.identity.session = Some("same-session".into());
        child_exit.identity.pid = Some(99);
        child_exit.occurred_at = Some(t0);
        child_exit
            .attributes
            .insert("process_role".into(), serde_json::json!("child"));
        let mut later =
            ExternalEvidenceEvent::new("audit", "process", "later", EvidenceAction::ProcessExec);
        later.identity.trace_id = Some("same-trace".into());
        later.identity.run_id = Some("same-run".into());
        later.identity.session = Some("same-session".into());
        later.occurred_at = Some(t0 + chrono::Duration::seconds(1));
        later
            .attributes
            .insert("parent_pid".into(), serde_json::json!(99));

        let findings = detect_boundary_findings(DetectInputs {
            run_id: "same-run",
            contract: None,
            events: &[],
            external: &[child_exit, later],
        });
        assert!(!findings
            .iter()
            .any(|finding| finding.detector == "persistence_after_exit"));
    }

    #[test]
    fn invalid_signature_flags_but_unsigned_telemetry_does_not() {
        let mut invalid =
            ExternalEvidenceEvent::new("audit", "process", "invalid", EvidenceAction::ProcessExec);
        invalid.integrity = crate::evidence::EvidenceIntegrity::SignedInvalid;
        let unsigned =
            ExternalEvidenceEvent::new("audit", "process", "unsigned", EvidenceAction::ProcessExec);
        let invalid_findings = detect_boundary_findings(DetectInputs {
            run_id: "r1",
            contract: None,
            events: &[],
            external: &[invalid],
        });
        assert!(invalid_findings
            .iter()
            .any(|finding| finding.detector == "telemetry_integrity_invalid"));
        let unsigned_findings = detect_boundary_findings(DetectInputs {
            run_id: "r1",
            contract: None,
            events: &[],
            external: &[unsigned],
        });
        assert!(unsigned_findings.is_empty());
    }
}
