//! Deterministic boundary violation and behavior-transition detectors (1.7 Phase E).

#![allow(missing_docs)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};
use crate::evidence::{EvidenceAction, EvidenceOutcome, ExternalEvidenceEvent};

use super::contract::BoundaryContract;
use super::vocab::Disposition;

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

/// Severity recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warn,
    High,
    Critical,
}

impl FindingSeverity {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::High => "high",
            Self::Critical => "critical",
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
    /// Confidence note: findings are deterministic detectors, not LLM claims.
    #[serde(default)]
    pub confidence_note: String,
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
            confidence_note: "deterministic_detector".into(),
        }
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

fn detect_unexpected_destinations(inputs: &DetectInputs<'_>) -> Vec<BoundaryFinding> {
    let mut out = Vec::new();
    let contract = inputs.contract;
    for ev in inputs.external {
        let Some(ref dest) = ev.destination else {
            continue;
        };
        let looks_public = dest.contains("example.com")
            || dest.contains("githubusercontent")
            || dest.starts_with("http://")
            || dest.starts_with("https://")
            || dest.contains("public_network");
        let allowed = contract
            .map(|c| {
                c.allowed.network.iter().any(|n| dest.contains(n))
                    || c.disposition_of(dest) == Disposition::Allowed
            })
            .unwrap_or(false);
        let d = disposition_of(contract, "public_network");
        if looks_public && !allowed && is_hard_or_approval(d) {
            let mut f = BoundaryFinding::new(
                inputs.run_id,
                FindingKind::BoundaryViolation,
                "unexpected_destination",
                if matches!(d, Disposition::HardProhibition) {
                    FindingSeverity::Critical
                } else {
                    FindingSeverity::High
                },
                format!("unexpected destination {dest}"),
            );
            f.external_evidence_ids.push(ev.id.clone());
            f.token = Some("public_network".into());
            f.disposition = Some(d);
            f.recommendation =
                Some("investigate egress path; do not treat task success as containment".into());
            out.push(f);
        }
        // Explicit prohibited token match on destination string.
        if let Some(c) = contract {
            for p in &c.prohibited {
                if dest.contains(p) {
                    let mut f = BoundaryFinding::new(
                        inputs.run_id,
                        FindingKind::BoundaryViolation,
                        "prohibited_destination_token",
                        FindingSeverity::High,
                        format!("destination matches prohibited token {p:?}: {dest}"),
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
            if (dest.starts_with("http://") || dest.starts_with("https://"))
                && is_hard_or_approval(d)
            {
                let allowed = contract
                    .map(|c| c.allowed.network.iter().any(|n| dest.contains(n)))
                    .unwrap_or(false);
                if !allowed {
                    let mut f = BoundaryFinding::new(
                        inputs.run_id,
                        FindingKind::BoundaryViolation,
                        "unexpected_destination",
                        FindingSeverity::High,
                        format!("tool/network destination {dest}"),
                    );
                    f.evidence_event_ids.push(ev.id.clone());
                    f.token = Some("public_network".into());
                    f.disposition = Some(d);
                    out.push(f);
                }
            }
        }
    }
    out
}

fn detect_credential_activity(inputs: &DetectInputs<'_>) -> Vec<BoundaryFinding> {
    let mut out = Vec::new();
    let d = disposition_of(inputs.contract, "production_credentials");
    for ev in inputs.external {
        if matches!(ev.action, EvidenceAction::CredentialAccess) {
            let mut f = BoundaryFinding::new(
                inputs.run_id,
                FindingKind::BoundaryViolation,
                "credential_access",
                FindingSeverity::Critical,
                "credential access observed in external evidence",
            );
            f.external_evidence_ids.push(ev.id.clone());
            f.token = Some("production_credentials".into());
            f.disposition = Some(d);
            f.recommendation = Some("rotate if production; preserve receipt chain".into());
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
        if path.contains(".ssh")
            || path.contains("credentials")
            || path.contains(".aws")
            || path.contains("id_rsa")
            || tool.contains("secret")
        {
            let mut f = BoundaryFinding::new(
                inputs.run_id,
                FindingKind::BoundaryViolation,
                "credential_path_access",
                FindingSeverity::High,
                format!("possible credential material access path={path} tool={tool}"),
            );
            f.evidence_event_ids.push(ev.id.clone());
            f.token = Some("production_credentials".into());
            f.disposition = Some(d);
            out.push(f);
        }
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
}
