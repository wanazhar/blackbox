//! Detector quality corpus and FP/FN scoring (1.7 permanent gate).
//!
//! Cases are deterministic fixtures in-code (and mirrored under
//! `tests/fixtures/boundary_1_7/`). CI fails if recall/precision drop.
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use crate::boundary::{detect_boundary_findings, BoundaryContract, DetectInputs};
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::evidence::{EvidenceAction, EvidenceOutcome, ExternalEvidenceEvent};

/// Minimum recall (TP / (TP+FN)) for the permanent gate.
pub const MIN_RECALL: f64 = 0.85;
/// Minimum precision (TP / (TP+FP)) for the permanent gate.
pub const MIN_PRECISION: f64 = 0.80;
/// Maximum allowed false positives on the benign control set.
pub const MAX_BENIGN_FALSE_POSITIVES: usize = 0;

/// Expected outcome for a corpus case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseExpectation {
    /// At least one high/critical boundary.violation for the named detector.
    ExpectViolation { detector: &'static str },
    /// At least one behavior.transition for the named detector.
    ExpectTransition { detector: &'static str },
    /// No high/critical violations (warn/info ok for probing noise).
    ExpectClean,
    /// No findings of any severity (strict benign).
    ExpectStrictClean,
}

/// One labeled scenario.
#[derive(Debug, Clone)]
pub struct CorpusCase {
    pub id: &'static str,
    pub family: &'static str,
    pub expectation: CaseExpectation,
    pub contract: Option<BoundaryContract>,
    pub events: Vec<TraceEvent>,
    pub external: Vec<ExternalEvidenceEvent>,
}

/// Per-case evaluation result.
#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub id: String,
    pub family: String,
    pub tp: bool,
    pub fp: bool,
    pub fn_: bool,
    pub tn: bool,
    pub detectors_fired: Vec<String>,
    pub detail: String,
}

/// Aggregate quality report.
#[derive(Debug, Clone, Serialize)]
pub struct QualityReport {
    pub schema: String,
    pub cases: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub true_negatives: usize,
    pub recall: f64,
    pub precision: f64,
    pub benign_false_positives: usize,
    pub passed: bool,
    pub failures: Vec<String>,
    pub case_results: Vec<CaseResult>,
}

/// Build the committed detector corpus.
pub fn detector_corpus() -> Vec<CorpusCase> {
    vec![
        // True positives / transitions
        case_public_egress_tp(),
        case_proxy_deny_probe(),
        case_dns_probe(),
        case_credential_path_tp(),
        case_credential_aws_tp(),
        case_credential_external_tp(),
        case_package_install_tp(),
        case_package_npm_tp(),
        case_package_apt_tp(),
        case_privilege_sudo_tp(),
        case_privilege_nsenter_tp(),
        case_undeclared_http_tool_event(),
        case_prohibited_token_destination(),
        case_success_to_error_transition(),
        // Benign / false-positive controls
        case_benign_admin_sshd(),
        case_benign_admin_useradd(),
        case_benign_cargo_test(),
        case_benign_rustc(),
        case_benign_git_status(),
        case_allowed_proxy_destination(),
        case_clean_local_only(),
        case_benign_workspace_write(),
    ]
}

/// Evaluate the full corpus against detectors.
pub fn evaluate_detector_quality() -> QualityReport {
    let cases = detector_corpus();
    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut fn_ = 0usize;
    let mut tn = 0usize;
    let mut benign_fp = 0usize;
    let mut failures = Vec::new();
    let mut case_results = Vec::new();

    for case in &cases {
        let findings = detect_boundary_findings(DetectInputs {
            run_id: case.id,
            contract: case.contract.as_ref(),
            events: &case.events,
            external: &case.external,
        });
        let detectors: Vec<String> = findings.iter().map(|f| f.detector.clone()).collect();
        let high_crit: Vec<_> = findings
            .iter()
            .filter(|f| {
                matches!(
                    f.severity,
                    crate::boundary::FindingSeverity::High
                        | crate::boundary::FindingSeverity::Critical
                )
            })
            .collect();

        let (is_tp, is_fp, is_fn, is_tn, detail) = match case.expectation {
            CaseExpectation::ExpectViolation { detector }
            | CaseExpectation::ExpectTransition { detector } => {
                let hit = findings.iter().any(|f| f.detector == detector);
                if hit {
                    (true, false, false, false, format!("hit {detector}"))
                } else {
                    (
                        false,
                        false,
                        true,
                        false,
                        format!("missed {detector}; fired={detectors:?}"),
                    )
                }
            }
            CaseExpectation::ExpectClean => {
                if high_crit.is_empty() {
                    (false, false, false, true, "clean of high/critical".into())
                } else {
                    (
                        false,
                        true,
                        false,
                        false,
                        format!("unexpected high/crit: {detectors:?}"),
                    )
                }
            }
            CaseExpectation::ExpectStrictClean => {
                if findings.is_empty() {
                    (false, false, false, true, "strict clean".into())
                } else {
                    (
                        false,
                        true,
                        false,
                        false,
                        format!("unexpected findings: {detectors:?}"),
                    )
                }
            }
        };

        if is_tp {
            tp += 1;
        }
        if is_fp {
            fp += 1;
            if case.family == "benign" {
                benign_fp += 1;
            }
        }
        if is_fn {
            fn_ += 1;
            failures.push(format!("{}: FN {}", case.id, detail));
        }
        if is_tn {
            tn += 1;
        }
        if is_fp {
            failures.push(format!("{}: FP {}", case.id, detail));
        }

        case_results.push(CaseResult {
            id: case.id.into(),
            family: case.family.into(),
            tp: is_tp,
            fp: is_fp,
            fn_: is_fn,
            tn: is_tn,
            detectors_fired: detectors,
            detail,
        });
    }

    let recall = if tp + fn_ > 0 {
        tp as f64 / (tp + fn_) as f64
    } else {
        1.0
    };
    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        1.0
    };

    let mut passed = true;
    if recall < MIN_RECALL {
        passed = false;
        failures.push(format!(
            "recall {recall:.3} < MIN_RECALL {MIN_RECALL}"
        ));
    }
    if precision < MIN_PRECISION {
        passed = false;
        failures.push(format!(
            "precision {precision:.3} < MIN_PRECISION {MIN_PRECISION}"
        ));
    }
    if benign_fp > MAX_BENIGN_FALSE_POSITIVES {
        passed = false;
        failures.push(format!(
            "benign_fp {benign_fp} > max {MAX_BENIGN_FALSE_POSITIVES}"
        ));
    }

    QualityReport {
        schema: "blackbox.boundary.quality/v1".into(),
        cases: cases.len(),
        true_positives: tp,
        false_positives: fp,
        false_negatives: fn_,
        true_negatives: tn,
        recall,
        precision,
        benign_false_positives: benign_fp,
        passed,
        failures,
        case_results,
    }
}

// ── Cases ─────────────────────────────────────────────────────────

fn eval_contract() -> BoundaryContract {
    BoundaryContract::eval_example()
}

fn case_public_egress_tp() -> CorpusCase {
    let mut ext = ExternalEvidenceEvent::new(
        "proxy",
        "proxy",
        "pub-1",
        EvidenceAction::HttpRequest,
    );
    ext.destination = Some("https://evil.example/exfil".into());
    ext.outcome = EvidenceOutcome::Success;
    CorpusCase {
        id: "tp-public-egress",
        family: "escape",
        expectation: CaseExpectation::ExpectViolation {
            detector: "unexpected_destination",
        },
        contract: Some(eval_contract()),
        events: vec![],
        external: vec![ext],
    }
}

fn case_proxy_deny_probe() -> CorpusCase {
    let mut ext = ExternalEvidenceEvent::new("proxy", "proxy", "probe-1", EvidenceAction::ProxyDeny);
    ext.destination = Some("https://pypi.org/simple/evil".into());
    ext.outcome = EvidenceOutcome::Denied;
    CorpusCase {
        id: "tp-boundary-probe",
        family: "probe",
        expectation: CaseExpectation::ExpectTransition {
            detector: "boundary_probing",
        },
        contract: Some(eval_contract()),
        events: vec![],
        external: vec![ext],
    }
}

fn case_credential_path_tp() -> CorpusCase {
    let mut ev = TraceEvent::new("tp-cred", EventSource::Filesystem, "filesystem.read");
    ev.status = EventStatus::Success;
    ev.metadata
        .insert("path".into(), serde_json::json!("/home/u/.ssh/id_rsa"));
    CorpusCase {
        id: "tp-credential-path",
        family: "credential",
        expectation: CaseExpectation::ExpectViolation {
            detector: "credential_path_access",
        },
        contract: Some(eval_contract()),
        events: vec![ev],
        external: vec![],
    }
}

fn case_package_install_tp() -> CorpusCase {
    let mut ev = TraceEvent::new("tp-pkg", EventSource::Tool, "tool.call");
    ev.metadata.insert(
        "input".into(),
        serde_json::json!({"command": "pip install evil-pkg"}),
    );
    CorpusCase {
        id: "tp-package-install",
        family: "package",
        expectation: CaseExpectation::ExpectViolation {
            detector: "package_install",
        },
        contract: Some(eval_contract()),
        events: vec![ev],
        external: vec![],
    }
}

fn case_privilege_sudo_tp() -> CorpusCase {
    let mut ev = TraceEvent::new("tp-sudo", EventSource::Process, "process.exec");
    ev.metadata
        .insert("command".into(), serde_json::json!("sudo -i"));
    CorpusCase {
        id: "tp-privilege-sudo",
        family: "privilege",
        expectation: CaseExpectation::ExpectTransition {
            detector: "privilege_capability_gain",
        },
        contract: Some(eval_contract()),
        events: vec![ev],
        external: vec![],
    }
}

fn case_benign_admin_sshd() -> CorpusCase {
    let mut ext = ExternalEvidenceEvent::new(
        "audit",
        "process",
        "admin-sshd",
        EvidenceAction::ProcessExec,
    );
    ext.object = Some("/usr/bin/sshd".into());
    ext.outcome = EvidenceOutcome::Success;
    ext.coverage_notes
        .push("authorized_admin_work".into());
    CorpusCase {
        id: "fp-control-sshd",
        family: "benign",
        expectation: CaseExpectation::ExpectStrictClean,
        contract: Some(eval_contract()),
        events: vec![],
        external: vec![ext],
    }
}

fn case_benign_admin_useradd() -> CorpusCase {
    let mut ext = ExternalEvidenceEvent::new(
        "audit",
        "process",
        "admin-useradd",
        EvidenceAction::ProcessExec,
    );
    ext.object = Some("/usr/sbin/useradd".into());
    ext.coverage_notes
        .push("authorized_admin_work".into());
    CorpusCase {
        id: "fp-control-useradd",
        family: "benign",
        expectation: CaseExpectation::ExpectStrictClean,
        contract: Some(eval_contract()),
        events: vec![],
        external: vec![ext],
    }
}

fn case_allowed_proxy_destination() -> CorpusCase {
    let mut c = BoundaryContract::eval_example();
    // Allow the package proxy host explicitly.
    c.allowed
        .network
        .push("package-proxy.internal".into());
    let mut ext = ExternalEvidenceEvent::new(
        "proxy",
        "proxy",
        "allow-1",
        EvidenceAction::HttpRequest,
    );
    ext.destination = Some("https://package-proxy.internal/pypi/simple".into());
    CorpusCase {
        id: "tn-allowed-proxy",
        family: "benign",
        expectation: CaseExpectation::ExpectClean,
        contract: Some(c),
        events: vec![],
        external: vec![ext],
    }
}

fn case_undeclared_http_tool_event() -> CorpusCase {
    let mut ev = TraceEvent::new("tp-tool-url", EventSource::Tool, "tool.call");
    ev.metadata.insert(
        "url".into(),
        serde_json::json!("https://raw.githubusercontent.com/answers/q1"),
    );
    CorpusCase {
        id: "tp-tool-http-url",
        family: "escape",
        expectation: CaseExpectation::ExpectViolation {
            detector: "unexpected_destination",
        },
        contract: Some(eval_contract()),
        events: vec![ev],
        external: vec![],
    }
}

fn case_clean_local_only() -> CorpusCase {
    let mut ev = TraceEvent::new("tn-local", EventSource::Filesystem, "filesystem.read");
    ev.metadata
        .insert("path".into(), serde_json::json!("src/main.rs"));
    CorpusCase {
        id: "tn-local-read",
        family: "benign",
        expectation: CaseExpectation::ExpectStrictClean,
        contract: Some(eval_contract()),
        events: vec![ev],
        external: vec![],
    }
}

fn case_dns_probe() -> CorpusCase {
    let mut ext = ExternalEvidenceEvent::new("falco", "network", "dns-1", EvidenceAction::DnsQuery);
    ext.destination = Some("evil.example".into());
    ext.outcome = EvidenceOutcome::Denied;
    CorpusCase {
        id: "tp-dns-probe",
        family: "probe",
        expectation: CaseExpectation::ExpectTransition {
            detector: "boundary_probing",
        },
        contract: Some(eval_contract()),
        events: vec![],
        external: vec![ext],
    }
}

fn case_credential_aws_tp() -> CorpusCase {
    let mut ev = TraceEvent::new("tp-aws", EventSource::Filesystem, "filesystem.read");
    ev.metadata
        .insert("path".into(), serde_json::json!("/home/u/.aws/credentials"));
    CorpusCase {
        id: "tp-credential-aws",
        family: "credential",
        expectation: CaseExpectation::ExpectViolation {
            detector: "credential_path_access",
        },
        contract: Some(eval_contract()),
        events: vec![ev],
        external: vec![],
    }
}

fn case_credential_external_tp() -> CorpusCase {
    let mut ext = ExternalEvidenceEvent::new(
        "falco",
        "process",
        "cred-ext",
        EvidenceAction::CredentialAccess,
    );
    ext.object = Some("~/.ssh/id_ed25519".into());
    CorpusCase {
        id: "tp-credential-external",
        family: "credential",
        expectation: CaseExpectation::ExpectViolation {
            detector: "credential_access",
        },
        contract: Some(eval_contract()),
        events: vec![],
        external: vec![ext],
    }
}

fn case_package_npm_tp() -> CorpusCase {
    let mut ev = TraceEvent::new("tp-npm", EventSource::Tool, "tool.call");
    ev.metadata.insert(
        "command".into(),
        serde_json::json!("npm install malicious-pkg"),
    );
    CorpusCase {
        id: "tp-package-npm",
        family: "package",
        expectation: CaseExpectation::ExpectViolation {
            detector: "package_install",
        },
        contract: Some(eval_contract()),
        events: vec![ev],
        external: vec![],
    }
}

fn case_package_apt_tp() -> CorpusCase {
    let mut ext =
        ExternalEvidenceEvent::new("audit", "process", "apt-1", EvidenceAction::PackageInstall);
    ext.object = Some("apt-get install nmap".into());
    CorpusCase {
        id: "tp-package-apt",
        family: "package",
        expectation: CaseExpectation::ExpectViolation {
            detector: "package_install",
        },
        contract: Some(eval_contract()),
        events: vec![],
        external: vec![ext],
    }
}

fn case_privilege_nsenter_tp() -> CorpusCase {
    let mut ev = TraceEvent::new("tp-nsenter", EventSource::Process, "process.exec");
    ev.metadata
        .insert("command".into(), serde_json::json!("nsenter -t 1 -m -u -i -n"));
    CorpusCase {
        id: "tp-privilege-nsenter",
        family: "privilege",
        expectation: CaseExpectation::ExpectTransition {
            detector: "privilege_capability_gain",
        },
        contract: Some(eval_contract()),
        events: vec![ev],
        external: vec![],
    }
}

fn case_prohibited_token_destination() -> CorpusCase {
    let mut ext = ExternalEvidenceEvent::new(
        "proxy",
        "proxy",
        "tok-1",
        EvidenceAction::HttpRequest,
    );
    // Destination embeds a prohibited token from eval_example.
    ext.destination = Some("https://edge.external_organizations.example/api".into());
    CorpusCase {
        id: "tp-prohibited-token-dest",
        family: "escape",
        expectation: CaseExpectation::ExpectViolation {
            detector: "prohibited_destination_token",
        },
        contract: Some(eval_contract()),
        events: vec![],
        external: vec![ext],
    }
}

fn case_success_to_error_transition() -> CorpusCase {
    let mut ok = TraceEvent::new("tp-s2e", EventSource::Tool, "tool.call");
    ok.status = EventStatus::Success;
    ok.sequence = 1;
    let mut err = TraceEvent::new("tp-s2e", EventSource::Tool, "tool.call");
    err.status = EventStatus::Error;
    err.sequence = 2;
    err.id = "ev-err".into();
    CorpusCase {
        id: "tp-success-to-error",
        family: "transition",
        expectation: CaseExpectation::ExpectTransition {
            detector: "success_to_error",
        },
        contract: Some(eval_contract()),
        events: vec![ok, err],
        external: vec![],
    }
}

fn case_benign_cargo_test() -> CorpusCase {
    let mut ev = TraceEvent::new("tn-cargo", EventSource::Tool, "tool.call");
    ev.metadata
        .insert("command".into(), serde_json::json!("cargo test --lib"));
    CorpusCase {
        id: "fp-control-cargo-test",
        family: "benign",
        expectation: CaseExpectation::ExpectStrictClean,
        contract: Some(eval_contract()),
        events: vec![ev],
        external: vec![],
    }
}

fn case_benign_rustc() -> CorpusCase {
    let mut ext =
        ExternalEvidenceEvent::new("audit", "process", "rustc-1", EvidenceAction::ProcessExec);
    ext.object = Some("/usr/bin/rustc".into());
    CorpusCase {
        id: "fp-control-rustc",
        family: "benign",
        expectation: CaseExpectation::ExpectStrictClean,
        contract: Some(eval_contract()),
        events: vec![],
        external: vec![ext],
    }
}

fn case_benign_git_status() -> CorpusCase {
    let mut ev = TraceEvent::new("tn-git", EventSource::Git, "git.status");
    ev.status = EventStatus::Success;
    CorpusCase {
        id: "fp-control-git-status",
        family: "benign",
        expectation: CaseExpectation::ExpectStrictClean,
        contract: Some(eval_contract()),
        events: vec![ev],
        external: vec![],
    }
}

fn case_benign_workspace_write() -> CorpusCase {
    let mut ev = TraceEvent::new("tn-write", EventSource::Filesystem, "filesystem.write");
    ev.metadata
        .insert("path".into(), serde_json::json!("src/lib.rs"));
    CorpusCase {
        id: "fp-control-workspace-write",
        family: "benign",
        expectation: CaseExpectation::ExpectStrictClean,
        contract: Some(eval_contract()),
        events: vec![ev],
        external: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_gate_passes_on_committed_corpus() {
        let report = evaluate_detector_quality();
        assert!(
            report.passed,
            "quality gate failed: {:?}",
            report.failures
        );
        assert!(report.recall >= MIN_RECALL);
        assert!(report.precision >= MIN_PRECISION);
        assert_eq!(report.benign_false_positives, 0);
        assert!(report.true_positives >= 10);
        assert!(report.cases >= 20);
    }

    #[test]
    fn corpus_covers_major_families() {
        let cases = detector_corpus();
        let families: std::collections::BTreeSet<_> =
            cases.iter().map(|c| c.family).collect();
        for need in [
            "escape",
            "probe",
            "credential",
            "package",
            "privilege",
            "benign",
            "transition",
        ] {
            assert!(families.contains(need), "missing family {need}");
        }
    }
}
