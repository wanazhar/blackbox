use blackbox::boundary::{
    detect_boundary_findings, detector_corpus, evaluate_frozen_benchmark, match_network_selector,
    match_token_selector, ContainmentClaimState, ContainmentReceipt, ContainmentResult,
    DetectInputs, MatchDecision, ProvenanceKind, ProvenanceRecord, ResourceSelector,
};
use blackbox::forensic::{
    build_forensic_pack, build_forensic_pack_result, build_forensic_pack_with_trust,
    ForensicPackOpts, SecretTokenMode,
};
use blackbox::incident::Incident;

#[test]
fn every_detector_finding_has_a_calibrated_decision() {
    for case in detector_corpus() {
        let findings = detect_boundary_findings(DetectInputs {
            run_id: case.id,
            contract: case.contract.as_ref(),
            events: &case.events,
            external: &case.external,
        });
        for finding in findings {
            let decision = finding
                .decision
                .as_ref()
                .unwrap_or_else(|| panic!("{}:{} lacks decision", case.id, finding.detector));
            assert_eq!(finding.severity, decision.severity);
            assert_eq!(decision.detector_repeatability, "deterministic_detector");
        }
    }
}

#[test]
fn typed_selectors_cover_ports_and_exact_policy_tokens() {
    let url = ResourceSelector::UrlPrefix {
        scheme: Some("https".into()),
        host: "api.example.com".into(),
        port: Some(8443),
        path: Some("/v1".into()),
    };
    assert!(match_network_selector(&url, "https://API.EXAMPLE.COM.:8443/v1/jobs").is_allow());
    assert_eq!(
        match_network_selector(&url, "https://api.example.com:443/v1/jobs").decision,
        MatchDecision::NoMatch
    );

    for selector in [
        ResourceSelector::Identity {
            value: "eval-workload".into(),
        },
        ResourceSelector::Tool {
            value: "shell".into(),
        },
        ResourceSelector::Effect {
            value: "workspace_write".into(),
        },
        ResourceSelector::ProvenanceClass {
            value: "declared_dataset".into(),
        },
    ] {
        let value = selector
            .disposition_token()
            .expect("typed token")
            .to_string();
        assert!(match_token_selector(&selector, &value).is_allow());
        assert_eq!(
            match_token_selector(&selector, &format!("{value}-suffix")).decision,
            MatchDecision::NoMatch
        );
    }
}

#[test]
fn frozen_gate_and_layered_outputs_are_release_evidence() {
    let report = evaluate_frozen_benchmark();
    assert!(report.passed, "{:?}", report.failures);
    assert!(report.frozen_baseline_verified);
    assert!(report.cross_platform_consistent);
    assert!(!report.detector_stats.is_empty());
    assert!(report.sensor_loss.variants > 0);

    let incident = Incident::new(Some("layer contract".into()));
    assert_eq!(incident.evidence_layer, "incident_interpretation");

    let pack = build_forensic_pack(
        "run-1",
        None,
        &[],
        &[],
        &[],
        &[],
        &ForensicPackOpts::default(),
    );
    assert_eq!(pack.evidence_layers["event_window"], "observation");
    assert_eq!(pack.evidence_layers["edges"], "correlation");
    assert_eq!(pack.evidence_layers["findings"], "findings");
    assert_eq!(pack.evidence_layers["derived_claims"], "claim");

    let receipt = ContainmentReceipt::new(
        "run-1",
        ContainmentClaimState::Verified,
        ContainmentResult::Held,
        "test",
        "release_contract",
    );
    let provenance = ProvenanceRecord::new("run-1", ProvenanceKind::VerificationData);
    let trust_pack = build_forensic_pack_with_trust(
        "run-1",
        None,
        &[],
        &[],
        &[],
        &[],
        &[receipt],
        &[provenance],
        &ForensicPackOpts::default(),
    );
    let scope = trust_pack.scope.expect("scope");
    assert_eq!(scope.containment_total, 1);
    assert_eq!(scope.containment_included, 1);
    assert_eq!(scope.provenance_total, 1);
    assert_eq!(scope.provenance_included, 1);

    let invalid_hmac = ForensicPackOpts {
        secret_token_mode: SecretTokenMode::ProjectCorrelatable { key: vec![] },
        ..Default::default()
    };
    let errors = build_forensic_pack_result("run-1", None, &[], &[], &[], &[], &invalid_hmac, None)
        .expect_err("empty project HMAC key must fail closed");
    assert!(errors
        .iter()
        .any(|error| error.contains("nonempty_hmac_key")));

    let release_script = include_str!("../scripts/release-qualify-unix.sh");
    assert!(release_script.contains("1.8: frozen detector benchmark"));
    assert!(release_script.contains("boundary benchmark"));
}
