//! Boundary policy linting and resolution explain (1.8).
//!
//! `blackbox boundary lint` surfaces unknown tokens, near-miss spellings,
//! inert selectors, and contradictory rules. Under fail-closed mode, unknown
//! required/prohibited tokens are errors.
//!
//! `blackbox boundary explain` shows effective value, source layer, overrides,
//! and resolution order per token.

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use super::contract::BoundaryContract;
use super::selector::ResourceEntry;
use super::vocab::{well_known, Disposition};

/// Known core capability / effect / identity tokens.
pub const CORE_CAPABILITY_TOKENS: &[&str] = &[
    well_known::PUBLIC_NETWORK,
    well_known::PRODUCTION_CREDENTIALS,
    well_known::EXTERNAL_ORGANIZATIONS,
    well_known::UNDECLARED_ANSWER_SOURCES,
    well_known::PACKAGE_INSTALL,
    well_known::LOCAL_RANGE,
    well_known::SYNTHETIC,
    well_known::EVAL_WORKLOAD,
    "local_only",
    "package_proxy",
    "dns",
    "workspace_write",
    "credential_read",
    "process_spawn",
    "network_connect",
    "persistence",
    "privilege_escalation",
    "shell",
    "sudo",
    "ci_runner",
    "developer_workstation",
    "production",
    "kubernetes_cluster",
    "localhost",
    "public",
    "internal",
    "secret",
    "pii",
    "declared_dataset",
    "model_weights",
    "retrieved_content",
    "human_provided",
];

/// Known required-evidence class tokens.
pub const CORE_EVIDENCE_TOKENS: &[&str] = &[
    "process",
    "network",
    "filesystem",
    "proxy",
    "containment_receipt",
    "artifact_provenance",
    "identity",
    "k8s_audit",
    "cloud_audit",
    "otel",
];

/// Severity of a lint finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LintLevel {
    Error,
    Warning,
    Info,
}

impl LintLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

/// One lint diagnostic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LintDiagnostic {
    pub level: LintLevel,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Aggregate lint report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LintReport {
    pub schema: String,
    pub ok: bool,
    pub error_count: usize,
    pub warning_count: usize,
    pub diagnostics: Vec<LintDiagnostic>,
}

/// Source layer for an effective policy token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySourceLayer {
    Leaf,
    Parent { index: usize },
    Default,
}

impl PolicySourceLayer {
    pub fn as_str(&self) -> String {
        match self {
            Self::Leaf => "leaf".into(),
            Self::Parent { index } => format!("parent[{index}]"),
            Self::Default => "default".into(),
        }
    }
}

/// Explanation of one resolved token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenResolution {
    pub token: String,
    pub effective: Disposition,
    pub source: PolicySourceLayer,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overridden: Vec<OverriddenValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolution_order: Vec<String>,
}

/// A value that was overridden during inheritance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverriddenValue {
    pub layer: PolicySourceLayer,
    pub disposition: Disposition,
}

/// Full policy explanation for a resolved contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyExplanation {
    pub schema: String,
    pub policy_hash: Option<String>,
    pub fail_closed: bool,
    pub tokens: Vec<TokenResolution>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_selectors: Vec<String>,
}

/// Lint a boundary contract (and optional parents already merged into `contract`
/// when you pass a resolved body — typically lint the leaf + merged separately).
pub fn lint_boundary_contract(contract: &BoundaryContract) -> LintReport {
    let mut diagnostics = Vec::new();

    if let Err(errs) = contract.validate() {
        for e in errs {
            diagnostics.push(LintDiagnostic {
                level: LintLevel::Error,
                code: "structural_validation".into(),
                message: e,
                token: None,
                suggestion: None,
                path: Some("contract".into()),
            });
        }
    }

    // Unknown prohibited tokens.
    for p in &contract.prohibited {
        if !is_known_capability(p) {
            let suggestion = nearest_token(p, CORE_CAPABILITY_TOKENS);
            let level = if contract.fail_closed {
                LintLevel::Error
            } else {
                LintLevel::Warning
            };
            diagnostics.push(LintDiagnostic {
                level,
                code: "unknown_prohibited_token".into(),
                message: format!("unknown prohibited token {p:?}"),
                token: Some(p.clone()),
                suggestion,
                path: Some("prohibited".into()),
            });
        }
    }

    // Unknown required evidence.
    for e in &contract.required_evidence {
        if !is_known_evidence(e) {
            let suggestion = nearest_token(e, CORE_EVIDENCE_TOKENS);
            let level = if contract.fail_closed {
                LintLevel::Error
            } else {
                LintLevel::Warning
            };
            diagnostics.push(LintDiagnostic {
                level,
                code: "unknown_required_evidence".into(),
                message: format!("unknown required_evidence token {e:?}"),
                token: Some(e.clone()),
                suggestion,
                path: Some("required_evidence".into()),
            });
        }
    }

    // Disposition keys.
    for (k, d) in &contract.dispositions {
        if !is_known_capability(k) {
            diagnostics.push(LintDiagnostic {
                level: LintLevel::Warning,
                code: "unknown_disposition_token".into(),
                message: format!("disposition key {k:?} is not a known core token"),
                token: Some(k.clone()),
                suggestion: nearest_token(k, CORE_CAPABILITY_TOKENS),
                path: Some("dispositions".into()),
            });
        }
        if matches!(d, Disposition::Unknown) {
            diagnostics.push(LintDiagnostic {
                level: LintLevel::Error,
                code: "unknown_disposition_value".into(),
                message: format!("disposition for {k:?} is unknown"),
                token: Some(k.clone()),
                suggestion: None,
                path: Some("dispositions".into()),
            });
        }
    }

    // Allowed list tokens (string forms).
    for t in &contract.allowed.targets {
        warn_unknown_allowed(&mut diagnostics, t, "allowed.targets");
    }
    for t in &contract.allowed.identities {
        warn_unknown_allowed(&mut diagnostics, t, "allowed.identities");
    }
    for t in &contract.allowed.tools {
        warn_unknown_allowed(&mut diagnostics, t, "allowed.tools");
    }
    for t in &contract.allowed.effects {
        warn_unknown_allowed(&mut diagnostics, t, "allowed.effects");
    }
    for t in &contract.allowed.data_classes {
        warn_unknown_allowed(&mut diagnostics, t, "allowed.data_classes");
    }
    for t in &contract.allowed.provenance {
        warn_unknown_allowed(&mut diagnostics, t, "allowed.provenance");
    }

    // Network selectors: inert / malformed.
    for (i, entry) in contract.allowed.network.iter().enumerate() {
        match entry {
            ResourceEntry::Legacy(s) if s.trim().is_empty() => {
                diagnostics.push(LintDiagnostic {
                    level: LintLevel::Warning,
                    code: "inert_network_selector".into(),
                    message: "empty network allowlist entry".into(),
                    token: None,
                    suggestion: None,
                    path: Some(format!("allowed.network[{i}]")),
                });
            }
            ResourceEntry::Legacy(s) => {
                // Class-looking tokens get capability check; hostnames are fine.
                let sel = entry.as_selector();
                if matches!(
                    sel,
                    super::selector::ResourceSelector::ClassToken { .. }
                ) && !is_known_capability(s)
                {
                    diagnostics.push(LintDiagnostic {
                        level: LintLevel::Warning,
                        code: "unknown_network_class_token".into(),
                        message: format!("network class token {s:?} is not a known core token"),
                        token: Some(s.clone()),
                        suggestion: nearest_token(s, CORE_CAPABILITY_TOKENS),
                        path: Some(format!("allowed.network[{i}]")),
                    });
                }
            }
            ResourceEntry::Typed(sel) => {
                use super::selector::ResourceSelector;
                use super::normalize::{normalize_cidr, normalize_host, NormalizeOutcome};
                match sel {
                    ResourceSelector::Cidr { value } => {
                        if matches!(normalize_cidr(value), NormalizeOutcome::Unknown { .. }) {
                            diagnostics.push(LintDiagnostic {
                                level: LintLevel::Error,
                                code: "malformed_cidr_selector".into(),
                                message: format!("malformed CIDR selector {value:?}"),
                                token: Some(value.clone()),
                                suggestion: None,
                                path: Some(format!("allowed.network[{i}]")),
                            });
                        }
                    }
                    ResourceSelector::DomainExact { value }
                    | ResourceSelector::DomainSuffix { value } => {
                        if matches!(normalize_host(value.trim_start_matches('.')), NormalizeOutcome::Unknown { .. })
                        {
                            diagnostics.push(LintDiagnostic {
                                level: LintLevel::Error,
                                code: "malformed_domain_selector".into(),
                                message: format!("malformed domain selector {value:?}"),
                                token: Some(value.clone()),
                                suggestion: None,
                                path: Some(format!("allowed.network[{i}]")),
                            });
                        }
                    }
                    ResourceSelector::ClassToken { value } if !is_known_capability(value) => {
                        diagnostics.push(LintDiagnostic {
                            level: LintLevel::Warning,
                            code: "unknown_network_class_token".into(),
                            message: format!("network class token {value:?} is not a known core token"),
                            token: Some(value.clone()),
                            suggestion: nearest_token(value, CORE_CAPABILITY_TOKENS),
                            path: Some(format!("allowed.network[{i}]")),
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    // Unregistered extensions.
    for key in contract.extensions.keys() {
        diagnostics.push(LintDiagnostic {
            level: LintLevel::Info,
            code: "unregistered_extension".into(),
            message: format!("extension key {key:?} is not a registered core extension"),
            token: Some(key.clone()),
            suggestion: None,
            path: Some("extensions".into()),
        });
    }

    // Contradictory: disposition Allowed while also prohibited.
    for p in &contract.prohibited {
        if let Some(d) = contract.dispositions.get(p) {
            if matches!(d, Disposition::Allowed) {
                diagnostics.push(LintDiagnostic {
                    level: LintLevel::Error,
                    code: "contradictory_disposition".into(),
                    message: format!(
                        "token {p:?} is prohibited but dispositions maps it to allowed"
                    ),
                    token: Some(p.clone()),
                    suggestion: Some("remove from prohibited or change disposition".into()),
                    path: Some("dispositions".into()),
                });
            }
        }
    }

    let error_count = diagnostics
        .iter()
        .filter(|d| matches!(d.level, LintLevel::Error))
        .count();
    let warning_count = diagnostics
        .iter()
        .filter(|d| matches!(d.level, LintLevel::Warning))
        .count();

    LintReport {
        schema: "blackbox.boundary.lint/v1".into(),
        ok: error_count == 0,
        error_count,
        warning_count,
        diagnostics,
    }
}

fn warn_unknown_allowed(out: &mut Vec<LintDiagnostic>, token: &str, path: &str) {
    // Hostnames and ranges often appear in allowed lists; only flag snake_case tokens.
    if token.contains('.') || token.contains('/') || token.contains(':') {
        return;
    }
    if !is_known_capability(token) {
        out.push(LintDiagnostic {
            level: LintLevel::Warning,
            code: "unknown_allowed_token".into(),
            message: format!("allowed token {token:?} is not a known core token"),
            token: Some(token.into()),
            suggestion: nearest_token(token, CORE_CAPABILITY_TOKENS),
            path: Some(path.into()),
        });
    }
}

fn is_known_capability(token: &str) -> bool {
    CORE_CAPABILITY_TOKENS.contains(&token) || well_known::ALL.contains(&token)
}

fn is_known_evidence(token: &str) -> bool {
    CORE_EVIDENCE_TOKENS.contains(&token)
}

/// Suggest a near-miss spelling via simple Levenshtein distance ≤ 2.
pub fn nearest_token(input: &str, candidates: &[&str]) -> Option<String> {
    let mut best: Option<(usize, &str)> = None;
    for c in candidates {
        let d = levenshtein(input, c);
        if d == 0 {
            return None;
        }
        if d <= 2 {
            match best {
                Some((bd, _)) if d >= bd => {}
                _ => best = Some((d, c)),
            }
        }
    }
    best.map(|(_, c)| c.to_string())
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Explain effective dispositions for every token present across leaf + parents.
pub fn explain_boundary_policy(
    leaf: &BoundaryContract,
    parents: &[BoundaryContract],
    policy_hash: Option<String>,
) -> PolicyExplanation {
    // Layers root-first then leaf.
    let mut layers: Vec<(&BoundaryContract, PolicySourceLayer)> = Vec::new();
    for (i, p) in parents.iter().enumerate() {
        layers.push((p, PolicySourceLayer::Parent { index: i }));
    }
    layers.push((leaf, PolicySourceLayer::Leaf));

    let mut all_tokens: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (c, _) in &layers {
        all_tokens.extend(c.prohibited.iter().cloned());
        all_tokens.extend(c.dispositions.keys().cloned());
        all_tokens.extend(c.allowed.tools.iter().cloned());
        all_tokens.extend(c.allowed.effects.iter().cloned());
        all_tokens.extend(c.allowed.targets.iter().cloned());
        all_tokens.extend(c.allowed.identities.iter().cloned());
        all_tokens.extend(c.allowed.data_classes.iter().cloned());
        all_tokens.extend(c.allowed.provenance.iter().cloned());
        for e in &c.allowed.network {
            if let ResourceEntry::Legacy(s) = e {
                if !s.contains('.') && !s.contains('/') {
                    all_tokens.insert(s.clone());
                }
            }
            if let ResourceEntry::Typed(super::selector::ResourceSelector::ClassToken { value }) = e
            {
                all_tokens.insert(value.clone());
            }
        }
    }

    let merged = if parents.is_empty() {
        leaf.clone()
    } else {
        let mut acc = parents[0].clone();
        for p in parents.iter().skip(1) {
            acc = BoundaryContract::inherit_from(&acc, p);
        }
        BoundaryContract::inherit_from(&acc, leaf)
    };

    let mut tokens = Vec::new();
    for token in all_tokens {
        let effective = merged.disposition_of(&token);
        let mut overridden = Vec::new();
        let mut resolution_order = Vec::new();
        let mut source = PolicySourceLayer::Default;
        let mut last_disp: Option<Disposition> = None;

        for (c, layer) in &layers {
            let d = c.disposition_of(&token);
            // Only record layers that explicitly mention the token.
            let explicit = c.prohibited.iter().any(|p| p == &token)
                || c.dispositions.contains_key(&token)
                || c.allowed.contains_token(&token);
            if !explicit {
                continue;
            }
            resolution_order.push(format!("{}:{}", layer.as_str(), d.as_str()));
            if let Some(prev) = last_disp {
                if prev != d {
                    overridden.push(OverriddenValue {
                        layer: source.clone(),
                        disposition: prev,
                    });
                }
            }
            source = layer.clone();
            last_disp = Some(d);
        }

        tokens.push(TokenResolution {
            token,
            effective,
            source,
            overridden,
            resolution_order,
        });
    }

    PolicyExplanation {
        schema: "blackbox.boundary.explain/v1".into(),
        policy_hash,
        fail_closed: merged.fail_closed,
        tokens,
        required_evidence: merged.required_evidence.clone(),
        network_selectors: merged.allowed.network_as_strings(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::BoundaryContract;

    #[test]
    fn unknown_prohibited_is_error_when_fail_closed() {
        let mut c = BoundaryContract::new();
        c.fail_closed = true;
        c.prohibited.push("publc_network".into()); // typo
        let report = lint_boundary_contract(&c);
        assert!(!report.ok);
        assert!(report.diagnostics.iter().any(|d| {
            d.code == "unknown_prohibited_token"
                && d.suggestion.as_deref() == Some("public_network")
                && matches!(d.level, LintLevel::Error)
        }));
    }

    #[test]
    fn unknown_required_evidence_warns_when_open() {
        let mut c = BoundaryContract::new();
        c.fail_closed = false;
        c.required_evidence.push("netwrok".into());
        let report = lint_boundary_contract(&c);
        assert!(report.ok);
        assert!(report.diagnostics.iter().any(|d| {
            d.code == "unknown_required_evidence"
                && d.suggestion.as_deref() == Some("network")
                && matches!(d.level, LintLevel::Warning)
        }));
    }

    #[test]
    fn explain_shows_override_trace() {
        let mut parent = BoundaryContract::new();
        parent.allowed.network.push(crate::boundary::ResourceEntry::Legacy(
            "public_network".into(),
        ));
        let mut child = BoundaryContract::new();
        child.prohibited.push("public_network".into());
        let expl = explain_boundary_policy(&child, &[parent], None);
        let t = expl
            .tokens
            .iter()
            .find(|t| t.token == "public_network")
            .unwrap();
        assert_eq!(t.effective, Disposition::HardProhibition);
        assert!(matches!(t.source, PolicySourceLayer::Leaf));
        assert!(!t.overridden.is_empty() || !t.resolution_order.is_empty());
    }

    #[test]
    fn nearest_suggests_typo() {
        assert_eq!(
            nearest_token("publc_network", CORE_CAPABILITY_TOKENS).as_deref(),
            Some("public_network")
        );
    }
}
