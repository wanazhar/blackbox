//! Boundary contract schema (`blackbox.boundary/v1`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::vocab::Disposition;

/// Schema identifier for boundary contracts.
pub const BOUNDARY_SCHEMA: &str = "blackbox.boundary/v1";

/// Map from capability/effect token → disposition.
pub type DispositionMap = BTreeMap<String, Disposition>;

/// Explicitly allowed resource classes under a boundary contract.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedResources {
    /// Target systems or ranges (e.g. `local_range`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// Allowed network destinations / classes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    /// Allowed identities / principals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identities: Vec<String>,
    /// Allowed data classification tokens.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_classes: Vec<String>,
    /// Allowed tools / harness capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    /// Allowed side-effect classes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<String>,
    /// Allowed provenance / answer-source classes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<String>,
}

impl AllowedResources {
    /// True when every list is empty.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
            && self.network.is_empty()
            && self.identities.is_empty()
            && self.data_classes.is_empty()
            && self.tools.is_empty()
            && self.effects.is_empty()
            && self.provenance.is_empty()
    }

    /// Merge `other` into self (union, de-duplicated, sorted).
    pub fn merge_from(&mut self, other: &AllowedResources) {
        merge_unique(&mut self.targets, &other.targets);
        merge_unique(&mut self.network, &other.network);
        merge_unique(&mut self.identities, &other.identities);
        merge_unique(&mut self.data_classes, &other.data_classes);
        merge_unique(&mut self.tools, &other.tools);
        merge_unique(&mut self.effects, &other.effects);
        merge_unique(&mut self.provenance, &other.provenance);
    }
}

fn merge_unique(dst: &mut Vec<String>, src: &[String]) {
    for s in src {
        if !dst.iter().any(|x| x == s) {
            dst.push(s.clone());
        }
    }
    dst.sort();
    dst.dedup();
}

/// Machine-readable purpose, allowed capabilities, prohibitions, and
/// required evidence for a governed run.
///
/// This is the **authored** form (file / experiment / CLI). The stored form
/// is [`crate::boundary::ResolvedBoundary`] after inheritance and hashing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoundaryContract {
    /// Always `blackbox.boundary/v1`.
    pub schema: String,
    /// Human-readable purpose of the run under this contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Explicitly allowed resources.
    #[serde(default)]
    pub allowed: AllowedResources,
    /// Prohibited capability / effect tokens (default disposition: hard_prohibition).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prohibited: Vec<String>,
    /// Per-token disposition overrides (and non-prohibited tokens).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dispositions: DispositionMap,
    /// Evidence classes that must be present for a conclusive evaluation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_evidence: Vec<String>,
    /// When true, missing required evidence fails the boundary gate.
    #[serde(default)]
    pub fail_closed: bool,
    /// Optional parent policy hash this contract inherits from / overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_policy_hash: Option<String>,
    /// Optional free-form labels (environment, eval case, model, harness).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Forward-compatible extension bag (ignored by core evaluators unless registered).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

impl Default for BoundaryContract {
    fn default() -> Self {
        Self {
            schema: BOUNDARY_SCHEMA.into(),
            purpose: None,
            allowed: AllowedResources::default(),
            prohibited: Vec::new(),
            dispositions: BTreeMap::new(),
            required_evidence: Vec::new(),
            fail_closed: false,
            parent_policy_hash: None,
            labels: BTreeMap::new(),
            extensions: BTreeMap::new(),
        }
    }
}

impl BoundaryContract {
    /// Create an empty contract with the correct schema id.
    pub fn new() -> Self {
        Self::default()
    }

    /// Minimal evaluation-style contract matching the epic example.
    pub fn eval_example() -> Self {
        let mut c = Self::new();
        c.purpose = Some("capability evaluation".into());
        c.allowed.targets = vec!["local-range".into()];
        c.allowed.network = vec!["package-proxy.internal".into()];
        c.allowed.identities = vec!["eval-workload".into()];
        c.allowed.data_classes = vec!["synthetic".into()];
        c.prohibited = vec![
            "public_network".into(),
            "production_credentials".into(),
            "external_organizations".into(),
            "undeclared_answer_sources".into(),
        ];
        c.required_evidence = vec![
            "process".into(),
            "network".into(),
            "containment_receipt".into(),
            "artifact_provenance".into(),
        ];
        c.fail_closed = true;
        c
    }

    /// Validate structural rules (schema id, non-empty purpose when governed).
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if self.schema != BOUNDARY_SCHEMA {
            errs.push(format!(
                "unsupported schema {:?} (expected {})",
                self.schema, BOUNDARY_SCHEMA
            ));
        }
        // Prohibited tokens should not also appear as allowed tools/effects without
        // an explicit disposition override — warn as error for determinism.
        for p in &self.prohibited {
            if self.allowed.tools.iter().any(|t| t == p)
                || self.allowed.effects.iter().any(|e| e == p)
                || self.allowed.network.iter().any(|n| n == p)
                || self.allowed.targets.iter().any(|t| t == p)
                || self.allowed.identities.iter().any(|i| i == p)
                || self.allowed.data_classes.iter().any(|d| d == p)
                || self.allowed.provenance.iter().any(|d| d == p)
            {
                errs.push(format!(
                    "token {p:?} is both prohibited and listed under allowed"
                ));
            }
        }
        for (k, d) in &self.dispositions {
            if matches!(d, Disposition::Unknown) {
                errs.push(format!("disposition for {k:?} is unknown"));
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    /// Effective disposition for a token.
    ///
    /// Order: explicit `dispositions` map → prohibited list → allowed lists → unknown.
    pub fn disposition_of(&self, token: &str) -> Disposition {
        if let Some(d) = self.dispositions.get(token) {
            return *d;
        }
        if self.prohibited.iter().any(|p| p == token) {
            return Disposition::HardProhibition;
        }
        if self.allowed.tools.iter().any(|t| t == token)
            || self.allowed.effects.iter().any(|e| e == token)
            || self.allowed.network.iter().any(|n| n == token)
            || self.allowed.targets.iter().any(|t| t == token)
            || self.allowed.identities.iter().any(|i| i == token)
            || self.allowed.data_classes.iter().any(|d| d == token)
            || self.allowed.provenance.iter().any(|d| d == token)
        {
            return Disposition::Allowed;
        }
        Disposition::Unknown
    }

    /// Merge a child contract over a parent (child wins on conflicts).
    ///
    /// - `allowed` is unioned then child-prohibited tokens removed
    /// - `prohibited` is unioned
    /// - `dispositions` child overrides parent keys
    /// - `required_evidence` is unioned
    /// - `fail_closed` is OR (child or parent)
    /// - `labels` / `extensions` child overrides parent keys
    pub fn inherit_from(parent: &Self, child: &Self) -> Self {
        let mut out = parent.clone();
        out.schema = BOUNDARY_SCHEMA.into();
        if child.purpose.is_some() {
            out.purpose = child.purpose.clone();
        }
        out.allowed.merge_from(&child.allowed);
        for p in &child.prohibited {
            if !out.prohibited.iter().any(|x| x == p) {
                out.prohibited.push(p.clone());
            }
            // Child prohibition removes from allowed sets.
            out.allowed.targets.retain(|t| t != p);
            out.allowed.network.retain(|t| t != p);
            out.allowed.identities.retain(|t| t != p);
            out.allowed.data_classes.retain(|t| t != p);
            out.allowed.tools.retain(|t| t != p);
            out.allowed.effects.retain(|t| t != p);
            out.allowed.provenance.retain(|t| t != p);
        }
        out.prohibited.sort();
        out.prohibited.dedup();
        for (k, v) in &child.dispositions {
            out.dispositions.insert(k.clone(), *v);
        }
        for e in &child.required_evidence {
            if !out.required_evidence.iter().any(|x| x == e) {
                out.required_evidence.push(e.clone());
            }
        }
        out.required_evidence.sort();
        out.required_evidence.dedup();
        out.fail_closed = parent.fail_closed || child.fail_closed;
        if child.parent_policy_hash.is_some() {
            out.parent_policy_hash = child.parent_policy_hash.clone();
        }
        for (k, v) in &child.labels {
            out.labels.insert(k.clone(), v.clone());
        }
        for (k, v) in &child.extensions {
            out.extensions.insert(k.clone(), v.clone());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_example_validates() {
        let c = BoundaryContract::eval_example();
        c.validate().unwrap();
        assert_eq!(
            c.disposition_of("public_network"),
            Disposition::HardProhibition
        );
        assert_eq!(c.disposition_of("local-range"), Disposition::Allowed);
        assert_eq!(c.disposition_of("something_else"), Disposition::Unknown);
    }

    #[test]
    fn prohibited_and_allowed_conflict() {
        let mut c = BoundaryContract::new();
        c.prohibited.push("shell".into());
        c.allowed.tools.push("shell".into());
        assert!(c.validate().is_err());
    }

    #[test]
    fn inherit_child_prohibition_removes_allowed() {
        let mut parent = BoundaryContract::new();
        parent.allowed.network.push("public_network".into());
        let mut child = BoundaryContract::new();
        child.prohibited.push("public_network".into());
        let merged = BoundaryContract::inherit_from(&parent, &child);
        assert!(!merged.allowed.network.iter().any(|n| n == "public_network"));
        assert!(merged.prohibited.iter().any(|p| p == "public_network"));
    }

    #[test]
    fn serde_roundtrip_epic_shape() {
        let c = BoundaryContract::eval_example();
        let json = serde_json::to_string_pretty(&c).unwrap();
        assert!(json.contains(BOUNDARY_SCHEMA));
        let back: BoundaryContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}
