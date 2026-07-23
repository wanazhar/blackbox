//! Boundary contract schema (`blackbox.boundary/v1`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::selector::{network_entries_allow, MatchExplanation, ResourceEntry, ResourceSelector};
use super::vocab::Disposition;

/// Schema identifier for boundary contracts.
pub const BOUNDARY_SCHEMA: &str = "blackbox.boundary/v1";

/// Map from capability/effect token → disposition.
pub type DispositionMap = BTreeMap<String, Disposition>;

/// Explicitly allowed resource classes under a boundary contract.
///
/// Network entries accept legacy strings **or** typed [`ResourceSelector`]
/// objects (1.8). Destination authorization uses typed matchers, never raw
/// substring containment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedResources {
    /// Target systems or ranges (e.g. `local_range`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// Allowed network destinations / classes (string tokens or typed selectors).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<ResourceEntry>,
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
    /// Allowed filesystem path selectors (1.8).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<ResourceEntry>,
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
            && self.paths.is_empty()
    }

    /// Merge `other` into self (union, de-duplicated, sorted).
    pub fn merge_from(&mut self, other: &AllowedResources) {
        merge_unique(&mut self.targets, &other.targets);
        merge_entries(&mut self.network, &other.network);
        merge_unique(&mut self.identities, &other.identities);
        merge_unique(&mut self.data_classes, &other.data_classes);
        merge_unique(&mut self.tools, &other.tools);
        merge_unique(&mut self.effects, &other.effects);
        merge_unique(&mut self.provenance, &other.provenance);
        merge_entries(&mut self.paths, &other.paths);
    }

    /// Whether a destination is authorized by typed network selectors.
    pub fn network_allows(&self, destination: &str) -> MatchExplanation {
        network_entries_allow(&self.network, destination)
    }

    /// Flatten network entries to string forms for provenance/source allow-lists.
    pub fn network_as_strings(&self) -> Vec<String> {
        self.network
            .iter()
            .map(|e| match e {
                ResourceEntry::Legacy(s) => s.clone(),
                ResourceEntry::Typed(sel) => selector_display(sel),
            })
            .collect()
    }

    /// True when a prohibited token appears in an allowed list.
    pub fn contains_token(&self, token: &str) -> bool {
        self.targets.iter().any(|t| t == token)
            || self.network.iter().any(|n| n.matches_token(token))
            || self.identities.iter().any(|i| i == token)
            || self.data_classes.iter().any(|d| d == token)
            || self.tools.iter().any(|t| t == token)
            || self.effects.iter().any(|e| e == token)
            || self.provenance.iter().any(|d| d == token)
            || self.paths.iter().any(|p| p.matches_token(token))
    }

    /// Remove a token from all string lists and matching resource entries.
    pub fn retain_not_token(&mut self, token: &str) {
        self.targets.retain(|t| t != token);
        self.network.retain(|t| !t.matches_token(token));
        self.identities.retain(|t| t != token);
        self.data_classes.retain(|t| t != token);
        self.tools.retain(|t| t != token);
        self.effects.retain(|t| t != token);
        self.provenance.retain(|t| t != token);
        self.paths.retain(|t| !t.matches_token(token));
    }
}

fn selector_display(sel: &ResourceSelector) -> String {
    match sel {
        ResourceSelector::DomainExact { value }
        | ResourceSelector::DomainSuffix { value }
        | ResourceSelector::Cidr { value }
        | ResourceSelector::IpExact { value }
        | ResourceSelector::UnixSocket { value }
        | ResourceSelector::PathExact { value }
        | ResourceSelector::PathPrefix { value }
        | ResourceSelector::Identity { value }
        | ResourceSelector::Tool { value }
        | ResourceSelector::Effect { value }
        | ResourceSelector::ProvenanceClass { value }
        | ResourceSelector::ClassToken { value } => value.clone(),
        ResourceSelector::UrlPrefix {
            scheme,
            host,
            path,
        } => format!(
            "{}://{}{}",
            scheme.as_deref().unwrap_or("*"),
            host,
            path.as_deref().unwrap_or("")
        ),
        ResourceSelector::Port { value } => value.to_string(),
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

fn merge_entries(dst: &mut Vec<ResourceEntry>, src: &[ResourceEntry]) {
    for s in src {
        let key = s.key();
        if !dst.iter().any(|x| x.key() == key) {
            dst.push(s.clone());
        }
    }
    dst.sort_by_key(|a| a.key());
    dst.dedup_by(|a, b| a.key() == b.key());
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
        c.allowed.network = vec![ResourceEntry::Legacy("package-proxy.internal".into())];
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
            if self.allowed.contains_token(p) {
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
        if self.allowed.contains_token(token) {
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
            out.allowed.retain_not_token(p);
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
        parent
            .allowed
            .network
            .push(ResourceEntry::Legacy("public_network".into()));
        let mut child = BoundaryContract::new();
        child.prohibited.push("public_network".into());
        let merged = BoundaryContract::inherit_from(&parent, &child);
        assert!(!merged
            .allowed
            .network
            .iter()
            .any(|n| n.matches_token("public_network")));
        assert!(merged.prohibited.iter().any(|p| p == "public_network"));
    }

    #[test]
    fn typed_network_selector_serde() {
        let mut c = BoundaryContract::new();
        c.allowed.network.push(ResourceEntry::Typed(
            ResourceSelector::DomainExact {
                value: "packages.internal".into(),
            },
        ));
        c.allowed.network.push(ResourceEntry::Legacy("10.0.0.0/8".into()));
        let json = serde_json::to_string(&c).unwrap();
        let back: BoundaryContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
        assert!(back.allowed.network_allows("https://packages.internal/x").is_allow());
        assert!(back.allowed.network_allows("10.1.2.3").is_allow());
        assert!(!back
            .allowed
            .network_allows("attacker-packages.internal")
            .is_allow());
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
