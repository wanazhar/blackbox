//! Resolve boundary contracts: inheritance, canonical JSON, policy hash.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::contract::{BoundaryContract, BOUNDARY_SCHEMA};

/// Options controlling policy resolution.
#[derive(Debug, Clone, Default)]
pub struct ResolveOpts {
    /// Optional parent contracts (experiment → run order: last is closest parent).
    pub parents: Vec<BoundaryContract>,
    /// Override fail_closed after merge.
    pub force_fail_closed: Option<bool>,
    /// Stamp time (defaults to now).
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Immutable resolved boundary stored with a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedBoundary {
    /// Schema identifier (always `blackbox.boundary/v1`).
    pub schema: String,
    /// Owning run id (may be empty before attach).
    pub run_id: String,
    /// SHA-256 hex of the canonical resolved contract body.
    pub policy_hash: String,
    /// When resolution occurred.
    pub resolved_at: DateTime<Utc>,
    /// Fully merged contract (the source of truth for evaluation).
    pub contract: BoundaryContract,
    /// Policy hashes of parents in inheritance order (root first), when known.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inheritance_chain: Vec<String>,
}

impl ResolvedBoundary {
    /// Attach (or re-bind) to a run id without changing the policy hash.
    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = run_id.into();
        self
    }
}

/// Load a boundary contract from a JSON file.
pub fn load_boundary_file(path: &Path) -> anyhow::Result<BoundaryContract> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read boundary file {}: {e}", path.display()))?;
    let contract: BoundaryContract = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("parse boundary file {}: {e}", path.display()))?;
    if let Err(errs) = contract.validate() {
        anyhow::bail!(
            "invalid boundary contract in {}: {}",
            path.display(),
            errs.join("; ")
        );
    }
    Ok(contract)
}

/// Resolve a leaf contract (optionally over parents) into a hashed, frozen form.
///
/// Canonical hash input is deterministic JSON of the **merged contract only**
/// (sorted keys via `serde_json::Value` + `BTreeMap` fields). Timestamps and
/// run_id are excluded from the hash so the same policy yields the same hash
/// across runs.
pub fn resolve_boundary(
    leaf: &BoundaryContract,
    opts: ResolveOpts,
) -> anyhow::Result<ResolvedBoundary> {
    if let Err(errs) = leaf.validate() {
        anyhow::bail!("invalid leaf boundary contract: {}", errs.join("; "));
    }
    for (i, p) in opts.parents.iter().enumerate() {
        if let Err(errs) = p.validate() {
            anyhow::bail!(
                "invalid parent boundary contract [{i}]: {}",
                errs.join("; ")
            );
        }
    }

    let mut inheritance_chain = Vec::new();
    let mut merged = if opts.parents.is_empty() {
        leaf.clone()
    } else {
        let mut acc = opts.parents[0].clone();
        inheritance_chain.push(policy_hash_of(&acc)?);
        for p in opts.parents.iter().skip(1) {
            acc = BoundaryContract::inherit_from(&acc, p);
            inheritance_chain.push(policy_hash_of(p)?);
        }
        BoundaryContract::inherit_from(&acc, leaf)
    };

    merged.schema = BOUNDARY_SCHEMA.into();
    if let Some(fc) = opts.force_fail_closed {
        merged.fail_closed = fc;
    }
    // Point parent_policy_hash at the nearest parent when not already set.
    if merged.parent_policy_hash.is_none() {
        if let Some(last) = inheritance_chain.last() {
            merged.parent_policy_hash = Some(last.clone());
        }
    }

    if let Err(errs) = merged.validate() {
        anyhow::bail!("resolved boundary failed validation: {}", errs.join("; "));
    }

    let policy_hash = policy_hash_of(&merged)?;
    let resolved_at = opts.resolved_at.unwrap_or_else(Utc::now);

    Ok(ResolvedBoundary {
        schema: BOUNDARY_SCHEMA.into(),
        run_id: String::new(),
        policy_hash,
        resolved_at,
        contract: merged,
        inheritance_chain,
    })
}

/// Compute the SHA-256 hex policy hash of a contract (canonical JSON).
pub fn policy_hash_of(contract: &BoundaryContract) -> anyhow::Result<String> {
    let canonical = canonical_json(contract)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Deterministic JSON serialization for hashing.
///
/// Uses `serde_json::to_value` then re-serializes; `BTreeMap` fields already
/// sort keys, and arrays keep author order (normalized during inherit).
fn canonical_json(contract: &BoundaryContract) -> anyhow::Result<String> {
    let value = serde_json::to_value(contract)?;
    // serde_json::to_string on a Value emits compact form with BTreeMap-ordered objects.
    Ok(serde_json::to_string(&value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::BoundaryContract;

    #[test]
    fn hash_stable_across_calls() {
        let c = BoundaryContract::eval_example();
        let h1 = policy_hash_of(&c).unwrap();
        let h2 = policy_hash_of(&c).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn resolve_without_parents() {
        let c = BoundaryContract::eval_example();
        let r = resolve_boundary(&c, ResolveOpts::default()).unwrap();
        assert_eq!(r.schema, BOUNDARY_SCHEMA);
        assert_eq!(r.policy_hash, policy_hash_of(&c).unwrap());
        assert!(r.inheritance_chain.is_empty());
        assert!(r.contract.fail_closed);
    }

    #[test]
    fn resolve_with_parent_inheritance() {
        let mut parent = BoundaryContract::new();
        parent.purpose = Some("experiment".into());
        parent.allowed.targets.push("local-range".into());
        parent.required_evidence.push("process".into());

        let mut child = BoundaryContract::new();
        child.purpose = Some("run".into());
        child.prohibited.push("public_network".into());
        child.required_evidence.push("network".into());
        child.fail_closed = true;

        let r = resolve_boundary(
            &child,
            ResolveOpts {
                parents: vec![parent.clone()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(r.contract.purpose.as_deref(), Some("run"));
        assert!(r
            .contract
            .allowed
            .targets
            .iter()
            .any(|t| t == "local-range"));
        assert!(r.contract.prohibited.iter().any(|p| p == "public_network"));
        assert_eq!(
            r.contract.required_evidence,
            vec!["network".to_string(), "process".to_string()]
        );
        assert!(r.contract.fail_closed);
        assert_eq!(r.inheritance_chain.len(), 1);
        assert_eq!(
            r.contract.parent_policy_hash.as_deref(),
            Some(r.inheritance_chain[0].as_str())
        );
    }

    #[test]
    fn hash_independent_of_run_id_and_time() {
        let c = BoundaryContract::eval_example();
        let r1 = resolve_boundary(&c, ResolveOpts::default()).unwrap();
        let r2 = resolve_boundary(
            &c,
            ResolveOpts {
                resolved_at: Some(Utc::now()),
                ..Default::default()
            },
        )
        .unwrap()
        .with_run_id("other-run");
        assert_eq!(r1.policy_hash, r2.policy_hash);
    }
}
