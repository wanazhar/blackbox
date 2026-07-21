//! Capsule inspect and integrity verification (no source-store mutation).

use serde::{Deserialize, Serialize};

use crate::capsule::create::{CapsuleCompleteness, CapsuleManifest};
use crate::crypto::content_key;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `CapsuleInspectReport` value.
pub struct CapsuleInspectReport {
    /// Schema identifier string.
    pub schema: String,
    /// Manifest.
    pub manifest: CapsuleManifest,
    /// Integrity ok.
    pub integrity_ok: bool,
    /// Issues.
    pub issues: Vec<String>,
    /// Completeness.
    pub completeness: CapsuleCompleteness,
    /// Model replay deterministic.
    pub model_replay_deterministic: bool,
}

/// Inspect capsule.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `inspect_capsule` — see module docs for full workflow.
/// ```
pub fn inspect_capsule(json: &str) -> anyhow::Result<CapsuleInspectReport> {
    let root: serde_json::Value = serde_json::from_str(json)?;
    let manifest: CapsuleManifest = serde_json::from_value(
        root.get("capsule")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing capsule object"))?,
    )?;
    let mut issues = Vec::new();
    let mut integrity_ok = true;

    let portable = root
        .get("portable")
        .ok_or_else(|| anyhow::anyhow!("missing portable archive"))?;
    let portable_hash = content_key(&serde_json::to_vec(portable)?);
    if portable_hash != manifest.portable_archive_sha256 {
        integrity_ok = false;
        issues.push(format!(
            "portable_archive_sha256 mismatch (declared {}, recomputed {portable_hash})",
            manifest.portable_archive_sha256
        ));
    }

    let mut m = manifest.clone();
    let declared = m.manifest_sha256.clone();
    m.manifest_sha256 = String::new();
    let recomputed = content_key(&serde_json::to_vec(&m)?);
    if recomputed != declared && !declared.is_empty() {
        integrity_ok = false;
        issues.push(format!(
            "manifest_sha256 mismatch (declared {declared}, recomputed {recomputed})"
        ));
    }

    if matches!(manifest.completeness, CapsuleCompleteness::ByteExact)
        && !manifest.transformation_ledger.is_empty()
    {
        integrity_ok = false;
        issues.push("capsule claims byte_exact but transformation_ledger is non-empty".into());
    }

    if manifest.model_replay_deterministic {
        integrity_ok = false;
        issues.push("capsule incorrectly claims deterministic model replay".into());
    }

    Ok(CapsuleInspectReport {
        schema: "blackbox.capsule.inspect/v1".into(),
        completeness: manifest.completeness.clone(),
        model_replay_deterministic: manifest.model_replay_deterministic,
        manifest,
        integrity_ok,
        issues,
    })
}

/// Verify capsule integrity.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `verify_capsule_integrity` — see module docs for full workflow.
/// ```
pub fn verify_capsule_integrity(json: &str) -> anyhow::Result<bool> {
    let report = inspect_capsule(json)?;
    Ok(report.integrity_ok)
}
