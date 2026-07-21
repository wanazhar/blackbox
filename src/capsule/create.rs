//! Create a reproducibility capsule from a run.

use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::core::blob::BlobReference;
use crate::core::run::Run;
use crate::crypto::content_key;
use crate::export::portable::export_portable;
use crate::storage::TraceStore;
use crate::verification::VerificationReceipt;
use crate::workspace_manifest::WorkspaceManifest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// `CapsuleCompleteness` classification.
pub enum CapsuleCompleteness {
    /// `ByteExact` variant.
    ByteExact,
    /// `SanitizedComplete` variant.
    SanitizedComplete,
    /// `Partial` variant.
    Partial,
    /// `MetadataOnly` variant.
    MetadataOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `TransformationEntry` value.
pub struct TransformationEntry {
    /// Filesystem path.
    pub path: String,
    /// Transformation.
    pub transformation: String,
    /// Original hash available.
    pub original_hash_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Capsule hash.
    pub capsule_hash: Option<String>,
    /// Byte exact.
    pub byte_exact: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `CapsuleManifest` value.
pub struct CapsuleManifest {
    /// Schema identifier string.
    pub schema: String,
    /// Version string or number.
    pub version: u32,
    /// Creation timestamp.
    pub created_at: String,
    /// Source run id.
    pub source_run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Experiment id.
    pub experiment_id: Option<String>,
    /// Command argv.
    pub command: Vec<String>,
    /// Command fidelity.
    pub command_fidelity: String,
    /// Completeness.
    pub completeness: CapsuleCompleteness,
    #[serde(default)]
    /// Transformation ledger.
    pub transformation_ledger: Vec<TransformationEntry>,
    #[serde(default)]
    /// Limitations.
    pub limitations: Vec<String>,
    /// Portable archive sha256.
    pub portable_archive_sha256: String,
    /// Manifest sha256.
    pub manifest_sha256: String,
    #[serde(default)]
    /// Verification receipt ids.
    pub verification_receipt_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Git commit.
    pub git_commit: Option<String>,
    /// Explicit statement: model output is not deterministic replay.
    pub model_replay_deterministic: bool,
}

#[derive(Debug, Clone, Default)]
/// `CapsuleCreateOpts` value.
pub struct CapsuleCreateOpts {
    /// Experiment id.
    pub experiment_id: Option<String>,
    /// Include receipts.
    pub include_receipts: bool,
}

/// Create a capsule JSON document wrapping a portable archive + completeness metadata.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `create_capsule` — see module docs for full workflow.
/// ```
pub async fn create_capsule(
    store: &dyn TraceStore,
    run: &Run,
    receipts: &[VerificationReceipt],
    workspace: Option<&WorkspaceManifest>,
    opts: CapsuleCreateOpts,
) -> anyhow::Result<String> {
    let events = store.get_events(&run.id).await?;
    // Capsules always redact for safe sharing unless caller used insecure path elsewhere.
    let portable = export_portable(store, run, &events, true).await?;
    // Hash the canonical JSON value embedded in the capsule rather than the
    // exporter’s presentation bytes.  The capsule itself is pretty-printed,
    // so preserving the exporter's whitespace here would make verification
    // dependent on formatting rather than archive content.
    let portable_value: serde_json::Value = serde_json::from_str(&portable)?;
    let portable_hash = content_key(&serde_json::to_vec(&portable_value)?);

    let mut ledger = Vec::new();
    let mut completeness = CapsuleCompleteness::ByteExact;
    let mut limitations = vec![
        "model output is not deterministic replay".into(),
        "capsule uses redacted portable export (sanitized)".into(),
    ];

    if let Some(wm) = workspace {
        for e in &wm.entries {
            if e.transformation.is_some() || !e.byte_exact {
                completeness = CapsuleCompleteness::SanitizedComplete;
                ledger.push(TransformationEntry {
                    path: e.path.clone(),
                    transformation: format!("{:?}", e.transformation),
                    original_hash_available: false,
                    capsule_hash: e.content_hash.clone(),
                    byte_exact: false,
                });
            }
            if !e.complete {
                completeness = CapsuleCompleteness::Partial;
                limitations.push(format!("{}: incomplete at capture", e.path));
            }
        }
        if !wm.capture_complete {
            completeness = CapsuleCompleteness::Partial;
            limitations.extend(wm.limitations.iter().cloned());
        }
    } else {
        completeness = CapsuleCompleteness::SanitizedComplete;
        limitations.push("no workspace manifest attached; file-level byte fidelity unknown".into());
    }

    if events.is_empty() {
        completeness = CapsuleCompleteness::MetadataOnly;
    }

    // Never claim byte_exact for redacted portable.
    if matches!(completeness, CapsuleCompleteness::ByteExact) {
        completeness = CapsuleCompleteness::SanitizedComplete;
    }

    let receipt_ids: Vec<String> = if opts.include_receipts {
        receipts.iter().map(|r| r.id.clone()).collect()
    } else {
        Vec::new()
    };

    let mut manifest = CapsuleManifest {
        schema: "blackbox.capsule/v1".into(),
        version: 1,
        created_at: Utc::now().to_rfc3339(),
        source_run_id: run.id.clone(),
        experiment_id: opts.experiment_id,
        command: run.command.clone(),
        command_fidelity: "recorded_argv".into(),
        completeness,
        transformation_ledger: ledger,
        limitations,
        portable_archive_sha256: portable_hash,
        manifest_sha256: String::new(),
        verification_receipt_ids: receipt_ids,
        git_commit: None,
        model_replay_deterministic: false,
    };

    // Hash manifest without its own hash field.
    let for_hash = serde_json::to_vec(&manifest)?;
    manifest.manifest_sha256 = content_key(&for_hash);

    // Embed portable as a named section (not content-addressed in map — already hashed).
    let doc = serde_json::json!({
        "capsule": manifest,
        "portable": portable_value,
        "receipts": receipts,
    });
    Ok(serde_json::to_string_pretty(&doc)?)
}

/// Write capsule to path.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `write_capsule_file` — see module docs for full workflow.
/// ```
pub async fn write_capsule_file(
    store: &dyn TraceStore,
    run: &Run,
    receipts: &[VerificationReceipt],
    path: &Path,
    opts: CapsuleCreateOpts,
) -> anyhow::Result<CapsuleManifest> {
    let json = create_capsule(store, run, receipts, None, opts).await?;
    std::fs::write(path, &json)?;
    let v: serde_json::Value = serde_json::from_str(&json)?;
    let manifest: CapsuleManifest = serde_json::from_value(v["capsule"].clone())?;
    Ok(manifest)
}

/// Helper used by tests to store a small blob under a known path key.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `ensure_blob` — see module docs for full workflow.
/// ```
pub async fn ensure_blob(store: &dyn TraceStore, data: &[u8]) -> anyhow::Result<BlobReference> {
    store.store_blob(data).await
}
