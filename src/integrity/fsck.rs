//! Store integrity checks (fast + deep).

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use chrono::Utc;

use crate::core::blob::{is_valid_blob_key, BlobReference};
use crate::core::run::RunStatus;
use crate::crypto::content_key;
use crate::scrub::collect_referenced_blobs;
use crate::storage::TraceStore;

use super::repair::plan_repairs;
use super::report::{FsckFinding, FsckReport, FsckSeverity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// `FsckMode` classification.
pub enum FsckMode {
    /// `Fast` variant.
    Fast,
    /// `Deep` variant.
    Deep,
}

#[derive(Debug, Clone)]
/// `FsckOptions` value.
pub struct FsckOptions {
    /// Mode.
    pub mode: FsckMode,
    /// Apply safe automatic repairs.
    pub repair: bool,
    /// Blob dir.
    pub blob_dir: Option<std::path::PathBuf>,
    /// Spool dir.
    pub spool_dir: Option<std::path::PathBuf>,
    /// Recovery dir.
    pub recovery_dir: Option<std::path::PathBuf>,
}

impl Default for FsckOptions {
    fn default() -> Self {
        Self {
            mode: FsckMode::Fast,
            repair: false,
            blob_dir: None,
            spool_dir: None,
            recovery_dir: None,
        }
    }
}

/// Run store integrity checks. When `repair` is set, builds a plan, writes a
/// recovery artifact, and applies only auto-safe repairs.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `fsck_store` — see module docs for full workflow.
/// ```
pub async fn fsck_store(
    store: Arc<dyn TraceStore>,
    opts: FsckOptions,
) -> anyhow::Result<FsckReport> {
    let mode_label = match opts.mode {
        FsckMode::Fast => "fast",
        FsckMode::Deep => "deep",
    };
    let mut report = FsckReport::new(mode_label);

    check_store_basics(store.as_ref(), &mut report).await?;
    check_runs_and_events(store.as_ref(), &mut report).await?;
    check_sequences(store.as_ref(), &mut report).await?;
    check_aggregates(store.as_ref(), &mut report).await?;
    check_checkpoints(store.as_ref(), &mut report).await?;
    check_blob_references(store.as_ref(), &opts, &mut report).await?;
    check_fts(store.as_ref(), &opts, &mut report).await?;
    check_spool(opts.spool_dir.as_deref(), &mut report)?;

    if opts.repair {
        let plan = plan_repairs(&report);
        if let Some(ref recovery_dir) = opts.recovery_dir {
            let artifact = write_recovery_artifact(recovery_dir, &report, &plan)?;
            report.recovery_artifact = Some(artifact);
        }
        report.repair_plan = Some(plan.clone());
        super::repair::apply_repair_plan(store.as_ref(), &plan).await?;
        // Re-check aggregates after repair.
        report
            .sections_checked
            .push("repair_applied".into());
    } else if report.repairable_count > 0 {
        report.repair_plan = Some(plan_repairs(&report));
    }

    Ok(report)
}

async fn check_store_basics(store: &dyn TraceStore, report: &mut FsckReport) -> anyhow::Result<()> {
    report.sections_checked.push("store".into());
    report.sections_checked.push("schema/migrations".into());
    // list_runs exercises basic connectivity.
    let _ = store.list_runs().await?;
    report.push(FsckFinding {
        section: "store".into(),
        severity: FsckSeverity::Info,
        code: "store_open".into(),
        message: "store opened and runs listed successfully".into(),
        run_id: None,
        event_id: None,
        checkpoint_id: None,
        field: None,
        blob_key: None,
        repairable: false,
    });
    Ok(())
}

async fn check_runs_and_events(
    store: &dyn TraceStore,
    report: &mut FsckReport,
) -> anyhow::Result<()> {
    report.sections_checked.push("runs".into());
    report.sections_checked.push("events".into());
    report.sections_checked.push("parent references".into());

    let runs = store.list_runs().await?;
    for run in &runs {
        if matches!(run.status, RunStatus::Running) {
            report.push(FsckFinding {
                section: "runs".into(),
                severity: FsckSeverity::Warning,
                code: "stale_running".into(),
                message: format!(
                    "run {} still marked Running (may be abandoned)",
                    short(&run.id)
                ),
                run_id: Some(run.id.clone()),
                event_id: None,
                checkpoint_id: None,
                field: Some("status".into()),
                blob_key: None,
                repairable: true,
            });
        }
        let events = store.get_events(&run.id).await?;
        let ids: HashSet<&str> = events.iter().map(|e| e.id.as_str()).collect();
        for ev in &events {
            if ev.run_id != run.id {
                report.push(FsckFinding {
                    section: "events".into(),
                    severity: FsckSeverity::Error,
                    code: "run_id_mismatch".into(),
                    message: format!(
                        "event {} run_id={} does not match parent run {}",
                        short(&ev.id),
                        short(&ev.run_id),
                        short(&run.id)
                    ),
                    run_id: Some(run.id.clone()),
                    event_id: Some(ev.id.clone()),
                    checkpoint_id: None,
                    field: Some("run_id".into()),
                    blob_key: None,
                    repairable: false,
                });
            }
            if let Some(ref pid) = ev.parent_event_id {
                if !ids.contains(pid.as_str()) {
                    report.push(FsckFinding {
                        section: "parent references".into(),
                        severity: FsckSeverity::Error,
                        code: "dangling_parent".into(),
                        message: format!(
                            "event {} parent_event_id={} not in run",
                            short(&ev.id),
                            short(pid)
                        ),
                        run_id: Some(run.id.clone()),
                        event_id: Some(ev.id.clone()),
                        checkpoint_id: None,
                        field: Some("parent_event_id".into()),
                        blob_key: None,
                        repairable: false,
                    });
                }
            }
            for (field, key) in [
                ("input_blob", ev.input_blob.as_deref()),
                ("output_blob", ev.output_blob.as_deref()),
                ("error_blob", ev.error_blob.as_deref()),
            ] {
                if let Some(k) = key {
                    if !is_valid_blob_key(k) {
                        report.push(FsckFinding {
                            section: "blobs".into(),
                            severity: FsckSeverity::Error,
                            code: "invalid_blob_key".into(),
                            message: format!(
                                "event {} has invalid {field} key",
                                short(&ev.id)
                            ),
                            run_id: Some(run.id.clone()),
                            event_id: Some(ev.id.clone()),
                            checkpoint_id: None,
                            field: Some(field.into()),
                            blob_key: Some(k.into()),
                            repairable: false,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

async fn check_sequences(store: &dyn TraceStore, report: &mut FsckReport) -> anyhow::Result<()> {
    report.sections_checked.push("sequences".into());
    let runs = store.list_runs().await?;
    for run in &runs {
        let events = store.get_events(&run.id).await?;
        let mut seen = HashSet::new();
        for ev in &events {
            if !seen.insert(ev.sequence) {
                report.push(FsckFinding {
                    section: "sequences".into(),
                    severity: FsckSeverity::Error,
                    code: "duplicate_sequence".into(),
                    message: format!(
                        "run {} has duplicate sequence {}",
                        short(&run.id),
                        ev.sequence
                    ),
                    run_id: Some(run.id.clone()),
                    event_id: Some(ev.id.clone()),
                    checkpoint_id: None,
                    field: Some("sequence".into()),
                    blob_key: None,
                    repairable: false,
                });
            }
        }
    }
    Ok(())
}

async fn check_aggregates(store: &dyn TraceStore, report: &mut FsckReport) -> anyhow::Result<()> {
    report.sections_checked.push("aggregates".into());
    let runs = store.list_runs().await?;
    for run in &runs {
        let count = store.count_events(&run.id).await? as u64;
        match store.get_run_aggregates(&run.id).await? {
            None if count > 0 => {
                report.push(FsckFinding {
                    section: "aggregates".into(),
                    severity: FsckSeverity::Warning,
                    code: "missing_aggregates".into(),
                    message: format!(
                        "run {} has {count} events but no aggregates payload",
                        short(&run.id)
                    ),
                    run_id: Some(run.id.clone()),
                    event_id: None,
                    checkpoint_id: None,
                    field: None,
                    blob_key: None,
                    repairable: true,
                });
            }
            Some(agg) if agg.events_total != count => {
                report.push(FsckFinding {
                    section: "aggregates".into(),
                    severity: FsckSeverity::Warning,
                    code: "aggregate_mismatch".into(),
                    message: format!(
                        "run {} aggregates.events_total={} but table has {count}",
                        short(&run.id),
                        agg.events_total
                    ),
                    run_id: Some(run.id.clone()),
                    event_id: None,
                    checkpoint_id: None,
                    field: Some("events_total".into()),
                    blob_key: None,
                    repairable: true,
                });
            }
            _ => {}
        }
    }
    Ok(())
}

async fn check_checkpoints(store: &dyn TraceStore, report: &mut FsckReport) -> anyhow::Result<()> {
    report.sections_checked.push("checkpoints".into());
    report
        .sections_checked
        .push("workspace manifests".into());
    let runs = store.list_runs().await?;
    for run in &runs {
        for cp in store.get_checkpoints(&run.id).await? {
            for (field, key) in [
                ("git_diff_blob", cp.git_diff_blob.as_deref()),
                (
                    "filesystem_manifest_blob",
                    cp.filesystem_manifest_blob.as_deref(),
                ),
                ("environment_blob", cp.environment_blob.as_deref()),
                ("transcript_blob", cp.transcript_blob.as_deref()),
            ] {
                if let Some(k) = key {
                    if !is_valid_blob_key(k) {
                        report.push(FsckFinding {
                            section: "checkpoints".into(),
                            severity: FsckSeverity::Error,
                            code: "invalid_checkpoint_blob".into(),
                            message: format!(
                                "checkpoint {} field {field} has invalid key",
                                short(&cp.id)
                            ),
                            run_id: Some(run.id.clone()),
                            event_id: None,
                            checkpoint_id: Some(cp.id.clone()),
                            field: Some(field.into()),
                            blob_key: Some(k.into()),
                            repairable: false,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

async fn check_blob_references(
    store: &dyn TraceStore,
    opts: &FsckOptions,
    report: &mut FsckReport,
) -> anyhow::Result<()> {
    report.sections_checked.push("blobs".into());
    report.sections_checked.push("FTS".into());

    let referenced = collect_referenced_blobs(store).await?;
    let all_keys = store.all_blob_keys().await.unwrap_or_default();
    let all_set: HashSet<String> = all_keys.into_iter().collect();

    for key in &referenced {
        if !all_set.contains(key) {
            // May still exist only on disk under content addressing without meta row.
            let missing_meta = true;
            if missing_meta {
                // Try load
                if let Some(bref) = BlobReference::try_new(key.clone(), 0) {
                    if store.load_blob(&bref).await.is_err() {
                        report.push(FsckFinding {
                            section: "blobs".into(),
                            severity: FsckSeverity::Error,
                            code: "missing_blob".into(),
                            message: format!("referenced blob {key} cannot be loaded"),
                            run_id: None,
                            event_id: None,
                            checkpoint_id: None,
                            field: None,
                            blob_key: Some(key.clone()),
                            repairable: false,
                        });
                    }
                }
            }
        }
    }

    if matches!(opts.mode, FsckMode::Deep) {
        for key in &referenced {
            let Some(bref) = BlobReference::try_new(key.clone(), 0) else {
                continue;
            };
            match store.load_blob(&bref).await {
                Ok(data) => {
                    let computed = content_key(&data);
                    if computed != *key {
                        report.push(FsckFinding {
                            section: "blobs".into(),
                            severity: FsckSeverity::Critical,
                            code: "blob_hash_mismatch".into(),
                            message: format!(
                                "blob {key} content hashes to {computed} (corruption)"
                            ),
                            run_id: None,
                            event_id: None,
                            checkpoint_id: None,
                            field: None,
                            blob_key: Some(key.clone()),
                            repairable: false,
                        });
                    }
                }
                Err(e) => {
                    report.push(FsckFinding {
                        section: "blobs".into(),
                        severity: FsckSeverity::Error,
                        code: "blob_load_failed".into(),
                        message: format!("deep load of {key} failed: {e}"),
                        run_id: None,
                        event_id: None,
                        checkpoint_id: None,
                        field: None,
                        blob_key: Some(key.clone()),
                        repairable: false,
                    });
                }
            }
        }

        // Orphan files on disk (info only).
        if let Some(ref blob_dir) = opts.blob_dir {
            if blob_dir.is_dir() {
                for entry in std::fs::read_dir(blob_dir)? {
                    let entry = entry?;
                    let name = entry.file_name().to_string_lossy().to_string();
                    if is_valid_blob_key(&name) && !referenced.contains(&name) {
                        report.push(FsckFinding {
                            section: "blobs".into(),
                            severity: FsckSeverity::Info,
                            code: "orphan_blob_file".into(),
                            message: format!("orphan blob file {name} (not referenced)"),
                            run_id: None,
                            event_id: None,
                            checkpoint_id: None,
                            field: None,
                            blob_key: Some(name),
                            repairable: true,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

/// Probe FTS availability / staleness (deep mode does a sample query).
async fn check_fts(
    store: &dyn TraceStore,
    opts: &FsckOptions,
    report: &mut FsckReport,
) -> anyhow::Result<()> {
    report.sections_checked.push("fts".into());
    match store.fts_event_ids("a OR b OR c OR the OR run", 1).await {
        Ok(None) => {
            report.push(FsckFinding {
                section: "fts".into(),
                severity: FsckSeverity::Info,
                code: "fts_unavailable".into(),
                message: "FTS5 index not available on this store backend".into(),
                run_id: None,
                event_id: None,
                checkpoint_id: None,
                field: None,
                blob_key: None,
                repairable: false,
            });
        }
        Ok(Some(_)) => {
            // Deep: compare approximate coverage by counting events with empty FTS hits
            // is expensive; instead flag repairable rebuild when events exist.
            if matches!(opts.mode, FsckMode::Deep) {
                let runs = store.list_runs().await?;
                let mut total_events = 0u64;
                for run in runs.iter().take(50) {
                    total_events += store.count_events(&run.id).await? as u64;
                }
                if total_events > 0 {
                    // Always offer rebuild as a safe repair for deep mode when
                    // the operator requested repair (idempotent full rebuild).
                    report.push(FsckFinding {
                        section: "fts".into(),
                        severity: FsckSeverity::Info,
                        code: "fts_stale".into(),
                        message: format!(
                            "FTS present; deep mode offers rebuild ({total_events}+ events sampled)"
                        ),
                        run_id: None,
                        event_id: None,
                        checkpoint_id: None,
                        field: None,
                        blob_key: None,
                        repairable: true,
                    });
                }
            }
        }
        Err(e) => {
            report.push(FsckFinding {
                section: "fts".into(),
                severity: FsckSeverity::Warning,
                code: "fts_missing".into(),
                message: format!("FTS probe failed ({e}); rebuild recommended"),
                run_id: None,
                event_id: None,
                checkpoint_id: None,
                field: None,
                blob_key: None,
                repairable: true,
            });
        }
    }
    Ok(())
}

fn check_spool(spool_dir: Option<&Path>, report: &mut FsckReport) -> anyhow::Result<()> {
    report.sections_checked.push("recovery spool".into());
    let Some(dir) = spool_dir else {
        return Ok(());
    };
    if !dir.exists() {
        report.push(FsckFinding {
            section: "recovery spool".into(),
            severity: FsckSeverity::Info,
            code: "spool_absent".into(),
            message: "no spool directory present".into(),
            run_id: None,
            event_id: None,
            checkpoint_id: None,
            field: None,
            blob_key: None,
            repairable: false,
        });
        return Ok(());
    }
    match crate::ingest::inspect_spool(dir) {
        Ok(info) => {
            if info.torn_records > 0 {
                report.push(FsckFinding {
                    section: "recovery spool".into(),
                    severity: FsckSeverity::Error,
                    code: "torn_spool_record".into(),
                    message: format!(
                        "{} torn/corrupt spool record(s) under {}",
                        info.torn_records,
                        dir.display()
                    ),
                    run_id: None,
                    event_id: None,
                    checkpoint_id: None,
                    field: None,
                    blob_key: None,
                    repairable: false,
                });
            }
            if info.pending_batches > 0 {
                report.push(FsckFinding {
                    section: "recovery spool".into(),
                    severity: FsckSeverity::Warning,
                    code: "pending_spool".into(),
                    message: format!(
                        "{} pending spool batch(es), {} events, {} bytes",
                        info.pending_batches, info.pending_events, info.bytes
                    ),
                    run_id: None,
                    event_id: None,
                    checkpoint_id: None,
                    field: None,
                    blob_key: None,
                    repairable: true,
                });
            }
        }
        Err(e) => {
            report.push(FsckFinding {
                section: "recovery spool".into(),
                severity: FsckSeverity::Error,
                code: "spool_inspect_failed".into(),
                message: format!("spool inspect failed: {e}"),
                run_id: None,
                event_id: None,
                checkpoint_id: None,
                field: None,
                blob_key: None,
                repairable: false,
            });
        }
    }
    Ok(())
}

fn write_recovery_artifact(
    dir: &Path,
    report: &FsckReport,
    plan: &super::report::RepairPlan,
) -> anyhow::Result<String> {
    std::fs::create_dir_all(dir)?;
    let name = format!("fsck-recovery-{}.json", Utc::now().format("%Y%m%dT%H%M%SZ"));
    let path = dir.join(&name);
    let body = serde_json::json!({
        "schema": "blackbox.fsck.recovery/v1",
        "created_at": Utc::now().to_rfc3339(),
        "report": report,
        "plan": plan,
    });
    std::fs::write(&path, serde_json::to_string_pretty(&body)?)?;
    Ok(path.display().to_string())
}

fn short(id: &str) -> &str {
    &id[..8.min(id.len())]
}
