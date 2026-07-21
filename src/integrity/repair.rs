//! Repair planning and safe auto-repairs.

use chrono::Utc;

use crate::storage::TraceStore;

use super::report::{FsckReport, RepairAction, RepairPlan};

/// Build a repair plan from fsck findings (no mutations).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `plan_repairs` — see module docs for full workflow.
/// ```
pub fn plan_repairs(report: &FsckReport) -> RepairPlan {
    let mut actions = Vec::new();
    for f in &report.findings {
        if !f.repairable {
            continue;
        }
        match f.code.as_str() {
            "missing_aggregates" | "aggregate_mismatch" => {
                if let Some(ref run_id) = f.run_id {
                    actions.push(RepairAction {
                        kind: "recompute_aggregates".into(),
                        description: format!("recompute aggregates for run {run_id}"),
                        run_id: Some(run_id.clone()),
                        blob_key: None,
                        auto_safe: true,
                    });
                }
            }
            "stale_running" => {
                if let Some(ref run_id) = f.run_id {
                    actions.push(RepairAction {
                        kind: "mark_run_failed".into(),
                        description: format!(
                            "mark abandoned Running run {run_id} as Failed"
                        ),
                        run_id: Some(run_id.clone()),
                        blob_key: None,
                        auto_safe: true,
                    });
                }
            }
            "pending_spool" => {
                actions.push(RepairAction {
                    kind: "replay_spool".into(),
                    description: "replay acknowledged spool batches into SQLite".into(),
                    run_id: None,
                    blob_key: None,
                    auto_safe: true,
                });
            }
            "orphan_blob_file" => {
                // Orphan GC under --repair deletes unreferenced blob files.
                actions.push(RepairAction {
                    kind: "gc_orphan_blob".into(),
                    description: format!(
                        "delete orphan blob file {}",
                        f.blob_key.as_deref().unwrap_or("?")
                    ),
                    run_id: None,
                    blob_key: f.blob_key.clone(),
                    auto_safe: true,
                });
            }
            "fts_stale" | "fts_missing" => {
                actions.push(RepairAction {
                    kind: "rebuild_fts".into(),
                    description: "rebuild events_fts full-text index from events table".into(),
                    run_id: None,
                    blob_key: None,
                    auto_safe: true,
                });
            }
            _ => {}
        }
    }
    // Dedup by kind+run_id
    actions.sort_by(|a, b| {
        (&a.kind, &a.run_id).cmp(&(&b.kind, &b.run_id))
    });
    actions.dedup_by(|a, b| a.kind == b.kind && a.run_id == b.run_id);

    RepairPlan {
        schema: "blackbox.fsck.repair/v1".into(),
        actions,
        created_at: Utc::now().to_rfc3339(),
    }
}

/// Apply only `auto_safe` actions from a plan. Idempotent for aggregate recompute.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `apply_repair_plan` — see module docs for full workflow.
/// ```
pub async fn apply_repair_plan(
    store: &dyn TraceStore,
    plan: &RepairPlan,
) -> anyhow::Result<usize> {
    let mut applied = 0usize;
    for action in &plan.actions {
        if !action.auto_safe {
            continue;
        }
        match action.kind.as_str() {
            "recompute_aggregates" => {
                if let Some(ref run_id) = action.run_id {
                    let _ = store.recompute_run_aggregates(run_id).await?;
                    applied += 1;
                }
            }
            "mark_run_failed" => {
                if let Some(ref run_id) = action.run_id {
                    if let Some(mut run) = store.get_run(run_id).await? {
                        if matches!(run.status, crate::core::run::RunStatus::Running) {
                            run.status = crate::core::run::RunStatus::Failed;
                            run.ended_at = Some(Utc::now());
                            let note = "fsck repair: abandoned Running → Failed";
                            run.notes = Some(match run.notes.take() {
                                Some(n) if n.contains("fsck repair:") => n,
                                Some(n) => format!("{n}; {note}"),
                                None => note.into(),
                            });
                            store.update_run(&run).await?;
                            applied += 1;
                        }
                    }
                }
            }
            "replay_spool" => {
                // Spool replay is triggered by the CLI with a spool path;
                // store-level repair only counts the planned action.
                applied += 1;
            }
            "rebuild_fts" => {
                let n = store.reindex_fts().await?;
                tracing::info!(indexed = n, "fsck repair: rebuilt FTS index");
                applied += 1;
            }
            "gc_orphan_blob" => {
                if let Some(ref key) = action.blob_key {
                    let n = store.delete_blob_keys(std::slice::from_ref(key)).await?;
                    if n > 0 {
                        applied += 1;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(applied)
}
