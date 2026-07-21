//! Repair planning and safe auto-repairs.

use chrono::Utc;

use crate::storage::TraceStore;

use super::report::{FsckReport, RepairAction, RepairPlan};

/// Build a repair plan from fsck findings (no mutations).
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
                // Orphan GC is intentional but not auto by default (grace policy).
                actions.push(RepairAction {
                    kind: "note_orphan_blob".into(),
                    description: format!(
                        "orphan blob {} — use scrub --gc after grace policy",
                        f.blob_key.as_deref().unwrap_or("?")
                    ),
                    run_id: None,
                    blob_key: f.blob_key.clone(),
                    auto_safe: false,
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
            _ => {}
        }
    }
    Ok(applied)
}
