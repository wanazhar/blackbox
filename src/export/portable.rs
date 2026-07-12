use anyhow::Context;

use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::storage::TraceStore;

/// Export a run and its events as a self-contained portable JSON archive.
///
/// The output is a single JSON object with run metadata, all events,
/// and an `exported_at` timestamp. This format is designed for sharing
/// and archival — it carries everything needed to reconstruct the view.
pub fn export_portable(
    run: &Run,
    events: &[TraceEvent],
    redact: bool,
) -> anyhow::Result<String> {
    let mut run_val = serde_json::to_value(run)?;
    if redact {
        redact_run(&mut run_val);
    }

    let mut events_val: Vec<serde_json::Value> = events
        .iter()
        .filter_map(|e| {
            let mut v = serde_json::to_value(e).ok()?;
            if redact {
                redact_event(&mut v);
            }
            Some(v)
        })
        .collect();

    // Sort by sequence for deterministic output
    events_val.sort_by_key(|v| v["sequence"].as_u64().unwrap_or(0));

    let output = serde_json::json!({
        "version": 1,
        "run": run_val,
        "events": events_val,
        "exported_at": chrono::Utc::now().to_rfc3339(),
    });

    Ok(serde_json::to_string_pretty(&output)?)
}

/// Result of importing a portable archive.
#[derive(Debug, Clone)]
pub struct ImportResult {
    pub run_id: String,
    pub events: usize,
    pub remapped: bool,
}

/// Import a portable JSON archive into the store.
///
/// If `new_ids` is true (default for safety), assigns a fresh run id and
/// rewrites event `run_id` / generates new event ids. If false, keeps ids
/// and fails if the run already exists.
pub async fn import_portable(
    store: &dyn TraceStore,
    json: &str,
    new_ids: bool,
) -> anyhow::Result<ImportResult> {
    let root: serde_json::Value =
        serde_json::from_str(json).context("invalid portable JSON")?;
    let version = root
        .get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if version != 1 {
        anyhow::bail!("unsupported portable version: {version} (expected 1)");
    }

    let mut run: Run = serde_json::from_value(
        root.get("run")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing run object"))?,
    )
    .context("invalid run payload")?;

    let mut events: Vec<TraceEvent> = serde_json::from_value(
        root.get("events")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([])),
    )
    .context("invalid events payload")?;

    let remapped;
    if new_ids {
        let old_id = run.id.clone();
        run.id = uuid::Uuid::new_v4().to_string();
        run.parent_run_id = run.parent_run_id.or(Some(old_id.clone()));
        if let Some(notes) = run.notes.take() {
            run.notes = Some(format!("imported from {old_id}; {notes}"));
        } else {
            run.notes = Some(format!("imported from {old_id}"));
        }
        if !run.tags.iter().any(|t| t == "imported") {
            run.tags.push("imported".into());
        }
        for ev in &mut events {
            ev.id = uuid::Uuid::new_v4().to_string();
            ev.run_id = run.id.clone();
        }
        remapped = true;
    } else {
        if store.get_run(&run.id).await?.is_some() {
            anyhow::bail!(
                "run {} already exists (pass --new-ids or delete first)",
                &run.id[..8.min(run.id.len())]
            );
        }
        remapped = false;
    }

    events.sort_by_key(|e| e.sequence);
    store.insert_run(&run).await?;
    for ev in &events {
        store.insert_event(ev).await?;
    }

    Ok(ImportResult {
        run_id: run.id,
        events: events.len(),
        remapped,
    })
}

fn redact_run(val: &mut serde_json::Value) {
    if let Some(obj) = val.as_object_mut() {
        if let Some(cwd) = obj.get("cwd").and_then(|v| v.as_str()) {
            let basename = std::path::Path::new(cwd)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "(redacted)".to_string());
            obj.insert("cwd".to_string(), serde_json::json!(basename));
        }
    }
}

fn redact_event(val: &mut serde_json::Value) {
    if let Some(obj) = val.as_object_mut() {
        if let Some(meta) = obj.get_mut("metadata").and_then(|v| v.as_object_mut()) {
            meta.remove("raw");
            if meta.contains_key("diff_preview") {
                meta.insert(
                    "diff_preview".to_string(),
                    serde_json::json!("[REDACTED]"),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};
    use chrono::Utc;

    fn make_run() -> Run {
        Run {
            id: "run-port001".into(),
            name: None,
            command: vec!["echo".into(), "hello".into()],
            cwd: "/home/user/project".into(),
            project_dir: "/home/user/project".into(),
            tags: vec![],
            notes: None,
            status: crate::core::run::RunStatus::Succeeded,
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            exit_code: Some(0),
            parent_run_id: None,
            next_sequence: 1,
        }
    }

    fn make_event(seq: u64) -> TraceEvent {
        TraceEvent {
            id: format!("evt-{}", seq),
            run_id: "run-port001".into(),
            parent_event_id: None,
            sequence: seq,
            source: EventSource::Terminal,
            kind: "command".into(),
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            duration_ms: Some(50),
            status: EventStatus::Success,
            side_effect: crate::core::event::SideEffect::None,
            input_blob: None,
            output_blob: None,
            error_blob: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn portable_export_valid_json() {
        let run = make_run();
        let events = vec![make_event(1), make_event(2)];
        let output = export_portable(&run, &events, false).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["run"]["id"], "run-port001");
        assert_eq!(parsed["events"].as_array().unwrap().len(), 2);
        assert!(parsed["exported_at"].is_string());
    }

    #[test]
    fn portable_export_empty_events() {
        let run = make_run();
        let output = export_portable(&run, &[], false).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["events"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn portable_export_redacted() {
        let run = make_run();
        let events = vec![make_event(1)];
        let output = export_portable(&run, &events, true).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        // cwd redacted to basename
        assert_eq!(parsed["run"]["cwd"], "project");
    }

    #[test]
    fn portable_export_events_sorted() {
        let run = make_run();
        let events = vec![make_event(3), make_event(1), make_event(2)];
        let output = export_portable(&run, &events, false).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed["events"].as_array().unwrap();
        assert_eq!(arr[0]["sequence"], 1);
        assert_eq!(arr[1]["sequence"], 2);
        assert_eq!(arr[2]["sequence"], 3);
    }

    #[tokio::test]
    async fn portable_round_trip_new_ids() {
        use crate::storage::sqlite::SqliteStore;
        use std::sync::Arc;

        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = make_run();
        store.insert_run(&run).await.unwrap();
        store.insert_event(&make_event(1)).await.unwrap();
        store.insert_event(&make_event(2)).await.unwrap();

        let events = store.get_events(&run.id).await.unwrap();
        let json = export_portable(&run, &events, false).unwrap();

        let result = import_portable(store.as_ref(), &json, true)
            .await
            .unwrap();
        assert_ne!(result.run_id, run.id);
        assert_eq!(result.events, 2);
        assert!(result.remapped);

        let imported = store.get_run(&result.run_id).await.unwrap().unwrap();
        assert!(imported.tags.contains(&"imported".into()));
        assert_eq!(store.get_events(&result.run_id).await.unwrap().len(), 2);
    }
}
