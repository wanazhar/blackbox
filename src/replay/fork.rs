use std::sync::Arc;

use crate::core::checkpoint::Checkpoint;
use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};
use crate::core::run::{Run, RunStatus};
use crate::replay::{events_from, ReplayEngine, ReplayOutcome};
use crate::storage::TraceStore;

/// Fork a new run from a recorded checkpoint / event boundary.
///
/// Creates a new `Run` row with `parent_run_id` set, writes a fork
/// context summary event + checkpoint, and returns the new run id.
/// Does not re-launch the harness automatically — the user can
/// `blackbox run` (or resume via adapter) with the restored context.
pub struct ForkManager {
    store: Option<Arc<dyn TraceStore>>,
    name: Option<String>,
}

impl ForkManager {
    pub fn new() -> Self {
        Self {
            store: None,
            name: None,
        }
    }

    pub fn with_store(mut self, store: Arc<dyn TraceStore>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    fn build_context_summary(
        parent: &Run,
        fork_point: &TraceEvent,
        remaining: &[TraceEvent],
    ) -> serde_json::Value {
        let tool_calls: Vec<serde_json::Value> = remaining
            .iter()
            .filter(|e| e.kind == "tool.call")
            .take(20)
            .map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "tool": e.metadata.get("tool_name"),
                    "input": e.metadata.get("input"),
                })
            })
            .collect();

        let session = remaining
            .iter()
            .chain(std::iter::once(fork_point))
            .find_map(|e| {
                e.metadata
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });

        serde_json::json!({
            "parent_run_id": parent.id,
            "parent_command": parent.command,
            "parent_cwd": parent.cwd,
            "fork_event_id": fork_point.id,
            "fork_event_kind": fork_point.kind,
            "fork_event_sequence": fork_point.sequence,
            "events_from_fork": remaining.len(),
            "tool_calls_preview": tool_calls,
            "harness_session_id": session,
            "parent_notes": parent.notes,
        })
    }
}

impl Default for ForkManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ReplayEngine for ForkManager {
    fn name(&self) -> &'static str {
        "fork"
    }

    async fn start(
        &mut self,
        run: &Run,
        events: &[TraceEvent],
        from_event_id: Option<&str>,
    ) -> anyhow::Result<ReplayOutcome> {
        let slice = events_from(events, from_event_id);
        if slice.is_empty() {
            return Ok(ReplayOutcome::Errored(
                "no events available at fork point".into(),
            ));
        }
        let fork_point = &slice[0];

        tracing::info!(
            fork_event_id = %fork_point.id,
            fork_event_kind = %fork_point.kind,
            fork_event_sequence = fork_point.sequence,
            "fork: selecting fork point"
        );

        let context = Self::build_context_summary(run, fork_point, slice);

        // Build the new run record
        let mut new_run = Run::new(run.command.clone(), run.cwd.clone());
        new_run.parent_run_id = Some(run.id.clone());
        new_run.name = self
            .name
            .clone()
            .or_else(|| Some(format!("fork-of-{}", &run.id[..8.min(run.id.len())])));
        new_run.tags = run.tags.clone();
        new_run.notes = Some(format!(
            "forked from {} at event {} ({})",
            &run.id[..8.min(run.id.len())],
            &fork_point.id[..8.min(fork_point.id.len())],
            fork_point.kind
        ));
        new_run.status = RunStatus::Pending;
        new_run.project_dir = run.project_dir.clone();

        let store = match &self.store {
            Some(s) => s.clone(),
            None => {
                // Without a store we still return a synthetic outcome with the
                // generated id so callers can see what would have been created.
                let summary = format!(
                    "dry-run fork at {} ({} events remaining); no store attached",
                    fork_point.kind,
                    slice.len()
                );
                println!("═══ Fork (dry-run) ═══");
                println!("would create run {}", new_run.id);
                println!("parent:  {}", run.id);
                println!("at:      {} ({})", fork_point.id, fork_point.kind);
                println!("context: {}", context);
                return Ok(ReplayOutcome::Forked {
                    new_run_id: new_run.id,
                    summary,
                });
            }
        };

        // Persist the forked run
        store.insert_run(&new_run).await?;

        // Fork context event
        let mut ctx_ev = TraceEvent::new(&new_run.id, EventSource::System, "fork.created");
        ctx_ev.status = EventStatus::Success;
        ctx_ev.side_effect = SideEffect::None;
        ctx_ev
            .metadata
            .insert("context".to_string(), context.clone());
        ctx_ev
            .metadata
            .insert("parent_run_id".to_string(), serde_json::json!(run.id));
        ctx_ev.metadata.insert(
            "fork_event_id".to_string(),
            serde_json::json!(fork_point.id),
        );
        store.insert_event(&ctx_ev).await?;

        // Checkpoint at fork boundary
        let mut cp = Checkpoint::new(&new_run.id, &ctx_ev.id, &new_run.cwd);
        if let Some(sid) = context.get("harness_session_id").and_then(|v| v.as_str()) {
            cp.harness_session_id = Some(sid.to_string());
        }
        store.insert_checkpoint(&cp).await?;

        let summary = format!(
            "created run {} from parent {} at {} (seq {}); {} events after fork point",
            crate::util::short_id(&new_run.id),
            crate::util::short_id(&run.id),
            fork_point.kind,
            fork_point.sequence,
            slice.len()
        );

        println!("═══ Fork created ═══");
        println!("new run : {}", new_run.id);
        println!("parent  : {}", run.id);
        println!("at event: {} ({})", fork_point.id, fork_point.kind);
        println!("name    : {:?}", new_run.name);
        if let Some(sid) = cp.harness_session_id.as_ref() {
            println!("session : {}", sid);
        }
        println!("─── {} ───", summary);
        println!("Next: blackbox run -- <command>  (or resume harness session if available)");

        Ok(ReplayOutcome::Forked {
            new_run_id: new_run.id,
            summary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::sqlite::SqliteStore;

    #[tokio::test]
    async fn fork_creates_child_run() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let mut parent = Run::new(vec!["claude".into()], "/tmp/proj".into());
        parent.status = RunStatus::Succeeded;
        store.insert_run(&parent).await.unwrap();

        let mut ev = TraceEvent::new(&parent.id, EventSource::Tool, "tool.call");
        ev.sequence = 5;
        ev.metadata
            .insert("tool_name".into(), serde_json::json!("Read"));
        store.insert_event(&ev).await.unwrap();

        let mut fork = ForkManager::new()
            .with_store(store.clone())
            .with_name(Some("my-fork".into()));
        let outcome = fork
            .start(&parent, &[ev.clone()], Some(&ev.id))
            .await
            .unwrap();

        match outcome {
            ReplayOutcome::Forked { new_run_id, .. } => {
                let child = store.get_run(&new_run_id).await.unwrap().unwrap();
                assert_eq!(child.parent_run_id.as_deref(), Some(parent.id.as_str()));
                assert_eq!(child.name.as_deref(), Some("my-fork"));
                let events = store.get_events(&new_run_id).await.unwrap();
                assert!(events.iter().any(|e| e.kind == "fork.created"));
            }
            other => panic!("unexpected {:?}", other),
        }
    }
}
