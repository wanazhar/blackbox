use crate::core::blob::BlobReference;
use crate::core::checkpoint::Checkpoint;
use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::storage::TraceStore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory [`TraceStore`] for unit tests and ephemeral experiments.
///
/// Production paths use [`crate::storage::sqlite::SqliteStore`] with
/// on-disk content-addressed blobs under `.blackbox/blobs/`.
pub struct InMemoryStore {
    runs: Arc<RwLock<HashMap<String, Run>>>,
    events: Arc<RwLock<HashMap<String, Vec<TraceEvent>>>>,
    checkpoints: Arc<RwLock<HashMap<String, Vec<Checkpoint>>>>,
    blobs: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            runs: Arc::new(RwLock::new(HashMap::new())),
            events: Arc::new(RwLock::new(HashMap::new())),
            checkpoints: Arc::new(RwLock::new(HashMap::new())),
            blobs: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl TraceStore for InMemoryStore {
    async fn insert_run(&self, run: &Run) -> anyhow::Result<()> {
        self.runs.write().await.insert(run.id.clone(), run.clone());
        Ok(())
    }

    async fn update_run(&self, run: &Run) -> anyhow::Result<()> {
        self.runs.write().await.insert(run.id.clone(), run.clone());
        Ok(())
    }

    async fn get_run(&self, run_id: &str) -> anyhow::Result<Option<Run>> {
        Ok(self.runs.read().await.get(run_id).cloned())
    }

    async fn list_runs(&self) -> anyhow::Result<Vec<Run>> {
        let mut runs: Vec<Run> = self.runs.read().await.values().cloned().collect();
        runs.sort_by_key(|b| std::cmp::Reverse(b.started_at));
        Ok(runs)
    }

    async fn delete_run(&self, run_id: &str) -> anyhow::Result<bool> {
        let removed = self.runs.write().await.remove(run_id).is_some();
        self.events.write().await.remove(run_id);
        self.checkpoints.write().await.remove(run_id);
        Ok(removed)
    }

    async fn insert_event(&self, event: &TraceEvent) -> anyhow::Result<()> {
        let mut events = self.events.write().await;
        events.entry(event.run_id.clone()).or_default().push(event.clone());
        Ok(())
    }

    async fn get_events(&self, run_id: &str) -> anyhow::Result<Vec<TraceEvent>> {
        let events = self.events.read().await;
        Ok(events.get(run_id).cloned().unwrap_or_default())
    }

    async fn get_event(&self, event_id: &str) -> anyhow::Result<Option<TraceEvent>> {
        let events = self.events.read().await;
        for evts in events.values() {
            if let Some(ev) = evts.iter().find(|e| e.id == event_id) {
                return Ok(Some(ev.clone()));
            }
        }
        Ok(None)
    }

    async fn update_event(&self, event: &TraceEvent) -> anyhow::Result<()> {
        let mut events = self.events.write().await;
        if let Some(evts) = events.get_mut(&event.run_id) {
            if let Some(slot) = evts.iter_mut().find(|e| e.id == event.id) {
                *slot = event.clone();
                return Ok(());
            }
        }
        // Fallback: search all runs
        for evts in events.values_mut() {
            if let Some(slot) = evts.iter_mut().find(|e| e.id == event.id) {
                *slot = event.clone();
                return Ok(());
            }
        }
        anyhow::bail!("event not found for update: {}", event.id)
    }

    async fn insert_checkpoint(&self, cp: &Checkpoint) -> anyhow::Result<()> {
        self.checkpoints
            .write()
            .await
            .entry(cp.run_id.clone())
            .or_default()
            .push(cp.clone());
        Ok(())
    }

    async fn get_checkpoints(&self, run_id: &str) -> anyhow::Result<Vec<Checkpoint>> {
        let cps = self.checkpoints.read().await;
        Ok(cps.get(run_id).cloned().unwrap_or_default())
    }

    async fn store_blob(&self, data: &[u8]) -> anyhow::Result<BlobReference> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let key = hex::encode(hasher.finalize());
        let size = data.len() as u64;

        self.blobs.write().await.insert(key.clone(), data.to_vec());

        Ok(BlobReference::new(key, size))
    }

    async fn load_blob(&self, reference: &BlobReference) -> anyhow::Result<Vec<u8>> {
        self.blobs
            .read()
            .await
            .get(&reference.key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("blob not found: {}", reference.key))
    }

    async fn move_blob(
        &self,
        from_key: &str,
        to_key: &str,
    ) -> anyhow::Result<()> {
        let mut blobs = self.blobs.write().await;
        if let Some(data) = blobs.remove(from_key) {
            blobs.entry(to_key.to_string()).or_insert(data);
        }
        Ok(())
    }
 }
