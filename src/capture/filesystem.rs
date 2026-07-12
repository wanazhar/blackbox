use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::run::Run;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// Filesystem-change observer.
///
/// Detects file creation, modification, renaming, and deletion
/// within the project directory by snapshotting a shallow listing
/// at start and stop (MVP). Full inotify watching is a later phase.
pub struct FilesystemCapture {
    event_tx: Option<mpsc::Sender<TraceEvent>>,
    run_id: Option<String>,
    cwd: Option<String>,
    start_manifest: Option<String>,
}

impl FilesystemCapture {
    pub fn new() -> Self {
        Self {
            event_tx: None,
            run_id: None,
            cwd: None,
            start_manifest: None,
        }
    }

    fn snapshot(cwd: &str) -> String {
        let mut entries = Vec::new();
        if let Ok(read_dir) = std::fs::read_dir(cwd) {
            for entry in read_dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') || name == "target" || name == "node_modules" {
                    continue;
                }
                let meta = entry.metadata().ok();
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let mtime = meta
                    .as_ref()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let kind = if meta.as_ref().map(|m| m.is_dir()).unwrap_or(false) {
                    "dir"
                } else {
                    "file"
                };
                entries.push(format!("{} {} {} {}", kind, size, mtime, name));
            }
        }
        entries.sort();
        entries.join("\n")
    }
}

impl Default for FilesystemCapture {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CaptureLayer for FilesystemCapture {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    async fn start(&mut self, run: &Run) -> anyhow::Result<mpsc::Receiver<TraceEvent>> {
        let (tx, rx) = mpsc::channel(1024);

        let mut ev =
            TraceEvent::new(&run.id, EventSource::Filesystem, "filesystem.observer.started");
        ev.status = EventStatus::Success;
        tx.send(ev).await?;

        let manifest = Self::snapshot(&run.cwd);
        let mut snap_ev =
            TraceEvent::new(&run.id, EventSource::Filesystem, "filesystem.snapshot");
        snap_ev.status = EventStatus::Success;
        snap_ev.metadata.insert(
            "entry_count".to_string(),
            serde_json::json!(manifest.lines().count()),
        );
        snap_ev.metadata.insert(
            "phase".to_string(),
            serde_json::json!("before"),
        );
        tx.send(snap_ev).await?;

        self.start_manifest = Some(manifest);
        self.run_id = Some(run.id.clone());
        self.cwd = Some(run.cwd.clone());
        self.event_tx = Some(tx);
        Ok(rx)
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        let (tx, run_id, cwd) = match (
            self.event_tx.take(),
            self.run_id.as_deref(),
            self.cwd.as_deref(),
        ) {
            (Some(tx), Some(run_id), Some(cwd)) => (tx, run_id.to_string(), cwd.to_string()),
            _ => return Ok(()),
        };

        let after = Self::snapshot(&cwd);
        let changed = self.start_manifest.as_deref() != Some(after.as_str());

        let mut snap_ev =
            TraceEvent::new(&run_id, EventSource::Filesystem, "filesystem.snapshot");
        snap_ev.status = EventStatus::Success;
        snap_ev.metadata.insert(
            "entry_count".to_string(),
            serde_json::json!(after.lines().count()),
        );
        snap_ev
            .metadata
            .insert("phase".to_string(), serde_json::json!("after"));
        snap_ev
            .metadata
            .insert("changed".to_string(), serde_json::json!(changed));
        let _ = tx.send(snap_ev).await;

        let mut stop_ev =
            TraceEvent::new(&run_id, EventSource::Filesystem, "filesystem.observer.stopped");
        stop_ev.status = EventStatus::Success;
        let _ = tx.send(stop_ev).await;

        Ok(())
    }
}
