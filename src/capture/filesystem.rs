use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use async_trait::async_trait;
use notify::event::{CreateKind, EventKind, ModifyKind, RemoveKind, RenameMode};
use notify::{Config, Event as NotifyEvent, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};
use crate::core::run::Run;

/// Path components ignored by the live watcher (high-noise / internal).
/// **Note:** `notify` follows symlinks by default on most platforms. Changes
/// inside symlinked directories will appear as normal events. If isolation is
/// needed in the future, resolve and filter symlinked paths before forwarding.
const IGNORE_COMPONENTS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".blackbox",
    ".cargo",
    "__pycache__",
    ".tox",
    "dist",
    "build",
];

/// Filesystem-change observer with live `notify` watching.
///
/// Emits:
/// - Bookend snapshots (`filesystem.snapshot` before/after)
/// - Live events while the run is active:
///   `filesystem.created`, `filesystem.modified`,
///   `filesystem.removed`, `filesystem.renamed`
pub struct FilesystemCapture {
    event_tx: Option<mpsc::Sender<TraceEvent>>,
    run_id: Option<String>,
    cwd: Option<String>,
    start_manifest: Option<String>,
    /// Kept alive so the OS watcher is not dropped mid-run
    _watcher: Option<RecommendedWatcher>,
    /// Join handle for the notify→async bridge task
    bridge_handle: Option<tokio::task::JoinHandle<()>>,
}

impl FilesystemCapture {
    pub fn new() -> Self {
        Self {
            event_tx: None,
            run_id: None,
            cwd: None,
            start_manifest: None,
            _watcher: None,
            bridge_handle: None,
        }
    }

    fn should_ignore(path: &Path) -> bool {
        for component in path.components() {
            if let std::path::Component::Normal(name) = component {
                let name = name.to_string_lossy();
                if IGNORE_COMPONENTS.iter().any(|ig| *ig == name) {
                    return true;
                }
            }
        }
        // Also ignore blackbox DB files at the project root
        if let Some(name) = path.file_name().map(|n| n.to_string_lossy()) {
            if name == "blackbox.db"
                || name.starts_with("blackbox.db-")
                || name.ends_with(".db-wal")
                || name.ends_with(".db-shm")
            {
                return true;
            }
        }
        false
    }

    fn snapshot(cwd: &str) -> String {
        let mut entries = Vec::new();
        let root = PathBuf::from(cwd);
        Self::walk_snapshot(&root, &root, &mut entries, 0);
        entries.sort();
        entries.join("\n")
    }

    fn walk_snapshot(root: &Path, dir: &Path, out: &mut Vec<String>, depth: usize) {
        if depth > 4 {
            return;
        }
        let Ok(read_dir) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if Self::should_ignore(&path) {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| path.to_string_lossy().to_string());
            let meta = entry.metadata().ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let mtime = meta
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let kind = if is_dir { "dir" } else { "file" };
            out.push(format!("{} {} {} {}", kind, size, mtime, rel));
            if is_dir {
                Self::walk_snapshot(root, &path, out, depth + 1);
            }
        }
    }

    fn notify_to_events(run_id: &str, event: NotifyEvent) -> Vec<TraceEvent> {
        let mut out = Vec::new();
        let paths: Vec<PathBuf> = event
            .paths
            .into_iter()
            .filter(|p| !Self::should_ignore(p))
            .collect();
        if paths.is_empty() {
            return out;
        }

        let (kind, side_effect) = match event.kind {
            EventKind::Create(CreateKind::File) | EventKind::Create(CreateKind::Any) => {
                ("filesystem.created", SideEffect::LocalWrite)
            }
            EventKind::Create(CreateKind::Folder) => ("filesystem.created", SideEffect::LocalWrite),
            EventKind::Modify(ModifyKind::Data(_))
            | EventKind::Modify(ModifyKind::Any)
            | EventKind::Modify(ModifyKind::Metadata(_)) => {
                ("filesystem.modified", SideEffect::LocalWrite)
            }
            EventKind::Modify(ModifyKind::Name(RenameMode::To))
            | EventKind::Modify(ModifyKind::Name(RenameMode::From))
            | EventKind::Modify(ModifyKind::Name(RenameMode::Both))
            | EventKind::Modify(ModifyKind::Name(RenameMode::Any)) => {
                ("filesystem.renamed", SideEffect::LocalWrite)
            }
            EventKind::Remove(RemoveKind::File)
            | EventKind::Remove(RemoveKind::Folder)
            | EventKind::Remove(RemoveKind::Any) => ("filesystem.removed", SideEffect::Destructive),
            // Collapse noisy other kinds
            EventKind::Access(_) | EventKind::Other | EventKind::Any => return out,
            _ => return out,
        };

        // Deduplicate paths within a single notify event
        let mut seen = HashSet::new();
        for path in paths {
            let path_str = path.to_string_lossy().to_string();
            if !seen.insert(path_str.clone()) {
                continue;
            }
            let mut ev = TraceEvent::new(run_id, EventSource::Filesystem, kind);
            ev.status = EventStatus::Success;
            ev.side_effect = side_effect.clone();
            ev.metadata
                .insert("path".to_string(), serde_json::json!(path_str));
            if let Some(name) = path.file_name() {
                ev.metadata.insert(
                    "name".to_string(),
                    serde_json::json!(name.to_string_lossy()),
                );
            }
            if let Ok(meta) = std::fs::metadata(&path) {
                ev.metadata
                    .insert("size".to_string(), serde_json::json!(meta.len()));
                ev.metadata
                    .insert("is_dir".to_string(), serde_json::json!(meta.is_dir()));
            }
            out.push(ev);
        }
        out
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

        let mut started = TraceEvent::new(
            &run.id,
            EventSource::Filesystem,
            "filesystem.observer.started",
        );
        started.status = EventStatus::Success;
        started
            .metadata
            .insert("mode".to_string(), serde_json::json!("live-notify"));
        tx.send(started).await?;
        let _ = tx
            .send(crate::capture::health::layer_started(&run.id, "filesystem"))
            .await;

        let manifest = Self::snapshot(&run.cwd);
        let mut snap_ev = TraceEvent::new(&run.id, EventSource::Filesystem, "filesystem.snapshot");
        snap_ev.status = EventStatus::Success;
        snap_ev.metadata.insert(
            "entry_count".to_string(),
            serde_json::json!(manifest.lines().filter(|l| !l.is_empty()).count()),
        );
        snap_ev
            .metadata
            .insert("phase".to_string(), serde_json::json!("before"));
        tx.send(snap_ev).await?;

        // Set up notify watcher → std mpsc → async mpsc bridge
        let (notify_tx, notify_rx) = std_mpsc::channel::<notify::Result<NotifyEvent>>();
        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = notify_tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_millis(200)),
        )?;

        let watch_path = PathBuf::from(&run.cwd);
        if let Err(e) = watcher.watch(&watch_path, RecursiveMode::Recursive) {
            tracing::warn!(
                path = %watch_path.display(),
                error = %e,
                "filesystem watch failed; falling back to snapshot-only mode"
            );
            let _ = tx
                .send(crate::capture::health::layer_failed(
                    &run.id,
                    "filesystem",
                    &format!("watch failed: {e}; snapshot-only fallback"),
                ))
                .await;
        } else {
            tracing::debug!(path = %watch_path.display(), "filesystem live watch started");
            self._watcher = Some(watcher);

            let run_id = run.id.clone();
            let bridge_tx = tx.clone();
            let handle = tokio::task::spawn_blocking(move || {
                // Coalesce bursts: small sleep between drains reduces event spam
                while let Ok(res) = notify_rx.recv() {
                    match res {
                        Ok(event) => {
                            for ev in FilesystemCapture::notify_to_events(&run_id, event) {
                                if bridge_tx.blocking_send(ev).is_err() {
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "filesystem watcher error");
                        }
                    }
                }
            });
            self.bridge_handle = Some(handle);
        }

        self.start_manifest = Some(manifest);
        self.run_id = Some(run.id.clone());
        self.cwd = Some(run.cwd.clone());
        self.event_tx = Some(tx);
        Ok(rx)
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        // Drop watcher first so the bridge task can exit
        self._watcher = None;
        if let Some(mut handle) = self.bridge_handle.take() {
            // Give the bridge a moment to finish gracefully, then abort if stuck.
            let _ = tokio::time::timeout(Duration::from_millis(250), &mut handle).await;
            if !handle.is_finished() {
                tracing::debug!("bridge task did not exit in time; aborting");
                handle.abort();
            }
        }

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

        let mut snap_ev = TraceEvent::new(&run_id, EventSource::Filesystem, "filesystem.snapshot");
        snap_ev.status = EventStatus::Success;
        snap_ev.metadata.insert(
            "entry_count".to_string(),
            serde_json::json!(after.lines().filter(|l| !l.is_empty()).count()),
        );
        snap_ev
            .metadata
            .insert("phase".to_string(), serde_json::json!("after"));
        snap_ev
            .metadata
            .insert("changed".to_string(), serde_json::json!(changed));
        let _ = tx.send(snap_ev).await;

        let mut stop_ev = TraceEvent::new(
            &run_id,
            EventSource::Filesystem,
            "filesystem.observer.stopped",
        );
        stop_ev.status = EventStatus::Success;
        let _ = tx.send(stop_ev).await;
        let _ = tx
            .send(crate::capture::health::layer_stopped(
                &run_id,
                "filesystem",
                None,
            ))
            .await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_workspace() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-fs-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ignore_noise_paths() {
        assert!(FilesystemCapture::should_ignore(Path::new(
            "/proj/target/debug/foo"
        )));
        assert!(FilesystemCapture::should_ignore(Path::new(
            "/proj/.git/objects/xx"
        )));
        assert!(FilesystemCapture::should_ignore(Path::new(
            "/proj/node_modules/x"
        )));
        assert!(!FilesystemCapture::should_ignore(Path::new(
            "/proj/src/main.rs"
        )));
    }

    #[test]
    fn snapshot_lists_files() {
        let dir = temp_workspace();
        fs::write(dir.join("a.txt"), b"hello").unwrap();
        fs::create_dir(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/b.txt"), b"world").unwrap();
        // noise should be skipped
        fs::create_dir(dir.join("target")).unwrap();
        fs::write(dir.join("target/x.o"), b"bin").unwrap();

        let snap = FilesystemCapture::snapshot(dir.to_str().unwrap());
        assert!(snap.contains("a.txt"));
        assert!(snap.contains("sub/b.txt") || snap.contains("sub"));
        assert!(!snap.contains("x.o"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn live_watch_emits_create() {
        let dir = temp_workspace();
        let mut capture = FilesystemCapture::new();
        let run = Run::new(vec!["true".into()], dir.to_string_lossy().to_string());

        let mut rx = capture.start(&run).await.unwrap();

        // Drain bookend events
        let mut kinds = Vec::new();
        // Give the watcher a moment to attach
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Create a file while watching
        let new_file = dir.join("live-created.txt");
        fs::write(&new_file, b"payload").unwrap();

        // Wait for notify to deliver
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut saw_create = false;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
                Ok(Some(ev)) => {
                    kinds.push(ev.kind.clone());
                    if ev.kind == "filesystem.created" {
                        saw_create = true;
                        break;
                    }
                }
                _ => continue,
            }
        }

        let _ = capture.stop().await;
        let _ = fs::remove_dir_all(&dir);

        assert!(
            saw_create,
            "expected filesystem.created event, got kinds: {:?}",
            kinds
        );
    }
}
