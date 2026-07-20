use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use notify::event::{CreateKind, EventKind, ModifyKind, RemoveKind, RenameMode};
use notify::{Config, Event as NotifyEvent, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};
use crate::core::run::Run;
use crate::workspace_manifest::is_ignored_component;

/// Symlink handling for filesystem capture (1.5 C1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SymlinkPolicy {
    /// Skip symlink paths entirely.
    #[default]
    Ignore,
    /// Emit link metadata only; do not follow into targets.
    LinkOnly,
    /// Follow only when the resolved path stays inside the project root.
    FollowWithinRoot,
}

/// How a path relates to the capture root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathScope {
    InRoot,
    OutsideRoot,
    Symlink,
    Ignored,
}

/// Bounded bridge capacity between notify callback and async ingest (1.5 C1).
const BRIDGE_CAPACITY: usize = 512;
/// Per-path coalescing window for storm reduction.
const COALESCE_MS: u128 = 25;

/// Filesystem-change observer with live `notify` watching.
///
/// Emits:
/// - Bookend snapshots (`filesystem.snapshot` before/after)
/// - Live events while the run is active:
///   `filesystem.created`, `filesystem.modified`,
///   `filesystem.removed`, `filesystem.renamed`
/// - `filesystem.overflow` when the bridge queue is full
/// - `filesystem.out_of_scope` when a path escapes the project root
pub struct FilesystemCapture {
    event_tx: Option<mpsc::Sender<TraceEvent>>,
    run_id: Option<String>,
    cwd: Option<String>,
    start_manifest: Option<String>,
    /// Kept alive so the OS watcher is not dropped mid-run
    _watcher: Option<RecommendedWatcher>,
    /// Join handle for the notify→async bridge task
    bridge_handle: Option<tokio::task::JoinHandle<()>>,
    symlink_policy: SymlinkPolicy,
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
            symlink_policy: SymlinkPolicy::default(),
        }
    }

    pub fn with_symlink_policy(mut self, policy: SymlinkPolicy) -> Self {
        self.symlink_policy = policy;
        self
    }

    /// Shared ignore policy (aligned with workspace_manifest / seed).
    pub fn should_ignore(path: &Path) -> bool {
        for component in path.components() {
            if let std::path::Component::Normal(name) = component {
                if is_ignored_component(&name.to_string_lossy()) {
                    return true;
                }
            }
        }
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

    /// Classify path against canonical project root and symlink policy.
    pub fn classify_path(root: &Path, path: &Path, policy: SymlinkPolicy) -> PathScope {
        if Self::should_ignore(path) {
            return PathScope::Ignored;
        }
        let root_canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

        // Symlink leaf or ancestor?
        let is_link = path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);

        if is_link {
            match policy {
                SymlinkPolicy::Ignore => return PathScope::Ignored,
                SymlinkPolicy::LinkOnly => return PathScope::Symlink,
                SymlinkPolicy::FollowWithinRoot => {
                    // Fall through to resolved path check.
                }
            }
        }

        let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if resolved.starts_with(&root_canon) {
            PathScope::InRoot
        } else {
            PathScope::OutsideRoot
        }
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
            // Never follow symlinks in snapshots (escape / secret tree leak).
            let ft = entry.file_type().ok();
            if ft.as_ref().map(|f| f.is_symlink()).unwrap_or(false) {
                let rel = path
                    .strip_prefix(root)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| path.to_string_lossy().to_string());
                out.push(format!("symlink 0 0 {rel}"));
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| path.to_string_lossy().to_string());
            // symlink_metadata: do not follow.
            let meta = std::fs::symlink_metadata(&path).ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let mtime = meta
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let is_dir = ft.as_ref().map(|f| f.is_dir()).unwrap_or(false);
            let kind = if is_dir { "dir" } else { "file" };
            out.push(format!("{} {} {} {}", kind, size, mtime, rel));
            if is_dir {
                Self::walk_snapshot(root, &path, out, depth + 1);
            }
        }
    }

    fn notify_to_events(
        run_id: &str,
        root: &Path,
        policy: SymlinkPolicy,
        event: NotifyEvent,
    ) -> Vec<TraceEvent> {
        let mut out = Vec::new();
        let paths: Vec<PathBuf> = event.paths;
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

            let scope = Self::classify_path(root, &path, policy);
            match scope {
                PathScope::Ignored => continue,
                PathScope::OutsideRoot => {
                    let mut ev =
                        TraceEvent::new(run_id, EventSource::Filesystem, "filesystem.out_of_scope");
                    ev.status = EventStatus::Error;
                    ev.side_effect = SideEffect::Unknown;
                    ev.metadata
                        .insert("path".into(), serde_json::json!(path_str));
                    ev.metadata
                        .insert("scope".into(), serde_json::json!("outside_root"));
                    out.push(ev);
                    continue;
                }
                PathScope::Symlink if matches!(policy, SymlinkPolicy::Ignore) => continue,
                PathScope::InRoot | PathScope::Symlink => {}
            }

            let mut ev = TraceEvent::new(run_id, EventSource::Filesystem, kind);
            ev.status = EventStatus::Success;
            ev.side_effect = side_effect.clone();
            ev.metadata
                .insert("path".to_string(), serde_json::json!(path_str));
            ev.metadata.insert(
                "scope".to_string(),
                serde_json::json!(match scope {
                    PathScope::InRoot => "in_root",
                    PathScope::Symlink => "symlink",
                    _ => "in_root",
                }),
            );
            if let Some(name) = path.file_name() {
                ev.metadata.insert(
                    "name".to_string(),
                    serde_json::json!(name.to_string_lossy()),
                );
            }
            // Prefer symlink_metadata so we do not follow escapes.
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                ev.metadata
                    .insert("size".to_string(), serde_json::json!(meta.len()));
                ev.metadata
                    .insert("is_dir".to_string(), serde_json::json!(meta.is_dir()));
                ev.metadata.insert(
                    "is_symlink".to_string(),
                    serde_json::json!(meta.file_type().is_symlink()),
                );
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
        // Bounded channel — overflow becomes filesystem.overflow events (1.5 C1).
        let (tx, rx) = mpsc::channel(BRIDGE_CAPACITY);

        let root = PathBuf::from(&run.cwd);
        let root_canon = root.canonicalize().unwrap_or_else(|_| root.clone());

        let mut started = TraceEvent::new(
            &run.id,
            EventSource::Filesystem,
            "filesystem.observer.started",
        );
        started.status = EventStatus::Success;
        started
            .metadata
            .insert("mode".to_string(), serde_json::json!("live-notify"));
        started.metadata.insert(
            "bridge_capacity".to_string(),
            serde_json::json!(BRIDGE_CAPACITY),
        );
        started.metadata.insert(
            "symlink_policy".to_string(),
            serde_json::json!(format!("{:?}", self.symlink_policy)),
        );
        started.metadata.insert(
            "root".to_string(),
            serde_json::json!(root_canon.display().to_string()),
        );
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
                // Non-blocking: drop if notify producer outpaces bridge (rare).
                let _ = notify_tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_millis(200)),
        )?;

        let watch_path = root_canon.clone();
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
            let root_for_bridge = root_canon.clone();
            let policy = self.symlink_policy;
            let handle = tokio::task::spawn_blocking(move || {
                let mut last_path: HashMap<String, Instant> = HashMap::new();
                let mut overflow_count = 0u64;
                while let Ok(res) = notify_rx.recv() {
                    match res {
                        Ok(event) => {
                            for ev in FilesystemCapture::notify_to_events(
                                &run_id,
                                &root_for_bridge,
                                policy,
                                event,
                            ) {
                                // Per-path coalescing: keep final state under storm.
                                if let Some(path) = ev.metadata.get("path").and_then(|v| v.as_str())
                                {
                                    let now = Instant::now();
                                    if let Some(prev) = last_path.get(path) {
                                        if now.duration_since(*prev).as_millis() < COALESCE_MS
                                            && ev.kind != "filesystem.out_of_scope"
                                        {
                                            // Skip intermediate; next event supersedes.
                                            last_path.insert(path.to_string(), now);
                                            continue;
                                        }
                                    }
                                    last_path.insert(path.to_string(), now);
                                }

                                match bridge_tx.try_send(ev) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(ev)) => {
                                        overflow_count = overflow_count.saturating_add(1);
                                        let mut overflow = TraceEvent::new(
                                            &run_id,
                                            EventSource::Filesystem,
                                            "filesystem.overflow",
                                        );
                                        overflow.status = EventStatus::Error;
                                        overflow.metadata.insert(
                                            "dropped_kind".into(),
                                            serde_json::json!(ev.kind),
                                        );
                                        overflow.metadata.insert(
                                            "overflow_count".into(),
                                            serde_json::json!(overflow_count),
                                        );
                                        overflow.metadata.insert(
                                            "bridge_capacity".into(),
                                            serde_json::json!(BRIDGE_CAPACITY),
                                        );
                                        // Best-effort overflow signal; if still full, give up this tick.
                                        let _ = bridge_tx.try_send(overflow);
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => return,
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "filesystem watcher error");
                            let mut err_ev = TraceEvent::new(
                                &run_id,
                                EventSource::Filesystem,
                                "filesystem.watcher_error",
                            );
                            err_ev.status = EventStatus::Error;
                            err_ev
                                .metadata
                                .insert("error".into(), serde_json::json!(e.to_string()));
                            let _ = bridge_tx.try_send(err_ev);
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
        assert!(FilesystemCapture::should_ignore(Path::new(
            "/proj/.venv/lib/x"
        )));
        assert!(!FilesystemCapture::should_ignore(Path::new(
            "/proj/src/main.rs"
        )));
    }

    #[test]
    fn classify_outside_root() {
        let root = temp_workspace();
        let outside = std::env::temp_dir().join(format!("bb-fs-out-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("x"), b"y").unwrap();
        let scope =
            FilesystemCapture::classify_path(&root, &outside.join("x"), SymlinkPolicy::Ignore);
        assert_eq!(scope, PathScope::OutsideRoot);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn classify_in_root() {
        let root = temp_workspace();
        fs::write(root.join("a.txt"), b"ok").unwrap();
        let scope =
            FilesystemCapture::classify_path(&root, &root.join("a.txt"), SymlinkPolicy::Ignore);
        assert_eq!(scope, PathScope::InRoot);
        let _ = fs::remove_dir_all(&root);
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
