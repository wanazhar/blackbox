use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tracing;

use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::run::Run;
use crate::storage::TraceStore;
use async_trait::async_trait;
use tokio::sync::mpsc;
/// Maximum bytes allowed for captured diffs. Diffs exceeding this are
/// truncated to avoid unbounded memory allocation on large repositories.
const MAX_DIFF_BYTES: usize = 1024 * 1024; // 1 MiB
// TODO(R2-M19): All synchronous `Command::new("git")` calls below block the
// async runtime. They should be wrapped in `tokio::task::spawn_blocking` to
// avoid starving the tokio executor. This is a larger refactor deferred to
// a dedicated pass because it changes the call-site signatures (sync → async)
// and requires careful handling of the Result types.

/// Git-aware change tracker.
///
/// Captures repository state before and after each run:
/// - Current commit hash
/// - Working tree diff (unstaged + staged changes)
/// - Stores diff as a content-addressed blob
///
/// Non-git directories fall back to a simple filesystem file listing.
pub struct GitCapture {
    /// Working directory to run git commands in
    cwd: Option<String>,
    /// Optional store for persisting diffs as content-addressed blobs
    store: Option<Arc<dyn TraceStore>>,
    /// Channel kept open so `stop()` can emit the after-run snapshot
    event_tx: Option<mpsc::Sender<TraceEvent>>,
    /// Run id captured at start
    run_id: Option<String>,
    /// Resolved working directory
    active_cwd: Option<String>,
    /// Diff blob key from the before-run snapshot (for checkpoint wiring)
    before_diff_blob: Option<String>,
    /// Diff blob key from the after-run snapshot
    after_diff_blob: Option<String>,
    /// Commit hash at start
    commit_hash: Option<String>,
    /// Commit hash after the run
    after_commit_hash: Option<String>,
}

impl Default for GitCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl GitCapture {
    pub fn new() -> Self {
        Self {
            cwd: None,
            store: None,
            event_tx: None,
            run_id: None,
            active_cwd: None,
            before_diff_blob: None,
            after_diff_blob: None,
            commit_hash: None,
            after_commit_hash: None,
        }
    }

    /// Attach a trace store so diffs are persisted as blobs.
    pub fn with_store(mut self, store: Arc<dyn TraceStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Blob key of the before-run diff, if any.
    pub fn before_diff_blob_key(&self) -> Option<&str> {
        self.before_diff_blob.as_deref()
    }

    /// Blob key of the after-run diff, if any.
    pub fn after_diff_blob_key(&self) -> Option<&str> {
        self.after_diff_blob
            .as_deref()
            .or(self.before_diff_blob.as_deref())
    }

    /// Commit hash captured at start, if any.
    pub fn commit_hash(&self) -> Option<&str> {
        self.commit_hash.as_deref()
    }

    /// Commit hash after the run (falls back to start hash).
    pub fn after_commit_hash(&self) -> Option<&str> {
        self.after_commit_hash
            .as_deref()
            .or(self.commit_hash.as_deref())
    }

    /// Check if the given directory is inside a git repository.
    pub fn is_git_repo(path: &Path) -> bool {
        Command::new("git")
            .args(["rev-parse", "--is-inside-work-tree"])
            .current_dir(path)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Get the current commit hash (HEAD).
    fn get_commit_hash(cwd: &str) -> Option<String> {
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(cwd)
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout)
                        .ok()
                        .map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
    }

    /// Get the working tree diff (unstaged changes).
    fn get_diff(cwd: &str) -> Option<String> {
        Command::new("git")
            .args(["diff", "--submodule=short"])
            .current_dir(cwd)
            .output()
            .ok()
            .and_then(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                if stdout.is_empty() {
                    None
                } else {
                    Some(stdout)
                }
            })
    }

    /// Get the staged diff.
    fn get_diff_cached(cwd: &str) -> Option<String> {
        Command::new("git")
            .args(["diff", "--cached", "--submodule=short"])
            .current_dir(cwd)
            .output()
            .ok()
            .and_then(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                if stdout.is_empty() {
                    None
                } else {
                    Some(stdout)
                }
            })
    }

    /// Capture the full diff snapshot (unstaged + staged).
    fn capture_diff(cwd: &str) -> Option<String> {
        let mut parts = Vec::new();

        if let Some(diff) = Self::get_diff(cwd) {
            parts.push(format!("--- Unstaged Changes ---\n{}", diff));
        }
        if let Some(diff) = Self::get_diff_cached(cwd) {
            parts.push(format!("--- Staged Changes ---\n{}", diff));
        }

        if parts.is_empty() {
            None
        } else {
            let combined = parts.join("\n\n");
            if combined.len() > MAX_DIFF_BYTES {
                tracing::warn!(
                    diff_len = combined.len(),
                    max = MAX_DIFF_BYTES,
                    "git diff exceeds size limit; truncating"
                );
                let end = combined.floor_char_boundary(MAX_DIFF_BYTES);
                Some(format!("{}...\n[truncated at {} bytes]", &combined[..end], MAX_DIFF_BYTES))
            } else {
                Some(combined)
            }
        }
    }

    /// Build a simple filesystem manifest (name + size) for non-git dirs.
    fn filesystem_manifest(cwd: &str) -> String {
        let mut entries = Vec::new();
        if let Ok(read_dir) = std::fs::read_dir(cwd) {
            for entry in read_dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                // Skip common noise
                if name.starts_with('.') || name == "target" || name == "node_modules" {
                    continue;
                }
                let meta = entry.metadata().ok();
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let kind = if meta.as_ref().map(|m| m.is_dir()).unwrap_or(false) {
                    "dir"
                } else {
                    "file"
                };
                entries.push(format!("{} {} {}", kind, size, name));
            }
        }
        entries.sort();
        entries.join("\n")
    }

    async fn emit_diff_event(
        &self,
        run_id: &str,
        kind: &str,
        diff: &str,
        tx: &mpsc::Sender<TraceEvent>,
    ) -> Option<String> {
        let mut ev = TraceEvent::new(run_id, EventSource::Git, kind);
        ev.status = EventStatus::Success;
        ev.metadata
            .insert("diff_size".to_string(), serde_json::json!(diff.len()));
        ev.metadata.insert(
            "diff_preview".to_string(),
            serde_json::json!(if diff.len() > 500 {
                let end = diff.floor_char_boundary(500);
                format!("{}...", &diff[..end])
            } else {
                diff.to_string()
            }),
        );

        let mut blob_key = None;
        if let Some(ref store) = self.store {
            match store.store_blob(diff.as_bytes()).await {
                Ok(reference) => {
                    ev.metadata.insert(
                        "diff_blob_key".to_string(),
                        serde_json::json!(reference.key),
                    );
                    ev.metadata.insert(
                        "diff_blob_size".to_string(),
                        serde_json::json!(reference.size),
                    );
                    blob_key = Some(reference.key);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to store git diff blob");
                }
            }
        }

        if tx.send(ev).await.is_err() {
            tracing::debug!("git capture event channel closed, dropping event");
        }
        blob_key
    }
}

#[async_trait]
impl CaptureLayer for GitCapture {
    fn name(&self) -> &'static str {
        "git"
    }

    async fn start(&mut self, run: &Run) -> anyhow::Result<mpsc::Receiver<TraceEvent>> {
        let (tx, rx) = mpsc::channel(1024);
        let cwd = self.cwd.as_deref().unwrap_or(&run.cwd).to_string();
        self.run_id = Some(run.id.clone());
        self.active_cwd = Some(cwd.clone());

        if !Self::is_git_repo(Path::new(&cwd)) {
            tracing::debug!(cwd = %cwd, "not a git repository, using filesystem manifest");
            let mut ev = TraceEvent::new(&run.id, EventSource::Git, "git.not_a_repo");
            ev.status = EventStatus::Success;
            ev.metadata
                .insert("cwd".to_string(), serde_json::json!(cwd));

            // Fallback: store a filesystem manifest as a blob
            let manifest = Self::filesystem_manifest(&cwd);
            if let Some(ref store) = self.store {
                match store.store_blob(manifest.as_bytes()).await {
                    Ok(reference) => {
                        ev.metadata.insert(
                            "filesystem_manifest_blob".to_string(),
                            serde_json::json!(reference.key),
                        );
                        self.before_diff_blob = Some(reference.key);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to store filesystem manifest blob");
                    }
                }
            }
            ev.metadata.insert(
                "manifest_preview".to_string(),
                serde_json::json!(if manifest.len() > 500 {
                    let end = manifest.floor_char_boundary(500);
                    format!("{}...", &manifest[..end])
                } else {
                    manifest
                }),
            );

            if tx.send(ev).await.is_err() {
                tracing::debug!("git capture event channel closed, dropping filesystem manifest event");
            }
            self.event_tx = Some(tx);
            return Ok(rx);
        }

        // Emit observer started event
        let ev = TraceEvent::new(&run.id, EventSource::Git, "git.observer.started");
        if tx.send(ev).await.is_err() {
            tracing::debug!("git capture event channel closed, dropping observer started event");
        }

        // Capture initial commit hash
        if let Some(hash) = Self::get_commit_hash(&cwd) {
            let mut ev = TraceEvent::new(&run.id, EventSource::Git, "git.commit");
            ev.status = EventStatus::Success;
            ev.metadata
                .insert("commit".to_string(), serde_json::json!(hash));
            self.commit_hash = Some(hash);
            if tx.send(ev).await.is_err() {
                tracing::debug!("git capture event channel closed, dropping commit event");
            }
        }

        // Capture initial diff snapshot (before the run starts producing changes)
        if let Some(diff) = Self::capture_diff(&cwd) {
            self.before_diff_blob = self
                .emit_diff_event(&run.id, "git.diff", &diff, &tx)
                .await;
        }

        self.event_tx = Some(tx);
        Ok(rx)
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        let (tx, run_id, cwd) = match (
            self.event_tx.take(),
            self.run_id.as_deref(),
            self.active_cwd.as_deref(),
        ) {
            (Some(tx), Some(run_id), Some(cwd)) => (tx, run_id.to_string(), cwd.to_string()),
            _ => return Ok(()),
        };

        if Self::is_git_repo(Path::new(&cwd)) {
            // After-run diff snapshot
            if let Some(diff) = Self::capture_diff(&cwd) {
                self.after_diff_blob = self
                    .emit_diff_event(&run_id, "git.diff.after", &diff, &tx)
                    .await;
            } else {
                let mut ev = TraceEvent::new(&run_id, EventSource::Git, "git.diff.after");
                ev.status = EventStatus::Success;
                ev.metadata
                    .insert("diff_size".to_string(), serde_json::json!(0));
                ev.metadata
                    .insert("clean".to_string(), serde_json::json!(true));
                if tx.send(ev).await.is_err() {
                    tracing::debug!("git capture event channel closed, dropping diff.after event");
                }
            }

            // Capture final commit (may have changed if commits were made)
            if let Some(hash) = Self::get_commit_hash(&cwd) {
                let mut ev = TraceEvent::new(&run_id, EventSource::Git, "git.commit.after");
                ev.status = EventStatus::Success;
                ev.metadata
                    .insert("commit".to_string(), serde_json::json!(hash));
                self.after_commit_hash = Some(hash);
                if tx.send(ev).await.is_err() {
                    tracing::debug!("git capture event channel closed, dropping commit.after event");
                }
            }
        } else {
            // After-run filesystem manifest
            let manifest = Self::filesystem_manifest(&cwd);
            let mut ev = TraceEvent::new(&run_id, EventSource::Filesystem, "filesystem.manifest.after");
            ev.status = EventStatus::Success;
            if let Some(ref store) = self.store {
                if let Ok(reference) = store.store_blob(manifest.as_bytes()).await {
                    ev.metadata.insert(
                        "filesystem_manifest_blob".to_string(),
                        serde_json::json!(reference.key),
                    );
                    self.after_diff_blob = Some(reference.key);
                }
            }
        if tx.send(ev).await.is_err() {
            tracing::debug!("git capture event channel closed, dropping after-run manifest event");
        }
        }

        let mut stop_ev = TraceEvent::new(&run_id, EventSource::Git, "git.observer.stopped");
        stop_ev.status = EventStatus::Success;
        if tx.send(stop_ev).await.is_err() {
            tracing::debug!("git capture event channel closed, dropping observer stopped event");
        }

        Ok(())
    }
}
