use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::run::Run;
use crate::storage::TraceStore;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// Git-aware change tracker.
///
/// Captures repository state before and after each action:
/// - Current commit hash
/// - Working tree diff (unstaged + staged changes)
/// - Stores diff as a content-addressed blob
pub struct GitCapture {
    /// Working directory to run git commands in
    cwd: Option<String>,
    /// Optional store for persisting diffs as content-addressed blobs
    store: Option<Arc<dyn TraceStore>>,
}

impl GitCapture {
    pub fn new() -> Self {
        Self { cwd: None, store: None }
    }

    /// Attach a trace store so diffs are persisted as blobs.
    pub fn with_store(mut self, store: Arc<dyn TraceStore>) -> Self {
        self.store = Some(store);
        self
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
                    String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string())
                } else {
                    None
                }
            })
    }

    /// Get the working tree diff (unstaged changes).
    fn get_diff(cwd: &str) -> Option<String> {
        Command::new("git")
            .args(["diff"])
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
            .args(["diff", "--cached"])
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
            Some(parts.join("\n\n"))
        }
    }
}

#[async_trait]
impl CaptureLayer for GitCapture {
    fn name(&self) -> &'static str {
        "git"
    }

    async fn start(&mut self, run: &Run) -> anyhow::Result<mpsc::Receiver<TraceEvent>> {
        let (tx, rx) = mpsc::channel(1024);
        let cwd = self.cwd.as_deref().unwrap_or(&run.cwd);

        if !Self::is_git_repo(Path::new(cwd)) {
            tracing::debug!(cwd = cwd, "not a git repository, skipping git capture");
            // Send a single event noting this is not a git repo
            let mut ev = TraceEvent::new(&run.id, EventSource::Git, "git.not_a_repo");
            ev.status = EventStatus::Success;
            ev.metadata
                .insert("cwd".to_string(), serde_json::json!(cwd));
            let _ = tx.send(ev).await;
            drop(tx);
            return Ok(rx);
        }

        // Emit observer started event
        let ev = TraceEvent::new(&run.id, EventSource::Git, "git.observer.started");
        let _ = tx.send(ev).await;

        // Capture initial commit hash
        if let Some(hash) = Self::get_commit_hash(cwd) {
            let mut ev = TraceEvent::new(&run.id, EventSource::Git, "git.commit");
            ev.status = EventStatus::Success;
            ev.metadata
                .insert("commit".to_string(), serde_json::json!(hash));
            let _ = tx.send(ev).await;
        }

        // Capture initial diff snapshot (before the run starts producing changes)
        if let Some(diff) = Self::capture_diff(cwd) {
            let mut ev = TraceEvent::new(&run.id, EventSource::Git, "git.diff");
            ev.status = EventStatus::Success;
            ev.metadata
                .insert("diff_size".to_string(), serde_json::json!(diff.len()));
            ev.metadata
                .insert("diff_preview".to_string(), serde_json::json!(
                    if diff.len() > 500 {
                        format!("{}...", &diff[..500])
                    } else {
                        diff.clone()
                    }
                ));

            // Store the full diff as a content-addressed blob
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
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to store git diff blob");
                    }
                }
            }

            let _ = tx.send(ev).await;
        }

        Ok(rx)
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
