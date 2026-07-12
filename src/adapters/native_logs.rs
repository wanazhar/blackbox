//! Poll harness-native log directories and feed lines into the event pipeline.
//!
//! Many agent CLIs write session JSONL under `~/.claude`, `~/.codex`, or
//! project-local folders. Scraping the PTY alone misses that structure;
//! this side channel recovers tool calls and session IDs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::watch;

use crate::adapters::harness::HarnessAdapter;
use crate::pipeline::EventWriter;
use crate::redaction::scanner::SecretScanner;

/// Discover likely native log roots for a harness + project.
pub fn discover_log_roots(adapter_id: &str, project_dir: &str) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let project = PathBuf::from(project_dir);

    match adapter_id {
        "claude" => {
            roots.push(project.join(".claude").join("logs"));
            roots.push(project.join(".claude").join("projects"));
            roots.push(project.join(".claude"));
            if let Some(home) = dirs_home() {
                roots.push(home.join(".claude").join("projects"));
                roots.push(home.join(".claude").join("logs"));
                roots.push(home.join(".claude"));
            }
        }
        "codex" => {
            roots.push(project.join(".codex").join("logs"));
            roots.push(project.join(".codex").join("sessions"));
            roots.push(project.join(".codex"));
            if let Some(home) = dirs_home() {
                roots.push(home.join(".codex").join("sessions"));
                roots.push(home.join(".codex").join("logs"));
                roots.push(home.join(".codex"));
            }
        }
        _ => {
            // Generic: light probe of common agent dirs
            roots.push(project.join(".claude"));
            roots.push(project.join(".codex"));
        }
    }

    roots.into_iter().filter(|p| p.exists()).collect()
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Collect candidate log files under roots (json/jsonl/log, recent first).
pub fn list_candidate_files(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in roots {
        walk_logs(root, root, 0, &mut files);
    }
    // Prefer recently modified
    files.sort_by_key(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .map(std::cmp::Reverse)
            .unwrap_or(std::cmp::Reverse(std::time::SystemTime::UNIX_EPOCH))
    });
    files.truncate(32); // cap watch set
    files
}

fn walk_logs(_root: &Path, dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 4 || out.len() >= 64 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') && depth > 0 {
            continue;
        }
        // Skip noise
        if matches!(
            name.as_str(),
            "node_modules" | "target" | "cache" | "debug" | "tmp"
        ) {
            continue;
        }
        if path.is_dir() {
            walk_logs(_root, &path, depth + 1, out);
        } else if path.is_file() {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let is_log = matches!(ext.as_str(), "json" | "jsonl" | "ndjson" | "log" | "txt")
                || name.contains("session")
                || name.contains("transcript")
                || name.ends_with(".jsonl");
            if is_log {
                // Skip huge files (>32 MiB)
                if let Ok(meta) = entry.metadata() {
                    if meta.len() > 32 * 1024 * 1024 {
                        continue;
                    }
                }
                out.push(path);
            }
        }
    }
}

/// Background poller: read new lines from native logs and emit structured events.
pub async fn poll_native_logs(
    adapter: Arc<dyn HarnessAdapter>,
    writer: Arc<EventWriter>,
    roots: Vec<PathBuf>,
    scanner: SecretScanner,
    mut stop: watch::Receiver<bool>,
) {
    if roots.is_empty() {
        tracing::debug!("native log ingest: no log roots found");
        return;
    }
    tracing::info!(
        roots = ?roots.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "native log ingest started"
    );

    let mut offsets: HashMap<PathBuf, u64> = HashMap::new();
    // Prime offsets at EOF so we only read *new* lines after attach
    for f in list_candidate_files(&roots) {
        if let Ok(meta) = std::fs::metadata(&f) {
            offsets.insert(f, meta.len());
        }
    }

    let mut tick = tokio::time::interval(Duration::from_millis(750));
    loop {
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() {
                    break;
                }
            }
            _ = tick.tick() => {
                let files = list_candidate_files(&roots);
                // Prune offset entries for files that no longer exist
                // when the map grows large
                if offsets.len() > 100 {
                    offsets.retain(|path, _| path.exists());
                }
                for path in files {
                    if let Err(e) = ingest_file_delta(
                        &path,
                        &mut offsets,
                        adapter.as_ref(),
                        writer.as_ref(),
                        &scanner,
                    ).await {
                        tracing::debug!(error = %e, path = %path.display(), "native log ingest error");
                    }
                }
            }
        }
    }
    tracing::debug!("native log ingest stopped");
}

async fn ingest_file_delta(
    path: &Path,
    offsets: &mut HashMap<PathBuf, u64>,
    adapter: &dyn HarnessAdapter,
    writer: &EventWriter,
    scanner: &SecretScanner,
) -> anyhow::Result<()> {
    let meta = tokio::fs::metadata(path).await?;
    let len = meta.len();
    let start = offsets.get(path).copied().unwrap_or(0);

    // Truncated / rotated
    let start = if len < start { 0 } else { start };
    if len == start {
        return Ok(());
    }

    let file = tokio::fs::File::open(path).await?;
    let mut file = file;
    file.seek(std::io::SeekFrom::Start(start)).await?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut pos = start;
    let mut emitted = 0u32;

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        pos += n as u64;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Only structured lines — avoid dumping entire debug logs as events
        if !trimmed.starts_with('{') {
            continue;
        }

        let mut events = adapter.parse_output(writer.run_id(), trimmed.as_bytes());
        for mut ev in events.drain(..) {
            // Tag provenance
            ev.metadata.insert(
                "native_log".to_string(),
                serde_json::json!(path.display().to_string()),
            );
            // Redact metadata
            let mut meta_val = serde_json::to_value(&ev.metadata).unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    event_id = %ev.id,
                    "failed to serialize event metadata for redaction, using empty map"
                );
                serde_json::json!({})
            });
            scanner.redact_json(&mut meta_val);
            if let Ok(m) = serde_json::from_value(meta_val) {
                ev.metadata = m;
            }
            if let Err(e) = writer.write(ev).await {
                tracing::debug!(error = %e, "failed to persist native log event");
            } else {
                emitted += 1;
            }
        }

        // SAFETY: cap per-cycle emission to prevent unbounded memory growth
        // when the log file has a large backlog.  500 events is enough for
        // a burst of activity while keeping the ingest loop bounded.
        if emitted > 500 {
            tracing::warn!(path = %path.display(), "native log ingest rate-limited this cycle");
            break;
        }
    }

    offsets.insert(path.to_path_buf(), pos);
    if emitted > 0 {
        tracing::debug!(
            path = %path.display(),
            emitted,
            "native log lines → events"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn list_candidate_finds_jsonl() {
        let dir = std::env::temp_dir().join(format!("bb-nativelog-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"{{"type":"system","session_id":"abc"}}"#).unwrap();

        let files = list_candidate_files(std::slice::from_ref(&dir));
        assert!(files.iter().any(|p| p.ends_with("session.jsonl")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discover_claude_roots_filters_missing() {
        // Should not panic; may be empty if no .claude on system
        let roots = discover_log_roots("claude", "/tmp");
        for r in &roots {
            assert!(r.exists());
        }
    }
}
