//! Poll harness-native log directories and feed lines into the event pipeline.
//!
//! Many agent CLIs write session JSONL under home/project dirs. Scraping the
//! PTY alone misses that structure; this side channel recovers tool calls and
//! session IDs. Per-harness roots + file filters prefer real session files
//! over huge debug dumps.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::watch;

use crate::adapters::harness::HarnessAdapter;
use crate::pipeline::EventWriter;
use crate::redaction::scanner::SecretScanner;

/// Where native harness logs may be read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NativeLogScope {
    /// Only under the project directory (default — privacy-safe).
    #[default]
    Project,
    /// Project + home-directory harness dirs (broader session recovery).
    Home,
    /// Do not poll native logs.
    Off,
}

impl NativeLogScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Home => "home",
            Self::Off => "off",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "project" | "local" | "cwd" => Some(Self::Project),
            "home" | "all" | "full" => Some(Self::Home),
            "off" | "none" | "disabled" | "false" | "0" => Some(Self::Off),
            _ => None,
        }
    }
}

/// Discover likely native log roots for a harness + project.
///
/// `scope` controls whether home-directory trees are included. Default
/// project-only avoids copying secrets from `~/.claude` etc. into `.blackbox/`.
pub fn discover_log_roots(adapter_id: &str, project_dir: &str) -> Vec<PathBuf> {
    discover_log_roots_scoped(adapter_id, project_dir, NativeLogScope::Home)
}

/// Scoped discovery (prefer this for capture).
pub fn discover_log_roots_scoped(
    adapter_id: &str,
    project_dir: &str,
    scope: NativeLogScope,
) -> Vec<PathBuf> {
    if matches!(scope, NativeLogScope::Off) {
        return Vec::new();
    }
    let include_home = matches!(scope, NativeLogScope::Home);
    let mut roots = Vec::new();
    let project = PathBuf::from(project_dir);

    match adapter_id {
        "claude" => {
            roots.push(project.join(".claude").join("logs"));
            roots.push(project.join(".claude").join("projects"));
            roots.push(project.join(".claude").join("session-env"));
            roots.push(project.join(".claude"));
            if include_home {
                if let Some(home) = dirs_home() {
                    roots.push(home.join(".claude").join("projects"));
                    roots.push(home.join(".claude").join("logs"));
                    roots.push(home.join(".claude").join("session-env"));
                    roots.push(home.join(".claude"));
                }
            }
        }
        "codex" => {
            roots.push(project.join(".codex").join("logs"));
            roots.push(project.join(".codex").join("sessions"));
            roots.push(project.join(".codex"));
            if include_home {
                if let Some(home) = dirs_home() {
                    roots.push(home.join(".codex").join("sessions"));
                    roots.push(home.join(".codex").join("logs"));
                    roots.push(home.join(".codex").join("sessions").join("rollouts"));
                    roots.push(home.join(".codex"));
                }
            }
        }
        "aider" => {
            roots.push(project.clone());
            roots.push(project.join(".aider"));
            if include_home {
                if let Some(home) = dirs_home() {
                    roots.push(home.join(".aider"));
                }
            }
        }
        "gemini" => {
            roots.push(project.join(".gemini"));
            roots.push(project.join(".gemini").join("tmp"));
            if include_home {
                if let Some(home) = dirs_home() {
                    roots.push(home.join(".gemini"));
                    roots.push(home.join(".config").join("gemini"));
                }
            }
        }
        "cursor" => {
            roots.push(project.join(".cursor"));
            roots.push(project.join(".cursor").join("projects"));
            if include_home {
                if let Some(home) = dirs_home() {
                    roots.push(home.join(".cursor"));
                    roots.push(home.join(".cursor").join("projects"));
                    roots.push(home.join(".config").join("cursor"));
                    roots.push(
                        home.join("Library")
                            .join("Application Support")
                            .join("Cursor"),
                    );
                }
            }
        }
        "opencode" => {
            roots.push(project.join(".opencode"));
            roots.push(project.join(".opencode").join("logs"));
            if include_home {
                if let Some(home) = dirs_home() {
                    roots.push(home.join(".opencode"));
                    roots.push(home.join(".local").join("share").join("opencode"));
                }
            }
        }
        "grok" => {
            roots.push(project.join(".grok"));
            roots.push(project.join(".grok").join("sessions"));
            if include_home {
                if let Some(home) = dirs_home() {
                    roots.push(home.join(".grok"));
                    roots.push(home.join(".config").join("grok"));
                }
            }
        }
        _ => {
            roots.push(project.join(".claude"));
            roots.push(project.join(".codex"));
            roots.push(project.join(".aider"));
            roots.push(project.join(".cursor"));
            roots.push(project.join(".gemini"));
            roots.push(project.join(".opencode"));
            roots.push(project.join(".grok"));
        }
    }

    roots.into_iter().filter(|p| p.exists()).collect()
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Whether this adapter may emit events from non-JSON native log lines.
pub fn accepts_plaintext_native_logs(adapter_id: &str) -> bool {
    matches!(adapter_id, "aider" | "generic")
}

/// Prefer session-ish files for a harness (name/ext heuristics).
fn is_preferred_log(adapter_id: &str, path: &Path, name: &str) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let name_l = name.to_ascii_lowercase();

    let base_ok = matches!(
        ext.as_str(),
        "json" | "jsonl" | "ndjson" | "log" | "txt" | "md"
    ) || name_l.contains("session")
        || name_l.contains("transcript")
        || name_l.contains("history")
        || name_l.ends_with(".jsonl");

    if !base_ok {
        return false;
    }

    match adapter_id {
        "claude" => {
            // Prefer project JSONL sessions over huge debug logs
            name_l.ends_with(".jsonl")
                || name_l.contains("session")
                || ext == "jsonl"
                || name_l.ends_with(".json")
        }
        "codex" => {
            name_l.ends_with(".jsonl")
                || name_l.contains("rollout")
                || name_l.contains("session")
                || ext == "jsonl"
        }
        "aider" => {
            name_l.contains("aider")
                || name_l.contains("chat.history")
                || name_l.ends_with(".md")
                || name_l.ends_with(".jsonl")
                || name == ".aider.chat.history.md"
                || name.starts_with(".aider.")
        }
        "cursor" => {
            name_l.contains("agent")
                || name_l.contains("session")
                || name_l.ends_with(".jsonl")
                || ext == "jsonl"
                || ext == "json"
        }
        "gemini" | "opencode" | "grok" => {
            name_l.ends_with(".jsonl")
                || name_l.contains("session")
                || name_l.contains("log")
                || ext == "json"
                || ext == "jsonl"
        }
        _ => true,
    }
}

/// Collect candidate log files under roots (json/jsonl/log, recent first).
pub fn list_candidate_files(roots: &[PathBuf]) -> Vec<PathBuf> {
    list_candidate_files_for("generic", roots)
}

/// Harness-aware candidate listing.
pub fn list_candidate_files_for(adapter_id: &str, roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in roots {
        // Special: aider chat history is often a single file at project root
        if adapter_id == "aider" && root.is_dir() {
            for name in [
                ".aider.chat.history.md",
                ".aider.input.history",
                "aider.chat.history.md",
            ] {
                let p = root.join(name);
                if p.is_file() {
                    files.push(p);
                }
            }
        }
        walk_logs(adapter_id, root, root, 0, &mut files);
    }
    files.sort_by_key(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .map(std::cmp::Reverse)
            .unwrap_or(std::cmp::Reverse(std::time::SystemTime::UNIX_EPOCH))
    });
    // Prefer .jsonl sessions first among same mtime by stable secondary sort
    files.sort_by(|a, b| {
        let score = |p: &Path| {
            let n = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let mut s = 0i32;
            if n.ends_with(".jsonl") {
                s += 10;
            }
            if n.contains("session") {
                s += 5;
            }
            s
        };
        score(b).cmp(&score(a))
    });
    files.truncate(48);
    files
}

fn walk_logs(adapter_id: &str, _root: &Path, dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let max_depth = if adapter_id == "cursor" { 5 } else { 4 };
    if depth > max_depth || out.len() >= 80 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') && depth > 0 && adapter_id != "aider" {
            // allow .aider* at project root (depth 0 handled by special case)
            if !(adapter_id == "aider" && name.starts_with(".aider")) {
                continue;
            }
        }
        if matches!(
            name.as_str(),
            "node_modules" | "target" | "cache" | "debug" | "tmp" | "CachedData" | "GPUCache"
        ) {
            continue;
        }
        if path.is_dir() {
            walk_logs(adapter_id, _root, &path, depth + 1, out);
        } else if path.is_file() && is_preferred_log(adapter_id, &path, &name) {
            if let Ok(meta) = entry.metadata() {
                if meta.len() > 32 * 1024 * 1024 {
                    continue;
                }
            }
            out.push(path);
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
    let adapter_id = adapter.id().to_string();
    tracing::info!(
        adapter = %adapter_id,
        roots = ?roots.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "native log ingest started"
    );

    let mut offsets: HashMap<PathBuf, u64> = HashMap::new();
    for f in list_candidate_files_for(&adapter_id, &roots) {
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
                let files = list_candidate_files_for(&adapter_id, &roots);
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
    let allow_plaintext = accepts_plaintext_native_logs(adapter.id());

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

        // Prefer structured JSON; allow plaintext for aider-style history.
        if !trimmed.starts_with('{') && !allow_plaintext {
            continue;
        }

        let mut events = adapter.parse_output(writer.run_id(), trimmed.as_bytes());
        for mut ev in events.drain(..) {
            ev.metadata.insert(
                "native_log".to_string(),
                serde_json::json!(path.display().to_string()),
            );
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
        let roots = discover_log_roots("claude", "/tmp");
        for r in &roots {
            assert!(r.exists());
        }
    }

    #[test]
    fn project_scope_excludes_home() {
        let project = "/tmp";
        let proj = discover_log_roots_scoped("claude", project, NativeLogScope::Project);
        let home = dirs_home();
        for r in &proj {
            if let Some(ref h) = home {
                assert!(
                    !r.starts_with(h),
                    "project scope must not include home path {r:?}"
                );
            }
        }
        assert!(matches!(
            discover_log_roots_scoped("claude", project, NativeLogScope::Off).as_slice(),
            []
        ));
    }

    #[test]
    fn aider_finds_chat_history_file() {
        let dir = tempfile::tempdir().unwrap();
        let hist = dir.path().join(".aider.chat.history.md");
        std::fs::write(&hist, "Running: pytest\n").unwrap();
        let files = list_candidate_files_for("aider", &[dir.path().to_path_buf()]);
        assert!(
            files.iter().any(|p| p.ends_with(".aider.chat.history.md")),
            "files={files:?}"
        );
    }

    #[test]
    fn prefers_jsonl_over_txt_name() {
        assert!(is_preferred_log(
            "claude",
            Path::new("/x/session.jsonl"),
            "session.jsonl"
        ));
        assert!(!is_preferred_log(
            "claude",
            Path::new("/x/image.png"),
            "image.png"
        ));
    }
}
