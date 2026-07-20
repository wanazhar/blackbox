//! Poll harness-native log directories and feed lines into the event pipeline.
//!
//! Many agent CLIs write session JSONL under home/project dirs. Scraping the
//! PTY alone misses that structure; this side channel recovers tool calls and
//! session IDs. Per-harness roots + file filters prefer real session files
//! over huge debug dumps.
//!
//! **1.5 C1 (native-log boundary):** files are tracked by identity (inode /
//! size / generation), not path+offset alone. Discovery runs once at start
//! (and rarely for new files); poll cycles do not recursively rescan large
//! home trees every tick. Rate limits expose backlog instead of implying
//! completeness.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::watch;

use crate::adapters::harness::HarnessAdapter;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::pipeline::EventWriter;
use crate::redaction::scanner::SecretScanner;

/// Max lines emitted from a single file in one poll cycle.
const RATE_LIMIT_LINES_PER_FILE: u32 = 500;
/// How often to re-walk roots for *new* files (not every tick).
const REDISCOVER_INTERVAL: Duration = Duration::from_secs(30);
/// Max tracked files before pruning missing paths.
const MAX_TRACKED_FILES: usize = 128;

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

/// Identity of a watched log file (1.5: not path/offset alone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    pub inode: u64,
    pub device: u64,
    pub created: Option<SystemTime>,
    pub generation: u64,
}

/// Per-file poller state.
#[derive(Debug, Clone)]
pub struct TrackedLogFile {
    pub path: PathBuf,
    pub identity: FileIdentity,
    pub size: u64,
    pub offset: u64,
    /// Bytes not yet consumed after a rate-limit stop.
    pub backlog_bytes: u64,
    /// Lines deferred due to rate limit this cycle (best-effort counter).
    pub deferred_lines: u64,
    pub rotations: u64,
}

impl TrackedLogFile {
    pub fn from_meta(path: PathBuf, meta: &std::fs::Metadata, generation: u64) -> Self {
        let (inode, device) = file_ids(meta);
        let created = meta.created().ok();
        let size = meta.len();
        Self {
            path,
            identity: FileIdentity {
                inode,
                device,
                created,
                generation,
            },
            size,
            // Start at EOF for existing content at discovery (avoid replaying history).
            offset: size,
            backlog_bytes: 0,
            deferred_lines: 0,
            rotations: 0,
        }
    }
}

/// Aggregate health for native-log surface (coverage / doctor).
#[derive(Debug, Clone, Default)]
pub struct NativeLogHealth {
    pub tracked_files: usize,
    pub backlog_bytes: u64,
    pub deferred_lines: u64,
    pub rotations: u64,
    pub poll_errors: u64,
    pub last_discovery_files: usize,
}

/// Extract stable file IDs when the OS provides them.
pub fn file_ids(meta: &std::fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (meta.ino(), meta.dev())
    }
    #[cfg(not(unix))]
    {
        // Fallback: size + mtime as weak identity.
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        (meta.len() ^ mtime, 0)
    }
}

/// Classify how metadata changed relative to tracked state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileChange {
    Unchanged,
    Appended,
    Truncated,
    /// Same path, different inode/device/created → rotation or replace.
    RotatedOrReplaced,
    Missing,
}

/// Detect rotation / truncate / append from identity + size.
pub fn classify_file_change(tracked: &TrackedLogFile, meta: &std::fs::Metadata) -> FileChange {
    let (inode, device) = file_ids(meta);
    let created = meta.created().ok();
    let size = meta.len();

    let id_changed = inode != tracked.identity.inode
        || device != tracked.identity.device
        || match (created, tracked.identity.created) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        };

    if id_changed {
        return FileChange::RotatedOrReplaced;
    }
    if size < tracked.offset {
        return FileChange::Truncated;
    }
    if size > tracked.offset {
        return FileChange::Appended;
    }
    FileChange::Unchanged
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

    // Initial discovery off the async worker (blocking tree walk).
    let roots_for_discover = roots.clone();
    let adapter_for_discover = adapter_id.clone();
    let initial = tokio::task::spawn_blocking(move || {
        list_candidate_files_for(&adapter_for_discover, &roots_for_discover)
    })
    .await
    .unwrap_or_default();

    let mut tracked: HashMap<PathBuf, TrackedLogFile> = HashMap::new();
    let mut generation = 1u64;
    for f in initial {
        if let Ok(meta) = std::fs::metadata(&f) {
            tracked.insert(f.clone(), TrackedLogFile::from_meta(f, &meta, generation));
        }
    }
    generation = generation.saturating_add(1);

    let mut health = NativeLogHealth {
        tracked_files: tracked.len(),
        last_discovery_files: tracked.len(),
        ..Default::default()
    };
    emit_native_log_health(writer.as_ref(), &health, "started").await;

    let mut tick = tokio::time::interval(Duration::from_millis(750));
    let mut last_rediscover = std::time::Instant::now();

    loop {
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() {
                    break;
                }
            }
            _ = tick.tick() => {
                // Rare rediscovery for *new* files only — not every poll cycle.
                if last_rediscover.elapsed() >= REDISCOVER_INTERVAL {
                    last_rediscover = std::time::Instant::now();
                    let roots_c = roots.clone();
                    let aid = adapter_id.clone();
                    let found = tokio::task::spawn_blocking(move || {
                        list_candidate_files_for(&aid, &roots_c)
                    })
                    .await
                    .unwrap_or_default();
                    health.last_discovery_files = found.len();
                    for f in found {
                        if tracked.contains_key(&f) {
                            continue;
                        }
                        if let Ok(meta) = std::fs::metadata(&f) {
                            tracked.insert(
                                f.clone(),
                                TrackedLogFile::from_meta(f, &meta, generation),
                            );
                            generation = generation.saturating_add(1);
                        }
                    }
                    if tracked.len() > MAX_TRACKED_FILES {
                        tracked.retain(|path, _| path.exists());
                    }
                }

                // Poll only tracked paths (no full tree walk each tick).
                let paths: Vec<PathBuf> = tracked.keys().cloned().collect();
                for path in paths {
                    match ingest_tracked_file(
                        &path,
                        &mut tracked,
                        adapter.as_ref(),
                        writer.as_ref(),
                        &scanner,
                        &mut generation,
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            health.poll_errors = health.poll_errors.saturating_add(1);
                            tracing::debug!(
                                error = %e,
                                path = %path.display(),
                                "native log ingest error (surface-local)"
                            );
                        }
                    }
                }

                // Refresh aggregate health gauges.
                health.tracked_files = tracked.len();
                health.backlog_bytes = tracked.values().map(|t| t.backlog_bytes).sum();
                health.deferred_lines = tracked.values().map(|t| t.deferred_lines).sum();
                health.rotations = tracked.values().map(|t| t.rotations).sum();
            }
        }
    }

    emit_native_log_health(writer.as_ref(), &health, "stopped").await;
    tracing::debug!(
        tracked = health.tracked_files,
        backlog = health.backlog_bytes,
        deferred = health.deferred_lines,
        rotations = health.rotations,
        "native log ingest stopped"
    );
}

async fn emit_native_log_health(writer: &EventWriter, health: &NativeLogHealth, phase: &str) {
    let mut ev = TraceEvent::new(writer.run_id(), EventSource::System, "native_log.health");
    ev.status = EventStatus::Success;
    ev.metadata.insert("phase".into(), serde_json::json!(phase));
    ev.metadata.insert(
        "tracked_files".into(),
        serde_json::json!(health.tracked_files),
    );
    ev.metadata.insert(
        "backlog_bytes".into(),
        serde_json::json!(health.backlog_bytes),
    );
    ev.metadata.insert(
        "deferred_lines".into(),
        serde_json::json!(health.deferred_lines),
    );
    ev.metadata
        .insert("rotations".into(), serde_json::json!(health.rotations));
    ev.metadata
        .insert("poll_errors".into(), serde_json::json!(health.poll_errors));
    let _ = writer.write(ev).await;
}

async fn ingest_tracked_file(
    path: &Path,
    tracked: &mut HashMap<PathBuf, TrackedLogFile>,
    adapter: &dyn HarnessAdapter,
    writer: &EventWriter,
    scanner: &SecretScanner,
    generation: &mut u64,
) -> anyhow::Result<()> {
    let meta = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(_) => {
            tracked.remove(path);
            return Ok(());
        }
    };

    let state = tracked
        .entry(path.to_path_buf())
        .or_insert_with(|| TrackedLogFile::from_meta(path.to_path_buf(), &meta, *generation));

    let change = classify_file_change(state, &meta);
    match change {
        FileChange::Unchanged => {
            state.size = meta.len();
            return Ok(());
        }
        FileChange::RotatedOrReplaced => {
            state.rotations = state.rotations.saturating_add(1);
            *generation = generation.saturating_add(1);
            let gen = *generation;
            *state = TrackedLogFile::from_meta(path.to_path_buf(), &meta, gen);
            // After rotation, read from start of the new file (offset 0).
            state.offset = 0;
            emit_rotation_event(writer, path, "rotated_or_replaced", state).await;
        }
        FileChange::Truncated => {
            state.rotations = state.rotations.saturating_add(1);
            state.offset = 0;
            state.size = meta.len();
            emit_rotation_event(writer, path, "truncated", state).await;
        }
        FileChange::Appended => {
            state.size = meta.len();
        }
        FileChange::Missing => {
            tracked.remove(path);
            return Ok(());
        }
    }

    let start = state.offset;
    let len = meta.len();
    if len <= start {
        state.backlog_bytes = 0;
        state.deferred_lines = 0;
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
    let inode = state.identity.inode;
    let gen = state.identity.generation;

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        // Peek: if we already hit the rate limit, do not consume further bytes
        // into pos — leave them as backlog for the next cycle.
        if emitted >= RATE_LIMIT_LINES_PER_FILE {
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

        // Redact the line before parse so tool payloads never carry raw secrets
        // into metadata construction. JSON structure with [REDACTED] still parses.
        let safe_line = scanner.redact(trimmed);

        let mut events = adapter.parse_output(writer.run_id(), safe_line.as_bytes());
        for mut ev in events.drain(..) {
            ev.metadata.insert(
                "native_log".to_string(),
                serde_json::json!(path.display().to_string()),
            );
            ev.metadata
                .insert("native_log_inode".into(), serde_json::json!(inode));
            ev.metadata
                .insert("native_log_generation".into(), serde_json::json!(gen));
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
                emitted = emitted.saturating_add(1);
            }
        }
    }

    if let Some(st) = tracked.get_mut(path) {
        st.offset = pos;
        st.size = len;
        st.backlog_bytes = len.saturating_sub(pos);
        // Estimate deferred lines as remaining bytes / ~80 (honest backlog signal).
        st.deferred_lines = if st.backlog_bytes > 0 {
            (st.backlog_bytes / 80).max(1)
        } else {
            0
        };
        if st.backlog_bytes > 0 {
            tracing::warn!(
                path = %path.display(),
                backlog_bytes = st.backlog_bytes,
                deferred_lines_est = st.deferred_lines,
                "native log ingest rate-limited; backlog remains (not complete)"
            );
        }
    }

    if emitted > 0 {
        tracing::debug!(
            path = %path.display(),
            emitted,
            "native log lines → events"
        );
    }
    Ok(())
}

async fn emit_rotation_event(
    writer: &EventWriter,
    path: &Path,
    reason: &str,
    state: &TrackedLogFile,
) {
    let mut ev = TraceEvent::new(writer.run_id(), EventSource::System, "native_log.rotation");
    ev.status = EventStatus::Success;
    ev.metadata
        .insert("path".into(), serde_json::json!(path.display().to_string()));
    ev.metadata
        .insert("reason".into(), serde_json::json!(reason));
    ev.metadata
        .insert("inode".into(), serde_json::json!(state.identity.inode));
    ev.metadata.insert(
        "generation".into(),
        serde_json::json!(state.identity.generation),
    );
    ev.metadata
        .insert("rotations".into(), serde_json::json!(state.rotations));
    let _ = writer.write(ev).await;
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

    #[test]
    fn classify_append_truncate_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.jsonl");
        std::fs::write(&path, b"line1\n").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let mut tracked = TrackedLogFile::from_meta(path.clone(), &meta, 1);
        tracked.offset = meta.len();

        // Append
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"line2\n")
            .unwrap();
        let meta2 = std::fs::metadata(&path).unwrap();
        assert_eq!(classify_file_change(&tracked, &meta2), FileChange::Appended);

        // Truncate (same inode, smaller size)
        std::fs::write(&path, b"new\n").unwrap();
        let meta3 = std::fs::metadata(&path).unwrap();
        // On most Unix FS, rewrite keeps inode → truncated relative to old offset
        tracked.offset = meta2.len(); // old end
        let ch = classify_file_change(&tracked, &meta3);
        assert!(
            matches!(ch, FileChange::Truncated | FileChange::RotatedOrReplaced),
            "got {ch:?}"
        );
    }

    #[test]
    fn classify_same_path_replace_as_rotation_when_inode_changes() {
        // Simulate identity change by constructing two TrackedLogFile states.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        std::fs::write(&path, b"a\n").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let mut tracked = TrackedLogFile::from_meta(path.clone(), &meta, 1);
        tracked.offset = 1;
        // Force different inode in tracked identity
        tracked.identity.inode = tracked.identity.inode.wrapping_add(99999);
        let meta2 = std::fs::metadata(&path).unwrap();
        assert_eq!(
            classify_file_change(&tracked, &meta2),
            FileChange::RotatedOrReplaced
        );
    }
}
