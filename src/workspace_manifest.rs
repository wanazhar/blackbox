//! Versioned workspace manifests for checkpoint completeness (1.5 W1).
//!
//! Captures relative paths with content hashes so restore can report
//! expected/restored/missing files and explicit limits — not only a git
//! commit + textual staged/unstaged diff.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::crypto::content_key;
use crate::storage::TraceStore;

/// Manifest format version.
pub const WORKSPACE_MANIFEST_VERSION: u32 = 1;

/// Shared noise dirs ignored by filesystem capture, seed, and manifests.
pub const IGNORE_DIR_NAMES: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".blackbox",
    ".cargo",
    "__pycache__",
    ".tox",
    "dist",
    "build",
    ".venv",
    "venv",
    ".next",
];

const DEFAULT_MAX_FILES: usize = 5_000;
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB content hashed
const DEFAULT_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024; // 8 MiB per file hash
const DEFAULT_MAX_DEPTH: usize = 8;

/// Capture bounds for a workspace walk.
#[derive(Debug, Clone)]
pub struct ManifestLimits {
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_depth: usize,
    /// When true, store file contents as blobs (required for full restore).
    pub store_blobs: bool,
}

impl Default for ManifestLimits {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_FILES,
            max_total_bytes: DEFAULT_MAX_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_depth: DEFAULT_MAX_DEPTH,
            store_blobs: true,
        }
    }
}

/// Entry type in a workspace manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManifestEntryType {
    File,
    Dir,
    Symlink,
}

/// One path in the workspace snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub entry_type: ManifestEntryType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
    /// tracked | untracked | unknown
    #[serde(default)]
    pub git_state: String,
    /// Whether content was fully captured (false if skipped for size/limit).
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

/// Versioned workspace manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceManifest {
    pub version: u32,
    pub root: String,
    pub captured_at: DateTime<Utc>,
    pub entries: Vec<ManifestEntry>,
    pub files_total: u64,
    pub bytes_total: u64,
    pub capture_complete: bool,
    #[serde(default)]
    pub limitations: Vec<String>,
}

/// Result of restoring a workspace from a manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreReport {
    pub expected: usize,
    pub restored: usize,
    pub missing: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
    pub limitations: Vec<String>,
    pub complete: bool,
}

impl WorkspaceManifest {
    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(s: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

/// Return true when a path component should be ignored.
pub fn is_ignored_component(name: &str) -> bool {
    IGNORE_DIR_NAMES.contains(&name)
        || name == "blackbox.db"
        || name.starts_with("blackbox.db-")
}

/// Capture a bounded workspace manifest. Optionally store file blobs.
pub async fn capture_workspace_manifest(
    root: &Path,
    store: Option<&dyn TraceStore>,
    limits: ManifestLimits,
) -> anyhow::Result<WorkspaceManifest> {
    let root = root
        .canonicalize()
        .with_context(|| format!("canonicalize {}", root.display()))?;

    let mut entries = Vec::new();
    let mut files_total = 0u64;
    let mut bytes_hashed = 0u64;
    let mut limitations = Vec::new();
    let mut hit_file_limit = false;
    let mut hit_byte_limit = false;

    // Iterative DFS: (dir, depth)
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.clone(), 0)];

    while let Some((dir, depth)) = stack.pop() {
        if hit_file_limit {
            break;
        }
        if depth > limits.max_depth {
            limitations.push(format!(
                "max depth {} hit under {}",
                limits.max_depth,
                rel_display(&root, &dir)
            ));
            continue;
        }

        let read_dir = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                limitations.push(format!("read_dir {}: {e}", dir.display()));
                continue;
            }
        };

        let mut children: Vec<_> = read_dir.flatten().collect();
        children.sort_by_key(|e| e.file_name());
        // Push dirs in reverse so we process sorted order on pop.
        for entry in children.into_iter().rev() {
            if entries.len() >= limits.max_files {
                hit_file_limit = true;
                break;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if is_ignored_component(&name) {
                continue;
            }
            let rel = match path.strip_prefix(&root) {
                Ok(r) => r.to_string_lossy().replace('\\', "/"),
                Err(_) => continue,
            };
            if validate_rel_path(&rel).is_err() {
                limitations.push(format!("skipped unsafe path: {rel}"));
                continue;
            }

            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    limitations.push(format!("stat {rel}: {e}"));
                    continue;
                }
            };

            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                Some(meta.permissions().mode())
            };
            #[cfg(not(unix))]
            let mode = None;

            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path)
                    .map(|p| p.to_string_lossy().into_owned())
                    .ok();
                entries.push(ManifestEntry {
                    path: rel,
                    entry_type: ManifestEntryType::Symlink,
                    content_hash: None,
                    size: None,
                    mode,
                    symlink_target: target,
                    git_state: "unknown".into(),
                    complete: true,
                    skip_reason: None,
                });
                continue;
            }

            if meta.is_dir() {
                entries.push(ManifestEntry {
                    path: rel,
                    entry_type: ManifestEntryType::Dir,
                    content_hash: None,
                    size: None,
                    mode,
                    symlink_target: None,
                    git_state: "unknown".into(),
                    complete: true,
                    skip_reason: None,
                });
                stack.push((path, depth + 1));
                continue;
            }

            if !meta.is_file() {
                continue;
            }

            files_total += 1;
            let size = meta.len();

            if size > limits.max_file_bytes {
                entries.push(ManifestEntry {
                    path: rel,
                    entry_type: ManifestEntryType::File,
                    content_hash: None,
                    size: Some(size),
                    mode,
                    symlink_target: None,
                    git_state: "unknown".into(),
                    complete: false,
                    skip_reason: Some(format!(
                        "file exceeds max_file_bytes {}",
                        limits.max_file_bytes
                    )),
                });
                continue;
            }
            if bytes_hashed.saturating_add(size) > limits.max_total_bytes {
                hit_byte_limit = true;
                entries.push(ManifestEntry {
                    path: rel,
                    entry_type: ManifestEntryType::File,
                    content_hash: None,
                    size: Some(size),
                    mode,
                    symlink_target: None,
                    git_state: "unknown".into(),
                    complete: false,
                    skip_reason: Some("total byte budget exhausted".into()),
                });
                continue;
            }

            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    entries.push(ManifestEntry {
                        path: rel,
                        entry_type: ManifestEntryType::File,
                        content_hash: None,
                        size: Some(size),
                        mode,
                        symlink_target: None,
                        git_state: "unknown".into(),
                        complete: false,
                        skip_reason: Some(format!("read failed: {e}")),
                    });
                    continue;
                }
            };
            bytes_hashed = bytes_hashed.saturating_add(data.len() as u64);
            let hash = content_key(&data);
            if limits.store_blobs {
                if let Some(store) = store {
                    if let Err(e) = store.store_blob(&data).await {
                        limitations.push(format!("store blob {rel}: {e}"));
                    }
                }
            }
            entries.push(ManifestEntry {
                path: rel,
                entry_type: ManifestEntryType::File,
                content_hash: Some(hash),
                size: Some(size),
                mode,
                symlink_target: None,
                git_state: "unknown".into(),
                complete: true,
                skip_reason: None,
            });
        }
    }

    if hit_file_limit {
        limitations.push(format!(
            "file count limit {} reached; remaining paths omitted",
            limits.max_files
        ));
    }
    if hit_byte_limit {
        limitations.push(format!(
            "total content byte limit {} reached; remaining content not hashed/stored",
            limits.max_total_bytes
        ));
    }

    // Stable order for diffs.
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let capture_complete = limitations.is_empty();
    Ok(WorkspaceManifest {
        version: WORKSPACE_MANIFEST_VERSION,
        root: root.display().to_string(),
        captured_at: Utc::now(),
        entries,
        files_total,
        bytes_total: bytes_hashed,
        capture_complete,
        limitations,
    })
}

fn rel_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

/// Restore files from a manifest into `dest`. Never escapes `dest`.
pub async fn restore_workspace_manifest(
    manifest: &WorkspaceManifest,
    dest: &Path,
    store: &dyn TraceStore,
) -> anyhow::Result<RestoreReport> {
    std::fs::create_dir_all(dest).context("create restore destination")?;
    let dest = dest
        .canonicalize()
        .with_context(|| format!("canonicalize dest {}", dest.display()))?;

    let mut expected = 0usize;
    let mut restored = 0usize;
    let mut missing = 0usize;
    let mut skipped = 0usize;
    let mut errors = Vec::new();
    let mut limitations = manifest.limitations.clone();

    for entry in &manifest.entries {
        if entry.entry_type != ManifestEntryType::Dir {
            continue;
        }
        if let Err(e) = validate_rel_path(&entry.path) {
            errors.push(format!("{}: {e}", entry.path));
            continue;
        }
        let target = dest.join(&entry.path);
        if !target.starts_with(&dest) {
            errors.push(format!("{}: path escapes destination", entry.path));
            continue;
        }
        if let Err(e) = std::fs::create_dir_all(&target) {
            errors.push(format!("{}: mkdir: {e}", entry.path));
        }
    }

    for entry in &manifest.entries {
        match entry.entry_type {
            ManifestEntryType::Dir => {}
            ManifestEntryType::Symlink => {
                expected += 1;
                if let Err(e) = validate_rel_path(&entry.path) {
                    errors.push(format!("{}: {e}", entry.path));
                    missing += 1;
                    continue;
                }
                let Some(ref target) = entry.symlink_target else {
                    skipped += 1;
                    limitations.push(format!("{}: symlink missing target", entry.path));
                    continue;
                };
                if Path::new(target).is_absolute() || target.contains("..") {
                    skipped += 1;
                    limitations.push(format!(
                        "{}: symlink target rejected (absolute or traversal)",
                        entry.path
                    ));
                    continue;
                }
                let link_path = dest.join(&entry.path);
                if let Some(parent) = link_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::symlink;
                    let _ = std::fs::remove_file(&link_path);
                    match symlink(target, &link_path) {
                        Ok(()) => restored += 1,
                        Err(e) => {
                            errors.push(format!("{}: symlink: {e}", entry.path));
                            missing += 1;
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    skipped += 1;
                    limitations.push(format!("{}: symlink restore not supported", entry.path));
                }
            }
            ManifestEntryType::File => {
                expected += 1;
                if !entry.complete {
                    skipped += 1;
                    if let Some(ref r) = entry.skip_reason {
                        limitations.push(format!("{}: skipped at capture ({r})", entry.path));
                    }
                    continue;
                }
                if let Err(e) = validate_rel_path(&entry.path) {
                    errors.push(format!("{}: {e}", entry.path));
                    missing += 1;
                    continue;
                }
                let Some(ref hash) = entry.content_hash else {
                    missing += 1;
                    errors.push(format!("{}: missing content hash", entry.path));
                    continue;
                };
                let Some(bref) = crate::core::blob::BlobReference::try_new(hash.clone(), 0) else {
                    missing += 1;
                    errors.push(format!("{}: invalid blob key", entry.path));
                    continue;
                };
                let data = match store.load_blob(&bref).await {
                    Ok(d) => d,
                    Err(e) => {
                        missing += 1;
                        errors.push(format!("{}: load blob: {e}", entry.path));
                        continue;
                    }
                };
                let computed = content_key(&data);
                if computed != *hash {
                    missing += 1;
                    errors.push(format!("{}: blob integrity mismatch", entry.path));
                    continue;
                }
                let out = dest.join(&entry.path);
                if !out.starts_with(&dest) {
                    errors.push(format!("{}: path escapes destination", entry.path));
                    missing += 1;
                    continue;
                }
                if let Some(parent) = out.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let tmp = out.with_extension("bb-restore-tmp");
                match std::fs::write(&tmp, &data).and_then(|_| std::fs::rename(&tmp, &out)) {
                    Ok(()) => {
                        #[cfg(unix)]
                        if let Some(mode) = entry.mode {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(
                                &out,
                                std::fs::Permissions::from_mode(mode),
                            );
                        }
                        restored += 1;
                    }
                    Err(e) => {
                        missing += 1;
                        errors.push(format!("{}: write: {e}", entry.path));
                        let _ = std::fs::remove_file(&tmp);
                    }
                }
            }
        }
    }

    let complete = missing == 0 && errors.is_empty() && skipped == 0 && manifest.capture_complete;
    Ok(RestoreReport {
        expected,
        restored,
        missing,
        skipped,
        errors,
        limitations,
        complete,
    })
}

/// Reject absolute / traversal relative paths.
pub fn validate_rel_path(path: &str) -> anyhow::Result<()> {
    let path = path.trim();
    if path.is_empty() {
        anyhow::bail!("empty path");
    }
    if path.starts_with('/') || path.starts_with('\\') {
        anyhow::bail!("absolute path rejected");
    }
    for comp in Path::new(path).components() {
        match comp {
            std::path::Component::ParentDir => anyhow::bail!("path traversal rejected"),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                anyhow::bail!("absolute path rejected");
            }
            _ => {}
        }
    }
    Ok(())
}

/// Index entries by path for quick lookup.
pub fn index_by_path(m: &WorkspaceManifest) -> BTreeMap<&str, &ManifestEntry> {
    m.entries.iter().map(|e| (e.path.as_str(), e)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::sqlite::SqliteStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn capture_and_restore_round_trip() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("a.txt"), b"hello").unwrap();
        std::fs::write(src.path().join("sub/b.bin"), b"\x00\x01\x02binary").unwrap();
        std::fs::create_dir_all(src.path().join("target")).unwrap();
        std::fs::write(src.path().join("target/x"), b"noise").unwrap();

        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let manifest = capture_workspace_manifest(
            src.path(),
            Some(store.as_ref()),
            ManifestLimits::default(),
        )
        .await
        .unwrap();

        assert!(manifest.entries.iter().any(|e| e.path == "a.txt"));
        assert!(manifest.entries.iter().any(|e| e.path == "sub/b.bin"));
        assert!(!manifest
            .entries
            .iter()
            .any(|e| e.path.starts_with("target")));

        let dest = tempfile::tempdir().unwrap();
        let report = restore_workspace_manifest(&manifest, dest.path(), store.as_ref())
            .await
            .unwrap();
        assert!(report.complete, "report={report:?}");
        assert_eq!(
            std::fs::read(dest.path().join("a.txt")).unwrap(),
            b"hello"
        );
        assert_eq!(
            std::fs::read(dest.path().join("sub/b.bin")).unwrap(),
            b"\x00\x01\x02binary"
        );
    }

    #[test]
    fn validate_rel_path_rejects_escape() {
        assert!(validate_rel_path("ok/file.txt").is_ok());
        assert!(validate_rel_path("../x").is_err());
        assert!(validate_rel_path("/etc/passwd").is_err());
    }

    #[tokio::test]
    async fn large_file_marked_incomplete() {
        let src = tempfile::tempdir().unwrap();
        let big = vec![b'x'; 1024];
        std::fs::write(src.path().join("big.bin"), &big).unwrap();
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let limits = ManifestLimits {
            max_file_bytes: 100,
            store_blobs: true,
            ..Default::default()
        };
        let manifest = capture_workspace_manifest(src.path(), Some(store.as_ref()), limits)
            .await
            .unwrap();
        let e = manifest
            .entries
            .iter()
            .find(|e| e.path == "big.bin")
            .unwrap();
        assert!(!e.complete);
        assert!(e.skip_reason.as_ref().unwrap().contains("max_file_bytes"));
    }
}
