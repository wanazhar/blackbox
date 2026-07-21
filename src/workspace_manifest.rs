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
use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;
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

/// How a symlink target relates to the capture root.
///
/// Symlinks are never followed during capture (`followed` is always false).
/// Outside-root targets are recorded as references only — their content is
/// never read, hashed, or stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SymlinkTargetScope {
    /// Target resolves under the capture root (still not followed).
    InsideRoot,
    /// Target points outside the capture root (external reference).
    OutsideRoot,
    /// Absolute path target (treated as external; never restored as absolute).
    Absolute,
    /// Contains `..` traversal components that leave the root or are unsafe.
    Traversal,
    /// `read_link` failed or target is empty/unusable.
    Broken,
}

/// Transformation applied to file content before hashing/storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentTransformation {
    SecretRedaction,
}

/// Completeness class for restore results (1.6 fidelity semantics).
///
/// A secret-redacted file is never `byte_exact` even when every sanitized
/// blob restores successfully.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestoreCompleteness {
    /// Every restored byte matches the original capture-time content.
    ByteExact,
    /// All expected content present, but at least one entry was transformed
    /// (e.g. secret redaction) at capture or scrub time.
    SanitizedComplete,
    /// Some content missing, skipped, or errored.
    Partial,
    /// Only metadata/structure restored; no file content available.
    MetadataOnly,
    /// Nothing useful could be restored.
    Unavailable,
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
    /// Scope of symlink target relative to capture root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_scope: Option<SymlinkTargetScope>,
    /// Whether capture followed the symlink (always false; never follow by default).
    #[serde(default)]
    pub followed: bool,
    /// tracked | untracked | unknown
    #[serde(default)]
    pub git_state: String,
    /// Whether content was fully captured (false if skipped for size/limit).
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// Transformation applied to content before hashing (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transformation: Option<ContentTransformation>,
    /// True only when stored bytes equal original file bytes (no redaction/transform).
    #[serde(default = "default_true")]
    pub byte_exact: bool,
}

fn default_true() -> bool {
    true
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
    /// Entries restored with transformed (non-original) content.
    #[serde(default)]
    pub transformed: usize,
    /// Entries excluded at capture (oversized, unreadable, etc.).
    #[serde(default)]
    pub excluded: usize,
    pub errors: Vec<String>,
    pub limitations: Vec<String>,
    /// True when every expected entry restored without error (does not imply byte-exact).
    pub complete: bool,
    /// Fidelity class — sanitized restores are never `byte_exact`.
    #[serde(default = "default_partial")]
    pub completeness: RestoreCompleteness,
    /// True when at least one restored file was secret-redacted or otherwise transformed.
    #[serde(default)]
    pub content_transformed: bool,
    /// True when all restored file content is original-byte faithful.
    #[serde(default)]
    pub byte_exact: bool,
}

fn default_partial() -> RestoreCompleteness {
    RestoreCompleteness::Partial
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
    IGNORE_DIR_NAMES.contains(&name) || name == "blackbox.db" || name.starts_with("blackbox.db-")
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
    let scanner = SecretScanner::new(RedactionConfig::default());
    // Checkpoint source files can contain split credential literals (for
    // example adjacent shell strings) that are too short for the general
    // scanner's low-false-positive thresholds but still expose useful token
    // prefixes at rest.
    let credential_fragment = regex::Regex::new(
        r"\b(?:sk-|ghp_|gho_|ghu_|ghs_|ghr_|xox[baprs]-|npm_|xai-)[A-Za-z0-9_-]{8,}",
    )?;

    // Iterative DFS: (dir, depth). Never push symlink targets onto the stack.
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.clone(), 0)];
    // Absolute paths of directories we have enqueued (loop protection if a dir
    // is reached via a different hard-link path after canonicalize root).
    let mut visited_dirs: std::collections::HashSet<PathBuf> =
        std::collections::HashSet::from([root.clone()]);

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

            // Prefer DirEntry::file_type / symlink_metadata so we never follow
            // a symlink before deciding how to record it (1.6 A safety).
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => match std::fs::symlink_metadata(&path) {
                    Ok(m) => m.file_type(),
                    Err(e) => {
                        limitations.push(format!("stat {rel}: {e}"));
                        continue;
                    }
                },
            };

            // Re-check with lstat to reduce TOCTOU (type change mid-walk).
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    limitations.push(format!("lstat {rel}: {e}"));
                    continue;
                }
            };
            if meta.file_type().is_symlink() != file_type.is_symlink()
                || meta.file_type().is_dir() != file_type.is_dir()
                || meta.file_type().is_file() != file_type.is_file()
            {
                limitations.push(format!(
                    "skipped {rel}: entry type changed during capture (TOCTOU)"
                ));
                continue;
            }

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
                let target_scope = classify_symlink_target(&root, &path, target.as_deref());
                // Never follow: do not hash/read target content, do not recurse.
                entries.push(ManifestEntry {
                    path: rel,
                    entry_type: ManifestEntryType::Symlink,
                    content_hash: None,
                    size: None,
                    mode,
                    symlink_target: target,
                    target_scope: Some(target_scope),
                    followed: false,
                    git_state: "unknown".into(),
                    complete: true,
                    skip_reason: None,
                    transformation: None,
                    byte_exact: true,
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
                    target_scope: None,
                    followed: false,
                    git_state: "unknown".into(),
                    complete: true,
                    skip_reason: None,
                    transformation: None,
                    byte_exact: true,
                });
                // Only recurse into real directories; never into symlink targets.
                if visited_dirs.insert(path.clone()) {
                    stack.push((path, depth + 1));
                }
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
                    target_scope: None,
                    followed: false,
                    git_state: "unknown".into(),
                    complete: false,
                    skip_reason: Some(format!(
                        "file exceeds max_file_bytes {}",
                        limits.max_file_bytes
                    )),
                    transformation: None,
                    byte_exact: false,
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
                    target_scope: None,
                    followed: false,
                    git_state: "unknown".into(),
                    complete: false,
                    skip_reason: Some("total byte budget exhausted".into()),
                    transformation: None,
                    byte_exact: false,
                });
                continue;
            }

            // Open without following: refuse if type flipped to symlink.
            let data = match read_regular_file_no_follow(&path) {
                Ok(d) => d,
                Err(e) => {
                    entries.push(ManifestEntry {
                        path: rel,
                        entry_type: ManifestEntryType::File,
                        content_hash: None,
                        size: Some(size),
                        mode,
                        symlink_target: None,
                        target_scope: None,
                        followed: false,
                        git_state: "unknown".into(),
                        complete: false,
                        skip_reason: Some(format!("read failed: {e}")),
                        transformation: None,
                        byte_exact: false,
                    });
                    continue;
                }
            };
            // Preserve arbitrary binary files byte-for-byte, but apply the
            // default redact-before-write policy to textual checkpoint data.
            let (safe_data, transformation) = match std::str::from_utf8(&data) {
                Ok(text) => {
                    let redacted = scanner.redact(text);
                    let after_frag = credential_fragment
                        .replace_all(&redacted, "[REDACTED]")
                        .into_owned();
                    if after_frag.as_bytes() != data.as_slice() {
                        (
                            after_frag.into_bytes(),
                            Some(ContentTransformation::SecretRedaction),
                        )
                    } else {
                        (data, None)
                    }
                }
                Err(_) => (data, None),
            };
            let byte_exact = transformation.is_none();
            bytes_hashed = bytes_hashed.saturating_add(safe_data.len() as u64);
            let hash = content_key(&safe_data);
            if limits.store_blobs {
                if let Some(store) = store {
                    if let Err(e) = store.store_blob(&safe_data).await {
                        limitations.push(format!("store blob {rel}: {e}"));
                    }
                }
            }
            entries.push(ManifestEntry {
                path: rel,
                entry_type: ManifestEntryType::File,
                content_hash: Some(hash),
                size: Some(safe_data.len() as u64),
                mode,
                symlink_target: None,
                target_scope: None,
                followed: false,
                git_state: "unknown".into(),
                complete: true,
                skip_reason: None,
                transformation,
                byte_exact,
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
///
/// Completeness distinguishes original-byte fidelity from sanitized-state
/// fidelity. Absolute, traversal, and outside-root symlink targets are never
/// recreated.
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
    let mut transformed = 0usize;
    let mut excluded = 0usize;
    let mut errors = Vec::new();
    let mut limitations = manifest.limitations.clone();
    let mut any_content_restored = false;
    let mut all_restored_byte_exact = true;
    let mut any_transformed = false;

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
                let scope = entry
                    .target_scope
                    .clone()
                    .unwrap_or_else(|| classify_symlink_target_str(target));
                // Never restore absolute, traversal, or outside-root links.
                if matches!(
                    scope,
                    SymlinkTargetScope::Absolute
                        | SymlinkTargetScope::Traversal
                        | SymlinkTargetScope::OutsideRoot
                        | SymlinkTargetScope::Broken
                ) || Path::new(target).is_absolute()
                    || path_has_parent_component(target)
                {
                    skipped += 1;
                    limitations.push(format!(
                        "{}: symlink target rejected ({scope:?})",
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
                    excluded += 1;
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
                        any_content_restored = true;
                        if entry.transformation.is_some() || !entry.byte_exact {
                            transformed += 1;
                            any_transformed = true;
                            all_restored_byte_exact = false;
                            if let Some(ref t) = entry.transformation {
                                limitations.push(format!(
                                    "{}: restored transformed content ({t:?})",
                                    entry.path
                                ));
                            }
                        }
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

    let structural_complete =
        missing == 0 && errors.is_empty() && skipped == 0 && manifest.capture_complete;
    let completeness = classify_restore_completeness(
        expected,
        restored,
        missing,
        skipped,
        excluded,
        structural_complete,
        any_content_restored,
        any_transformed,
        all_restored_byte_exact,
    );
    // `complete` means every expected entry restored without error — not
    // byte-exact fidelity. Sanitized-complete restores still report complete=true
    // when all sanitized blobs are present.
    let complete = structural_complete;

    Ok(RestoreReport {
        expected,
        restored,
        missing,
        skipped,
        transformed,
        excluded,
        errors,
        limitations,
        complete,
        completeness,
        content_transformed: any_transformed,
        byte_exact: complete && all_restored_byte_exact && !any_transformed && expected > 0,
    })
}

fn classify_restore_completeness(
    expected: usize,
    restored: usize,
    missing: usize,
    skipped: usize,
    excluded: usize,
    structural_complete: bool,
    any_content_restored: bool,
    any_transformed: bool,
    all_restored_byte_exact: bool,
) -> RestoreCompleteness {
    if expected == 0 {
        return if structural_complete {
            RestoreCompleteness::ByteExact
        } else {
            RestoreCompleteness::MetadataOnly
        };
    }
    if restored == 0 {
        return if excluded == expected || !any_content_restored {
            if expected > 0 && missing == 0 && skipped == expected {
                RestoreCompleteness::MetadataOnly
            } else {
                RestoreCompleteness::Unavailable
            }
        } else {
            RestoreCompleteness::Unavailable
        };
    }
    if missing > 0 || skipped > 0 || !structural_complete {
        return RestoreCompleteness::Partial;
    }
    if any_transformed || !all_restored_byte_exact {
        return RestoreCompleteness::SanitizedComplete;
    }
    RestoreCompleteness::ByteExact
}

/// Classify a symlink target relative to `root` without following the link.
pub fn classify_symlink_target(
    root: &Path,
    link_path: &Path,
    target: Option<&str>,
) -> SymlinkTargetScope {
    let Some(target) = target.filter(|t| !t.is_empty()) else {
        return SymlinkTargetScope::Broken;
    };
    classify_symlink_target_against_root(root, link_path, target)
}

fn classify_symlink_target_str(target: &str) -> SymlinkTargetScope {
    if target.is_empty() {
        return SymlinkTargetScope::Broken;
    }
    if Path::new(target).is_absolute() {
        return SymlinkTargetScope::Absolute;
    }
    if path_has_parent_component(target) {
        return SymlinkTargetScope::Traversal;
    }
    SymlinkTargetScope::InsideRoot
}

fn classify_symlink_target_against_root(
    root: &Path,
    link_path: &Path,
    target: &str,
) -> SymlinkTargetScope {
    let target_path = Path::new(target);
    if target_path.is_absolute() {
        // Absolute targets are never treated as captured content.
        if target_path.starts_with(root) {
            // Absolute but under root — still flagged Absolute for restore policy.
            return SymlinkTargetScope::Absolute;
        }
        return SymlinkTargetScope::OutsideRoot;
    }

    let parent = link_path.parent().unwrap_or(link_path);
    let joined = parent.join(target_path);
    // Lexical normalization without touching the filesystem (no follow).
    let normalized = normalize_path(&joined);
    if path_has_parent_component(target) {
        // If after normalization it still escapes root → outside/traversal.
        if !normalized.starts_with(root) {
            return SymlinkTargetScope::OutsideRoot;
        }
        // Traversal components present but lands inside root — still mark
        // Traversal so restore rejects `..` targets by policy.
        return SymlinkTargetScope::Traversal;
    }

    if normalized.starts_with(root) {
        SymlinkTargetScope::InsideRoot
    } else {
        SymlinkTargetScope::OutsideRoot
    }
}

fn path_has_parent_component(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

/// Lexically normalize `.` and `..` without resolving symlinks or requiring existence.
fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            Component::Normal(c) => out.push(c),
        }
    }
    out
}

/// Read a path only when it is a regular file (never follow a symlink).
fn read_regular_file_no_follow(path: &Path) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("lstat {}", path.display()))?;
    if meta.file_type().is_symlink() {
        anyhow::bail!("refusing to follow symlink");
    }
    if !meta.is_file() {
        anyhow::bail!("not a regular file");
    }
    // std::fs::read follows symlinks; re-check type immediately before read.
    // If the path flipped to a symlink between lstat and open, read would
    // follow — detect that by comparing size from lstat when possible and by
    // re-lstat after. On Unix we open with O_NOFOLLOW when available.
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("open(O_NOFOLLOW) {}", path.display()))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        return Ok(buf);
    }
    #[cfg(not(unix))]
    {
        let data = std::fs::read(path)?;
        // Best-effort post-check.
        let meta2 = std::fs::symlink_metadata(path)?;
        if meta2.file_type().is_symlink() {
            anyhow::bail!("path became symlink during read");
        }
        Ok(data)
    }
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
        let manifest =
            capture_workspace_manifest(src.path(), Some(store.as_ref()), ManifestLimits::default())
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
        assert_eq!(std::fs::read(dest.path().join("a.txt")).unwrap(), b"hello");
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
