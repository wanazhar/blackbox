//! Project paths and runtime configuration for blackbox.

use std::path::{Path, PathBuf};

/// Resolved filesystem layout for a blackbox store.
#[derive(Debug, Clone)]
pub struct BlackboxPaths {
    /// Root directory (usually `<project>/.blackbox`).
    pub root: PathBuf,
    /// SQLite database path.
    pub db_path: PathBuf,
    /// Content-addressed blob directory.
    pub blob_dir: PathBuf,
}

impl BlackboxPaths {
    /// Resolve store paths.
    ///
    /// Priority:
    /// 1. Explicit `db_override` (CLI `--store`)
    /// 2. `BLACKBOX_DB` environment variable
    /// 3. Legacy `./blackbox.db` if it already exists (migration)
    /// 4. `<project>/.blackbox/blackbox.db` (default)
    ///
    /// `project` defaults to the current working directory.
    pub fn resolve(project: Option<&Path>, db_override: Option<&Path>) -> anyhow::Result<Self> {
        if let Some(db) = db_override {
            return Ok(Self::from_db_path(db.to_path_buf()));
        }

        if let Ok(env_db) = std::env::var("BLACKBOX_DB") {
            if !env_db.is_empty() {
                return Ok(Self::from_db_path(PathBuf::from(env_db)));
            }
        }

        let project = match project {
            Some(p) => p.to_path_buf(),
            None => std::env::current_dir()?,
        };

        // Legacy: keep using cwd blackbox.db if present so existing traces survive.
        let legacy = project.join("blackbox.db");
        if legacy.exists() {
            return Ok(Self::from_db_path(legacy));
        }

        let root = project.join(".blackbox");
        let db_path = root.join("blackbox.db");
        let blob_dir = root.join("blobs");
        Ok(Self {
            root,
            db_path,
            blob_dir,
        })
    }

    /// Derive root + blob dir from a database path.
    ///
    /// If the DB already lives under a directory named `.blackbox`, blobs sit
    /// next to it (`…/.blackbox/blobs`). Otherwise blobs live in
    /// `<db_parent>/.blackbox/blobs` (legacy layout for `./blackbox.db`).
    pub fn from_db_path(db_path: PathBuf) -> Self {
        let parent = db_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        let parent_is_blackbox = parent
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n == ".blackbox")
            .unwrap_or(false);

        if parent_is_blackbox {
            Self {
                root: parent.clone(),
                db_path,
                blob_dir: parent.join("blobs"),
            }
        } else {
            let root = parent.join(".blackbox");
            Self {
                root: root.clone(),
                db_path,
                blob_dir: root.join("blobs"),
            }
        }
    }

    /// Ensure root and blob directories exist.
    pub fn ensure_dirs(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(&self.blob_dir)?;
        Ok(())
    }
}

/// Capture-time policy flags.
#[derive(Debug, Clone)]
pub struct CapturePolicy {
    /// When false (default), secrets are redacted before any write.
    /// When true, raw terminal bytes may be stored as blobs (dangerous).
    pub insecure_raw: bool,
    /// Redaction enabled (normally true).
    pub redact: bool,
}

impl Default for CapturePolicy {
    fn default() -> Self {
        Self {
            insecure_raw: false,
            redact: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_db_path_legacy_cwd() {
        let p = BlackboxPaths::from_db_path(PathBuf::from("/tmp/proj/blackbox.db"));
        assert_eq!(p.blob_dir, PathBuf::from("/tmp/proj/.blackbox/blobs"));
    }

    #[test]
    fn from_db_path_nested_blackbox() {
        let p = BlackboxPaths::from_db_path(PathBuf::from("/tmp/proj/.blackbox/blackbox.db"));
        assert_eq!(p.root, PathBuf::from("/tmp/proj/.blackbox"));
        assert_eq!(p.blob_dir, PathBuf::from("/tmp/proj/.blackbox/blobs"));
    }
}
