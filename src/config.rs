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

/// Check if a file is readable (has read permission).
fn is_readable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o444 != 0)
        .unwrap_or(false)
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
                let env_path = PathBuf::from(&env_db);
                if env_path.is_dir() {
                    anyhow::bail!(
                        "BLACKBOX_DB points to a directory, not a file: {}",
                        env_db
                    );
                }
                if env_path.exists() && !is_readable(&env_path) {
                    anyhow::bail!(
                        "BLACKBOX_DB is not readable: {}",
                        env_db
                    );
                }
                return Ok(Self::from_db_path(env_path));
            }
        }

        let project = match project {
            Some(p) => {
                if p.exists() {
                    std::fs::canonicalize(p)?
                } else {
                    p.to_path_buf()
                }
            }
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
    use std::fs;

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

    /// Helper: create a temp project dir with optional legacy blackbox.db.
    fn make_project(legacy: bool) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let proj = dir.path().to_path_buf();
        if legacy {
            fs::write(proj.join("blackbox.db"), b"").unwrap();
        }
        (dir, proj)
    }

    #[test]
    fn resolve_explicit_override_takes_priority() {
        let (_dir, proj) = make_project(true);
        let explicit = proj.join("custom.db");
        let paths = BlackboxPaths::resolve(Some(&proj), Some(&explicit)).unwrap();
        assert_eq!(paths.db_path, explicit);
    }

    #[test]
    fn resolve_env_db_takes_priority_over_legacy() {
        let (_dir, proj) = make_project(true);
        let env_db = proj.join("env.db");
        std::env::set_var("BLACKBOX_DB", &env_db);
        let paths = BlackboxPaths::resolve(Some(&proj), None).unwrap();
        assert_eq!(paths.db_path, env_db);
        std::env::remove_var("BLACKBOX_DB");
    }

    #[test]
    fn resolve_legacy_used_when_present() {
        let (_dir, proj) = make_project(true);
        let paths = BlackboxPaths::resolve(Some(&proj), None).unwrap();
        assert_eq!(paths.db_path, proj.join("blackbox.db"));
    }

    #[test]
    fn resolve_default_when_nothing_exists() {
        let (_dir, proj) = make_project(false);
        let paths = BlackboxPaths::resolve(Some(&proj), None).unwrap();
        assert_eq!(paths.db_path, proj.join(".blackbox").join("blackbox.db"));
        assert_eq!(paths.blob_dir, proj.join(".blackbox").join("blobs"));
    }
}
