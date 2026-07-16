//! Sealed project backup / restore (offline vault).
//!
//! Packs sticky state, config, and optionally the SQLite DB (+ blobs) into a
//! passphrase- or store-key-sealed archive. Prefer passphrase so the archive
//! can be stored away from the machine without also shipping `store.key`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::crypto::{self, BlobCrypto};

const BACKUP_FORMAT: &str = "blackbox.store.backup/v1";

#[derive(Debug, Clone, Default)]
pub struct BackupOptions {
    pub include_db: bool,
    pub include_blobs: bool,
    /// Max total blob bytes to embed (default 64 MiB).
    pub max_blob_bytes: u64,
}

impl BackupOptions {
    pub fn default_safe() -> Self {
        Self {
            include_db: true,
            include_blobs: false,
            max_blob_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BackupManifest {
    format: String,
    created_at: String,
    project_hint: Option<String>,
    files: BTreeMap<String, BackupFile>,
    notes: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BackupFile {
    encoding: String,
    size: u64,
    sha256: String,
    data_b64: String,
}

/// Build a sealed backup JSON string.
pub fn create_sealed_backup(
    store_root: &Path,
    db_path: &Path,
    blob_dir: &Path,
    opts: &BackupOptions,
    passphrase: Option<&str>,
    store_crypto: Option<&BlobCrypto>,
) -> anyhow::Result<String> {
    let mut files = BTreeMap::new();
    let mut notes = Vec::new();

    // Sticky / config (always)
    for name in [
        "state.json",
        "config.toml",
        "MEMORY.json",
        "MEMORY.md",
        "RESUME.json",
        "RESUME.md",
        "AGENT.md",
    ] {
        let p = store_root.join(name);
        if p.is_file() {
            add_file(&mut files, name, &p)?;
        }
    }

    if opts.include_db && db_path.is_file() {
        // Best-effort WAL checkpoint if possible is caller's job.
        add_file(&mut files, "blackbox.db", db_path)?;
        // WAL/SHM if present (consistent restore)
        let wal = PathBuf::from(format!("{}-wal", db_path.display()));
        let shm = PathBuf::from(format!("{}-shm", db_path.display()));
        if wal.is_file() {
            add_file(&mut files, "blackbox.db-wal", &wal)?;
            notes.push("included WAL sidecar".into());
        }
        if shm.is_file() {
            add_file(&mut files, "blackbox.db-shm", &shm)?;
        }
    } else if !opts.include_db {
        notes.push("db omitted (use --include-db)".into());
    }

    if opts.include_blobs && blob_dir.is_dir() {
        let mut total = 0u64;
        let mut n = 0usize;
        let mut truncated = false;
        for entry in std::fs::read_dir(blob_dir)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if !meta.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.len() != 64 || !name.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let len = meta.len();
            if total.saturating_add(len) > opts.max_blob_bytes {
                truncated = true;
                break;
            }
            let rel = format!("blobs/{name}");
            add_file(&mut files, &rel, &entry.path())?;
            total += len;
            n += 1;
        }
        notes.push(format!("blobs included: {n} files ({total} bytes)"));
        if truncated {
            notes.push(format!(
                "blob embedding truncated at max_blob_bytes={}",
                opts.max_blob_bytes
            ));
        }
    } else {
        notes.push("blobs omitted (use --include-blobs for offline-complete vault)".into());
    }

    // Never embed store.key into backups by default (would defeat passphrase vault).
    notes.push("store.key is never included — restore needs passphrase or local key".into());

    let manifest = BackupManifest {
        format: BACKUP_FORMAT.into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        project_hint: store_root
            .parent()
            .map(|p| p.display().to_string()),
        files,
        notes,
    };
    let plain = serde_json::to_string(&manifest)?;
    crypto::seal_export_pack(&plain, passphrase, store_crypto)
}

/// Restore a sealed backup into `store_root` (writes files under root / blobs / db).
pub fn restore_sealed_backup(
    sealed: &str,
    store_root: &Path,
    db_path: &Path,
    blob_dir: &Path,
    passphrase: Option<&str>,
    store_crypto: Option<&BlobCrypto>,
) -> anyhow::Result<RestoreReport> {
    let plain = crypto::open_export_pack(sealed, passphrase, store_crypto)?;
    let man: BackupManifest =
        serde_json::from_str(&plain).context("backup plaintext is not a valid manifest")?;
    if man.format != BACKUP_FORMAT {
        anyhow::bail!("unsupported backup format: {}", man.format);
    }

    std::fs::create_dir_all(store_root)?;
    crate::privacy::restrict_dir(store_root);
    std::fs::create_dir_all(blob_dir)?;
    crate::privacy::restrict_dir(blob_dir);
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
        crate::privacy::restrict_dir(parent);
    }

    let mut report = RestoreReport::default();
    for (name, file) in &man.files {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&file.data_b64)
            .with_context(|| format!("decode {name}"))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let got = hex::encode(hasher.finalize());
        if got != file.sha256 {
            anyhow::bail!("sha256 mismatch for {name}: expected {} got {got}", file.sha256);
        }
        let dest = if name == "blackbox.db" {
            db_path.to_path_buf()
        } else if name == "blackbox.db-wal" {
            PathBuf::from(format!("{}-wal", db_path.display()))
        } else if name == "blackbox.db-shm" {
            PathBuf::from(format!("{}-shm", db_path.display()))
        } else if let Some(rest) = name.strip_prefix("blobs/") {
            blob_dir.join(rest)
        } else {
            store_root.join(name)
        };
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, &bytes)?;
        crate::privacy::restrict_file(&dest);
        report.files_written += 1;
        report.bytes_written += bytes.len() as u64;
    }
    report.notes = man.notes;
    Ok(report)
}

#[derive(Debug, Default, Clone)]
pub struct RestoreReport {
    pub files_written: usize,
    pub bytes_written: u64,
    pub notes: Vec<String>,
}

fn add_file(
    files: &mut BTreeMap<String, BackupFile>,
    name: &str,
    path: &Path,
) -> anyhow::Result<()> {
    // Read possibly sealed sticky files as raw bytes (already sealed on disk is fine).
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let sha = hex::encode(hasher.finalize());
    files.insert(
        name.to_string(),
        BackupFile {
            encoding: "base64".into(),
            size: data.len() as u64,
            sha256: sha,
            data_b64: base64::engine::general_purpose::STANDARD.encode(&data),
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_restore_roundtrip_sticky() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(".blackbox");
        let blobs = root.join("blobs");
        let db = root.join("blackbox.db");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::write(root.join("state.json"), br#"{"schema":"blackbox.state/v2"}"#).unwrap();
        std::fs::write(root.join("config.toml"), b"enabled = true\n").unwrap();
        std::fs::write(&db, b"sqlite-fake").unwrap();

        let opts = BackupOptions {
            include_db: true,
            include_blobs: false,
            ..BackupOptions::default_safe()
        };
        let sealed =
            create_sealed_backup(&root, &db, &blobs, &opts, Some("test-pass-phrase-ok"), None)
                .unwrap();
        assert!(crypto::is_sealed_export_pack(&sealed));

        let out = dir.path().join("restore");
        let out_root = out.join(".blackbox");
        let out_db = out_root.join("blackbox.db");
        let out_blobs = out_root.join("blobs");
        let rep = restore_sealed_backup(
            &sealed,
            &out_root,
            &out_db,
            &out_blobs,
            Some("test-pass-phrase-ok"),
            None,
        )
        .unwrap();
        assert!(rep.files_written >= 3);
        assert_eq!(
            std::fs::read_to_string(out_root.join("config.toml")).unwrap(),
            "enabled = true\n"
        );
        assert_eq!(std::fs::read(&out_db).unwrap(), b"sqlite-fake");
    }
}
