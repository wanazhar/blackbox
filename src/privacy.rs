//! Local privacy hardening: restrictive file modes for store artifacts.
//!
//! Threat model: other local UIDs reading `.blackbox/` (shared machine, loose umask).
//! Same-UID malware and unlocked-disk theft still see everything — encryption is P2.

use std::path::Path;

/// Best-effort: make a directory owner-only (0700) on Unix.
pub fn restrict_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            if perms.mode() & 0o077 != 0 {
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Best-effort: make a file owner-only (0600) on Unix.
pub fn restrict_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            if perms.mode() & 0o177 != 0 {
                // Allow 0600 only (clear group/other + sticky execute bits for files)
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Create directory tree then restrict each existing component under `root`.
pub fn ensure_private_dirs(root: &Path, extras: &[&Path]) -> std::io::Result<()> {
    std::fs::create_dir_all(root)?;
    restrict_dir(root);
    for p in extras {
        if p.exists() || std::fs::create_dir_all(p).is_ok() {
            restrict_dir(p);
        }
    }
    Ok(())
}

/// True when path is readable by group or other (Unix).
pub fn is_world_or_group_readable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o044 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// True when bind address is loopback (IPv4/IPv6 localhost).
pub fn is_loopback_addr(addr: &std::net::SocketAddr) -> bool {
    addr.ip().is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        let a: std::net::SocketAddr = "127.0.0.1:7788".parse().unwrap();
        assert!(is_loopback_addr(&a));
        let b: std::net::SocketAddr = "0.0.0.0:7788".parse().unwrap();
        assert!(!is_loopback_addr(&b));
        let c: std::net::SocketAddr = "[::1]:7788".parse().unwrap();
        assert!(is_loopback_addr(&c));
    }

    #[cfg(unix)]
    #[test]
    fn restrict_file_and_dir_modes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("bb");
        let blobs = root.join("blobs");
        ensure_private_dirs(&root, &[&blobs]).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let f = root.join("secret.json");
        std::fs::write(&f, b"{}").unwrap();
        // Make world-readable then restrict
        let mut p = std::fs::metadata(&f).unwrap().permissions();
        p.set_mode(0o644);
        std::fs::set_permissions(&f, p).unwrap();
        assert!(is_world_or_group_readable(&f));
        restrict_file(&f);
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!is_world_or_group_readable(&f));
    }
}
