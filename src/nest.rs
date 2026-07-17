//! Nest detection without child-visible environment variables (1.4 N1).
//!
//! Recorder mode must not inject `BLACKBOX_*` into the supervised child.
//! Ambient nest prevention therefore uses **supervisor PID markers** under the
//! runtime directory, plus a legacy env check for older blackbox parents.
//!
//! Marker layout:
//! ```text
//! $XDG_RUNTIME_DIR/blackbox/supervisors/<pid>   # preferred
//! /tmp/blackbox-supervisors-<uid>/<pid>         # fallback
//! ```
//! Each file contains the active `run_id` (informational). Nested `maybe-run`
//! walks the PPID chain; if any ancestor has a marker, it passthroughs.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Legacy env var still honored when set by an older supervisor (or tests).
pub const ENV_ACTIVE_RUN: &str = "BLACKBOX_ACTIVE_RUN";

/// Prefix for all Blackbox-owned environment keys.
pub const ENV_PREFIX: &str = "BLACKBOX_";

/// Guard that registers this process as an active supervisor for the duration
/// of a supervised run. Drop clears the marker.
#[derive(Debug)]
pub struct ActiveSupervisorGuard {
    path: PathBuf,
}

impl ActiveSupervisorGuard {
    /// Register `std::process::id()` as supervising `run_id`.
    pub fn acquire(run_id: &str) -> Self {
        let dir = supervisor_dir();
        let _ = fs::create_dir_all(&dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        let path = dir.join(std::process::id().to_string());
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
        {
            let _ = writeln!(f, "{run_id}");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
        }
        Self { path }
    }

    /// Path of the marker file (tests).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ActiveSupervisorGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Directory holding per-PID supervisor markers.
pub fn supervisor_dir() -> PathBuf {
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        if !runtime.is_empty() {
            return PathBuf::from(runtime).join("blackbox").join("supervisors");
        }
    }
    let uid = current_uid();
    std::env::temp_dir().join(format!("blackbox-supervisors-{uid}"))
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::getuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// True when nest should passthrough: legacy env **or** an ancestor PID holds
/// an active supervisor marker.
pub fn is_nested_supervisor() -> bool {
    if std::env::var_os(ENV_ACTIVE_RUN).is_some() {
        return true;
    }
    nested_under_marker()
}

/// Walk PPID chain looking for supervisor markers.
pub fn nested_under_marker() -> bool {
    #[cfg(unix)]
    {
        let dir = supervisor_dir();
        if !dir.is_dir() {
            return false;
        }
        let mut pid = parent_pid(std::process::id());
        // Bound walks so a corrupt /proc chain cannot hang.
        for _ in 0..64 {
            if pid == 0 || pid == 1 {
                break;
            }
            if dir.join(pid.to_string()).is_file() {
                return true;
            }
            let next = parent_pid(pid);
            if next == pid {
                break;
            }
            pid = next;
        }
        false
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
fn parent_pid(pid: u32) -> u32 {
    // Prefer /proc (Linux); fall back to libc getppid only for self.
    let stat = PathBuf::from(format!("/proc/{pid}/stat"));
    if let Ok(data) = fs::read_to_string(&stat) {
        // Format: pid (comm) state ppid ...
        if let Some(close) = data.rfind(')') {
            let rest = data[close + 1..].split_whitespace().collect::<Vec<_>>();
            // After ")": state, ppid
            if rest.len() >= 2 {
                if let Ok(ppid) = rest[1].parse::<u32>() {
                    return ppid;
                }
            }
        }
    }
    if pid == std::process::id() {
        return unsafe { libc::getppid() as u32 };
    }
    0
}

/// Env keys that blackbox may inject for continuity (must not appear in
/// recorder-mode children).
pub fn continuity_inject_keys() -> &'static [&'static str] {
    &[
        "BLACKBOX_RESUME_FILE",
        "BLACKBOX_RESUME_RUN_ID",
        "BLACKBOX_RESUME_HINT",
        "BLACKBOX_MEMORY_FILE",
        "BLACKBOX_MEMORY_SCHEMA",
        "BLACKBOX_CONTINUITY",
        "BLACKBOX_AUTO_RESUME",
        "BLACKBOX_ACTIVE_RUN",
    ]
}

/// Remove all `BLACKBOX_*` keys from a portable-pty `CommandBuilder` so the
/// supervised child does not inherit recorder control surface.
pub fn strip_blackbox_env(cmd: &mut portable_pty::CommandBuilder) {
    // Collect first — env_remove while iterating env can be fine, but collect
    // is clearer and avoids depending on iterator invalidation semantics.
    let keys: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| k.starts_with(ENV_PREFIX))
        .collect();
    for k in keys {
        cmd.env_remove(&k);
    }
    // Always strip known inject keys even if not present in parent env
    // (defensive against builder defaults).
    for k in continuity_inject_keys() {
        cmd.env_remove(k);
    }
}

/// Whether hard recorder neutrality (no BLACKBOX_* inject) is supported here.
pub fn neutrality_supported() -> bool {
    cfg!(unix)
}

/// Documented PTY differences always present under supervision.
pub fn documented_pty_differences() -> Vec<&'static str> {
    vec!["session_id", "process_group", "tty_allocation"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_writes_and_clears_marker() {
        let g = ActiveSupervisorGuard::acquire("run-test-marker");
        assert!(g.path().is_file(), "marker should exist while guard lives");
        let path = g.path().to_path_buf();
        drop(g);
        assert!(!path.exists(), "marker should be removed on drop");
    }

    #[test]
    fn is_nested_honors_legacy_env() {
        let prev = std::env::var_os(ENV_ACTIVE_RUN);
        std::env::set_var(ENV_ACTIVE_RUN, "legacy");
        assert!(is_nested_supervisor());
        match prev {
            Some(v) => std::env::set_var(ENV_ACTIVE_RUN, v),
            None => std::env::remove_var(ENV_ACTIVE_RUN),
        }
    }

    #[test]
    fn strip_keys_include_active_run() {
        assert!(continuity_inject_keys().contains(&"BLACKBOX_ACTIVE_RUN"));
    }

    #[test]
    fn neutrality_supported_on_unix() {
        assert_eq!(neutrality_supported(), cfg!(unix));
    }
}
