//! Linux hard budget enforcement via prlimit + wall-time kill (1.6).
//!
//! **Important:** resource limits are applied to the **child** PID with
//! `prlimit(2)`, never `setrlimit` on the blackbox supervisor itself.

use std::time::Duration;

use crate::budget::policy::{BudgetCapability, BudgetPolicy, BudgetStatus};

/// Apply process-level rlimits to `pid` (the supervised child).
///
/// Does **not** mutate the calling process. Uses `prlimit` on Linux.
#[cfg(target_os = "linux")]
pub fn apply_child_rlimits(pid: u32, policy: &BudgetPolicy) -> Vec<String> {
    let mut notes = Vec::new();
    if pid == 0 || pid == 1 {
        notes.push(format!("refusing prlimit on unsafe pid {pid}"));
        return notes;
    }

    // RLIMIT_CPU is CPU time, not wall clock — only set when max_cpu_percent is
    // absent as a soft backstop proportional to wall if wall is set.
    // Prefer not conflating wall with CPU: only apply RLIMIT_CPU from an
    // explicit high wall as a multi-hour safety net (secs as CPU seconds).
    if let Some(secs) = policy.max_wall_secs {
        // Cap CPU seconds at wall seconds as a last-resort runaway brake.
        if let Err(e) = set_prlimit(pid, libc::RLIMIT_CPU, secs, secs) {
            notes.push(format!("prlimit RLIMIT_CPU pid={pid}: {e}"));
        } else {
            notes.push(format!("prlimit RLIMIT_CPU={secs}s on pid={pid} (CPU-time backstop)"));
        }
    }
    if let Some(n) = policy.max_processes {
        if let Err(e) = set_prlimit(pid, libc::RLIMIT_NPROC, n, n) {
            notes.push(format!("prlimit RLIMIT_NPROC pid={pid}: {e}"));
        } else {
            notes.push(format!("prlimit RLIMIT_NPROC={n} on pid={pid}"));
        }
    }
    if let Some(bytes) = policy.max_memory_bytes {
        if let Err(e) = set_prlimit(pid, libc::RLIMIT_AS, bytes, bytes) {
            notes.push(format!("prlimit RLIMIT_AS pid={pid}: {e}"));
        } else {
            notes.push(format!(
                "prlimit RLIMIT_AS={bytes} on pid={pid} (address-space backstop)"
            ));
        }
    }
    let _ = policy.max_output_bytes;
    notes
}

#[cfg(not(target_os = "linux"))]
pub fn apply_child_rlimits(_pid: u32, _policy: &BudgetPolicy) -> Vec<String> {
    vec!["child prlimit not available on this OS".into()]
}

/// Deprecated name kept for tests — redirects to child-targeted API with pid=self
/// only for unit probing; production code must call [`apply_child_rlimits`].
#[cfg(test)]
pub fn apply_process_rlimits(policy: &BudgetPolicy) -> Vec<String> {
    apply_child_rlimits(std::process::id(), policy)
}

#[cfg(target_os = "linux")]
fn set_prlimit(
    pid: u32,
    resource: libc::__rlimit_resource_t,
    soft: u64,
    hard: u64,
) -> std::io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    // prlimit(pid, resource, new_limit, old_limit)
    let rc = unsafe { libc::prlimit(pid as libc::pid_t, resource, &lim, std::ptr::null_mut()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Wall-time watchdog: spawn a task that kills `pid` after `timeout`.
pub fn spawn_wall_watchdog(
    pid: u32,
    timeout: Duration,
) -> tokio::task::JoinHandle<Option<BudgetBreachKill>> {
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        match kill_supervised(pid) {
            Ok(()) => Some(BudgetBreachKill {
                name: "wall_time".into(),
                pid,
                detail: format!("killed after {}s wall budget", timeout.as_secs()),
            }),
            Err(e) => {
                tracing::warn!(error = %e, pid, "wall watchdog kill failed");
                None
            }
        }
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BudgetBreachKill {
    pub name: String,
    pub pid: u32,
    pub detail: String,
}

/// Public budget kill entrypoint (tool/output ceilings in the capture path).
pub fn kill_budget_pid(pid: u32) -> std::io::Result<()> {
    kill_supervised(pid)
}

/// Kill a supervised child. Prefer process-group kill when the child called
/// `setsid()` (portable-pty), then fall back to the single PID.
///
/// Refuses pid 0/1 and the caller's own PID.
fn kill_supervised(pid: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let self_pid = std::process::id();
        if pid == 0 || pid == 1 || pid == self_pid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("refusing to kill pid {pid}"),
            ));
        }
        // Child is session leader via setsid → negative pgid kills the tree.
        let rc_pg = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
        if rc_pg == 0 {
            return Ok(());
        }
        let rc = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "kill not supported",
        ))
    }
}

/// Count processes in the same process group / descendants (best-effort via /proc).
#[cfg(target_os = "linux")]
pub fn count_descendant_processes(root_pid: u32) -> u64 {
    let mut pids = std::collections::HashSet::from([root_pid]);
    for _ in 0..8 {
        let Ok(rd) = std::fs::read_dir("/proc") else {
            return pids.len() as u64;
        };
        let snapshot: Vec<u32> = pids.iter().copied().collect();
        let mut grew = false;
        for entry in rd.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let pid: u32 = match name.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if pids.contains(&pid) {
                continue;
            }
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok();
            if let Some(s) = stat {
                if let Some(ppid) = parse_ppid(&s) {
                    if snapshot.contains(&ppid) {
                        pids.insert(pid);
                        grew = true;
                    }
                }
            }
        }
        if !grew {
            break;
        }
    }
    pids.len() as u64
}

#[cfg(not(target_os = "linux"))]
pub fn count_descendant_processes(_root_pid: u32) -> u64 {
    1
}

#[cfg(target_os = "linux")]
fn parse_ppid(stat: &str) -> Option<u32> {
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 2..)?;
    let mut parts = rest.split_whitespace();
    let _state = parts.next()?;
    parts.next()?.parse().ok()
}

/// Process-count watchdog: poll descendants and kill if over limit.
pub fn spawn_process_count_watchdog(
    root_pid: u32,
    max_processes: u64,
    interval: Duration,
) -> tokio::task::JoinHandle<Option<BudgetBreachKill>> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let n = count_descendant_processes(root_pid);
            if n > max_processes {
                let _ = kill_supervised(root_pid);
                return Some(BudgetBreachKill {
                    name: "process_count".into(),
                    pid: root_pid,
                    detail: format!("processes {n} exceeded limit {max_processes}"),
                });
            }
            #[cfg(target_os = "linux")]
            {
                if !std::path::Path::new(&format!("/proc/{root_pid}")).exists() {
                    return None;
                }
            }
        }
    })
}

/// Enrich capability notes after applying Linux backends.
pub fn linux_enforcement_status(policy: &BudgetPolicy) -> Vec<BudgetStatus> {
    linux_enforcement_status_with_cgroup(policy, None)
}

/// Same as [`linux_enforcement_status`] but folds an applied cgroup report.
pub fn linux_enforcement_status_with_cgroup(
    policy: &BudgetPolicy,
    cgroup: Option<&crate::budget::cgroup::CgroupApplyReport>,
) -> Vec<BudgetStatus> {
    let mut caps = policy.capability_report();
    for c in &mut caps {
        if c.name == "process_count" && policy.max_processes.is_some() {
            #[cfg(target_os = "linux")]
            {
                c.capability = BudgetCapability::Enforced;
                c.note = Some("prlimit RLIMIT_NPROC + /proc descendant watchdog".into());
            }
            #[cfg(not(target_os = "linux"))]
            {
                c.capability = BudgetCapability::ObservedOnly;
                c.note = Some("process count enforced only on Linux".into());
            }
        }
        if c.name == "wall_time" && policy.max_wall_secs.is_some() {
            c.capability = BudgetCapability::Enforced;
            c.note = Some("wall watchdog SIGKILL on child".into());
        }
    }
    crate::budget::cgroup::enrich_capabilities_with_cgroup(policy, &mut caps, cgroup);
    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_kill_self_and_init() {
        assert!(kill_supervised(0).is_err());
        assert!(kill_supervised(1).is_err());
        assert!(kill_supervised(std::process::id()).is_err());
    }

    #[test]
    fn prlimit_on_self_for_probe_does_not_panic() {
        let p = BudgetPolicy {
            max_wall_secs: Some(3600),
            max_processes: Some(4096),
            max_memory_bytes: Some(512 * 1024 * 1024),
            ..Default::default()
        };
        let notes = apply_child_rlimits(std::process::id(), &p);
        assert!(!notes.is_empty());
    }
}
