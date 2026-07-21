//! Linux hard budget enforcement via rlimits + wall-time kill (1.6).

use std::time::Duration;

use crate::budget::policy::{BudgetCapability, BudgetPolicy, BudgetStatus};

/// Apply process-level rlimits in the **current** process (call after fork /
/// in a pre-exec context when available). Best-effort; never claims success
/// for unsupported resources.
///
/// On non-Linux this is a no-op returning empty notes.
#[cfg(target_os = "linux")]
pub fn apply_process_rlimits(policy: &BudgetPolicy) -> Vec<String> {
    let mut notes = Vec::new();
    // CPU seconds (soft=hard for hard kill after CPU time).
    if let Some(secs) = policy.max_wall_secs {
        // RLIMIT_CPU is CPU time not wall — still useful as a backstop.
        if let Err(e) = set_rlimit(libc::RLIMIT_CPU, secs, secs) {
            notes.push(format!("RLIMIT_CPU unavailable: {e}"));
        } else {
            notes.push(format!("RLIMIT_CPU={secs}s applied"));
        }
    }
    if let Some(n) = policy.max_processes {
        if let Err(e) = set_rlimit(libc::RLIMIT_NPROC, n, n) {
            notes.push(format!("RLIMIT_NPROC unavailable: {e}"));
        } else {
            notes.push(format!("RLIMIT_NPROC={n} applied"));
        }
    }
    // Address-space ceiling as portable memory backstop when cgroup memory.max
    // is not writable. Not exact RSS; still useful.
    if let Some(bytes) = policy.max_memory_bytes {
        if let Err(e) = set_rlimit(libc::RLIMIT_AS, bytes, bytes) {
            notes.push(format!("RLIMIT_AS unavailable: {e}"));
        } else {
            notes.push(format!("RLIMIT_AS={bytes} applied (address-space backstop)"));
        }
    }
    let _ = policy.max_output_bytes;
    notes
}

#[cfg(not(target_os = "linux"))]
pub fn apply_process_rlimits(_policy: &BudgetPolicy) -> Vec<String> {
    vec!["process rlimits not available on this OS".into()]
}

#[cfg(target_os = "linux")]
fn set_rlimit(resource: libc::__rlimit_resource_t, soft: u64, hard: u64) -> std::io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    let rc = unsafe { libc::setrlimit(resource, &lim) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Wall-time watchdog: spawn a task that kills `pid` after `timeout`.
/// Returns a join handle; abort it if the child exits first.
pub fn spawn_wall_watchdog(
    pid: u32,
    timeout: Duration,
) -> tokio::task::JoinHandle<Option<BudgetBreachKill>> {
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        match kill_process_group(pid) {
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

fn kill_process_group(pid: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        // SIGKILL the process; best-effort process group if leader.
        let rc = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        if rc == 0 {
            return Ok(());
        }
        // Try process group
        let rc2 = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
        if rc2 == 0 {
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
    // Multi-pass BFS by ppid
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
                // ppid is field 4 after comm in parens — approximate parse.
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
    // format: pid (comm) state ppid ...
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
                let _ = kill_process_group(root_pid);
                return Some(BudgetBreachKill {
                    name: "process_count".into(),
                    pid: root_pid,
                    detail: format!("processes {n} exceeded limit {max_processes}"),
                });
            }
            // If root is gone, stop.
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
                c.note = Some("RLIMIT_NPROC + /proc descendant watchdog".into());
            }
            #[cfg(not(target_os = "linux"))]
            {
                c.capability = BudgetCapability::ObservedOnly;
                c.note = Some("process count enforced only on Linux".into());
            }
        }
        if c.name == "wall_time" && policy.max_wall_secs.is_some() {
            c.capability = BudgetCapability::Enforced;
            c.note = Some("wall watchdog SIGKILL".into());
        }
    }
    crate::budget::cgroup::enrich_capabilities_with_cgroup(policy, &mut caps, cgroup);
    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlimits_do_not_panic() {
        let p = BudgetPolicy {
            max_wall_secs: Some(3600),
            max_processes: Some(4096),
            ..Default::default()
        };
        let _ = apply_process_rlimits(&p);
    }
}
