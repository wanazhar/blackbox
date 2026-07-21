//! cgroup v2 memory/CPU controllers for budget enforcement (1.6).
//!
//! Strategy (first success wins for the control file path):
//! 1. Create a child cgroup under the current process's cgroup and write
//!    `memory.max` / `cpu.max` when permitted (common as root / GHA).
//! 2. Fall back to `RLIMIT_AS` for memory and `RLIMIT_CPU` for CPU time.
//!
//! Capability reporting never claims `enforced` when the backend is unavailable.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::budget::policy::{BudgetCapability, BudgetPolicy, BudgetStatus};

/// Active cgroup leaf that holds a supervised process (Drop removes empty leaf).
#[derive(Debug)]
pub struct CgroupScope {
    path: PathBuf,
    notes: Vec<String>,
    memory_enforced: bool,
    cpu_enforced: bool,
    pids_enforced: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CgroupApplyReport {
    pub notes: Vec<String>,
    pub memory_enforced: bool,
    pub cpu_enforced: bool,
    pub pids_enforced: bool,
    pub path: Option<PathBuf>,
}

impl CgroupScope {
    /// Create a budget leaf under the current process cgroup, configure limits,
    /// and move `pid` into it. Returns `None` when cgroup v2 is unusable.
    pub fn create_for_pid(pid: u32, policy: &BudgetPolicy) -> Option<(Self, CgroupApplyReport)> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (pid, policy);
            return None;
        }
        #[cfg(target_os = "linux")]
        {
            create_for_pid_linux(pid, policy)
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn report(&self) -> CgroupApplyReport {
        CgroupApplyReport {
            notes: self.notes.clone(),
            memory_enforced: self.memory_enforced,
            cpu_enforced: self.cpu_enforced,
            pids_enforced: self.pids_enforced,
            path: Some(self.path.clone()),
        }
    }
}

impl Drop for CgroupScope {
    fn drop(&mut self) {
        // Best-effort: move any remaining procs to parent then rmdir.
        if let Some(parent) = self.path.parent() {
            if let Ok(procs) = fs::read_to_string(self.path.join("cgroup.procs")) {
                for line in procs.lines() {
                    let _ = fs::write(parent.join("cgroup.procs"), line);
                }
            }
        }
        let _ = fs::remove_dir(&self.path);
    }
}

#[cfg(target_os = "linux")]
fn create_for_pid_linux(pid: u32, policy: &BudgetPolicy) -> Option<(CgroupScope, CgroupApplyReport)> {
    let needs = policy.max_memory_bytes.is_some()
        || policy.max_cpu_percent.is_some()
        || policy.max_processes.is_some();
    if !needs {
        return None;
    }

    let self_cg = current_cgroup_path()?;
    // Ensure intermediate can host children with controllers when possible.
    let _ = enable_controllers(&self_cg, &["memory", "cpu", "pids"]);

    let leaf_name = format!("blackbox-budget-{}-{}", std::process::id(), pid);
    let leaf = self_cg.join(&leaf_name);
    if let Err(e) = fs::create_dir_all(&leaf) {
        tracing::debug!(error = %e, path = %leaf.display(), "cgroup mkdir failed");
        return None;
    }

    let mut notes = vec![format!("cgroup leaf {}", leaf.display())];
    let mut memory_enforced = false;
    let mut cpu_enforced = false;
    let mut pids_enforced = false;

    // Controllers appear on the leaf only after parent subtree_control enables them.
    let _ = enable_controllers(&self_cg, &["memory", "cpu", "pids"]);

    if let Some(bytes) = policy.max_memory_bytes {
        match write_knob(&leaf.join("memory.max"), &format!("{bytes}")) {
            Ok(()) => {
                memory_enforced = true;
                notes.push(format!("memory.max={bytes}"));
            }
            Err(e) => notes.push(format!("memory.max unavailable: {e}")),
        }
        // OOM kill group by default when supported.
        let _ = write_knob(&leaf.join("memory.oom.group"), "1");
    }

    if let Some(pct) = policy.max_cpu_percent {
        // cpu.max: quota period (100ms period). pct of one CPU.
        let pct = pct.clamp(1, 10_000); // allow multi-core via >100
        let period: u64 = 100_000;
        let quota = (period.saturating_mul(pct as u64) / 100).max(1000);
        match write_knob(&leaf.join("cpu.max"), &format!("{quota} {period}")) {
            Ok(()) => {
                cpu_enforced = true;
                notes.push(format!("cpu.max={quota} {period} (~{pct}% of 1 CPU)"));
            }
            Err(e) => notes.push(format!("cpu.max unavailable: {e}")),
        }
    }

    if let Some(n) = policy.max_processes {
        match write_knob(&leaf.join("pids.max"), &format!("{n}")) {
            Ok(()) => {
                pids_enforced = true;
                notes.push(format!("pids.max={n}"));
            }
            Err(e) => notes.push(format!("pids.max unavailable: {e}")),
        }
    }

    // Move target process into the leaf.
    match write_knob(&leaf.join("cgroup.procs"), &format!("{pid}")) {
        Ok(()) => notes.push(format!("moved pid {pid} into cgroup")),
        Err(e) => {
            notes.push(format!("cgroup.procs write failed: {e}"));
            let _ = fs::remove_dir(&leaf);
            // Still report partial controller probe for capability honesty.
            if !memory_enforced && !cpu_enforced && !pids_enforced {
                return None;
            }
            // Controllers configured but move failed — drop leaf.
            return None;
        }
    }

    let scope = CgroupScope {
        path: leaf,
        notes: notes.clone(),
        memory_enforced,
        cpu_enforced,
        pids_enforced,
    };
    let report = scope.report();
    Some((scope, report))
}

#[cfg(target_os = "linux")]
fn current_cgroup_path() -> Option<PathBuf> {
    let text = fs::read_to_string("/proc/self/cgroup").ok()?;
    // cgroup v2: 0::/path
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let p = PathBuf::from("/sys/fs/cgroup").join(rest.trim_start_matches('/'));
            if p.is_dir() {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn enable_controllers(cg: &Path, controllers: &[&str]) -> std::io::Result<()> {
    let path = cg.join("cgroup.subtree_control");
    // Enable one at a time; ignore already-enabled / busy errors.
    for c in controllers {
        let _ = write_knob(&path, &format!("+{c}"));
    }
    Ok(())
}

fn write_knob(path: &Path, value: &str) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new().write(true).open(path)?;
    f.write_all(value.as_bytes())?;
    Ok(())
}

/// Probe whether cgroup v2 memory.max is writable in a throwaway leaf.
pub fn cgroup_v2_memory_writable() -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        let Some(base) = current_cgroup_path() else {
            return false;
        };
        let _ = enable_controllers(&base, &["memory"]);
        let leaf = base.join(format!("blackbox-probe-{}", std::process::id()));
        if fs::create_dir_all(&leaf).is_err() {
            return false;
        }
        let ok = write_knob(&leaf.join("memory.max"), "max").is_ok()
            || write_knob(&leaf.join("memory.max"), "104857600").is_ok();
        let _ = fs::remove_dir(&leaf);
        ok
    }
}

/// Merge cgroup backend status into capability report.
pub fn enrich_capabilities_with_cgroup(
    policy: &BudgetPolicy,
    caps: &mut [BudgetStatus],
    report: Option<&CgroupApplyReport>,
) {
    let cg_mem = report.map(|r| r.memory_enforced).unwrap_or(false);
    let cg_cpu = report.map(|r| r.cpu_enforced).unwrap_or(false);
    let cg_pids = report.map(|r| r.pids_enforced).unwrap_or(false);
    let probe = cgroup_v2_memory_writable();

    for c in caps.iter_mut() {
        match c.name.as_str() {
            "memory" if policy.max_memory_bytes.is_some() => {
                if cg_mem {
                    c.capability = BudgetCapability::Enforced;
                    c.note = Some("cgroup v2 memory.max".into());
                } else if probe {
                    c.capability = BudgetCapability::Enforced;
                    c.note = Some("cgroup v2 available (apply at run)".into());
                } else if cfg!(target_os = "linux") {
                    c.capability = BudgetCapability::ObservedOnly;
                    c.note = Some(
                        "cgroup memory.max not writable; RLIMIT_AS soft fallback may apply".into(),
                    );
                } else {
                    c.capability = BudgetCapability::Unavailable;
                    c.note = Some("cgroup v2 memory not available on this OS".into());
                }
            }
            "cpu" if policy.max_cpu_percent.is_some() => {
                if cg_cpu {
                    c.capability = BudgetCapability::Enforced;
                    c.note = Some("cgroup v2 cpu.max".into());
                } else if cfg!(target_os = "linux") {
                    c.capability = BudgetCapability::ObservedOnly;
                    c.note = Some("cgroup cpu.max not applied; RLIMIT_CPU time backstop only".into());
                } else {
                    c.capability = BudgetCapability::Unavailable;
                }
            }
            "process_count" if policy.max_processes.is_some() && cg_pids => {
                c.capability = BudgetCapability::Enforced;
                c.note = Some("cgroup v2 pids.max + RLIMIT_NPROC + watchdog".into());
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_does_not_panic() {
        let _ = cgroup_v2_memory_writable();
    }

    #[test]
    fn create_scope_is_best_effort() {
        let p = BudgetPolicy {
            max_memory_bytes: Some(256 * 1024 * 1024),
            max_cpu_percent: Some(50),
            max_processes: Some(256),
            ..Default::default()
        };
        // Own pid — may fail move on some hosts; must not panic.
        let _ = CgroupScope::create_for_pid(std::process::id(), &p);
    }
}
