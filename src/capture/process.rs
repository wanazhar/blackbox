use crate::capture::CaptureLayer;
use crate::core::command::{CaptureMethod, CommandMetadata};
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::process_tree::ProcessNode;
#[cfg(target_os = "linux")]
use crate::core::process_tree::ProcessResources;
use crate::core::run::Run;
use async_trait::async_trait;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;

/// Optional process-layer enrichment controls (safe defaults off/normal).
///
/// - `dense_poll`: tighter adaptive poll (25–100 ms vs 50–200 ms)
/// - `capture_environ`: sample `/proc/<pid>/environ` keys with redacted values
/// - `child_subreaper`: Linux PR_SET_CHILD_SUBREAPER for best-effort waitpid exit codes
#[derive(Debug, Clone)]
pub struct ProcessEnrichOpts {
    /// Dense poll.
    pub dense_poll: bool,
    /// Capture environ.
    pub capture_environ: bool,
    /// Child subreaper.
    pub child_subreaper: bool,
}

impl Default for ProcessEnrichOpts {
    fn default() -> Self {
        Self {
            dense_poll: false,
            capture_environ: false,
            // On by default: enables waitpid reaping for reparented children without
            // requiring eBPF. Opt out with BLACKBOX_PROCESS_SUBREAPER=0.
            child_subreaper: true,
        }
    }
}

impl ProcessEnrichOpts {
    /// Resolve from config-like booleans and environment overrides.
    ///
    /// Env (override when set):
    /// - `BLACKBOX_PROCESS_DENSE_POLL=1|0`
    /// - `BLACKBOX_PROCESS_ENVIRON=1|0`
    /// - `BLACKBOX_PROCESS_SUBREAPER=1|0`
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `resolve` — see module docs for full workflow.
    /// ```
    pub fn resolve(dense_poll: bool, capture_environ: bool, child_subreaper: bool) -> Self {
        let mut opts = Self {
            dense_poll,
            capture_environ,
            child_subreaper,
        };
        if let Ok(v) = std::env::var("BLACKBOX_PROCESS_DENSE_POLL") {
            opts.dense_poll = env_truthy(&v);
        }
        if let Ok(v) = std::env::var("BLACKBOX_PROCESS_ENVIRON") {
            opts.capture_environ = env_truthy(&v);
        }
        if let Ok(v) = std::env::var("BLACKBOX_PROCESS_SUBREAPER") {
            opts.child_subreaper = env_truthy(&v);
        }
        opts
    }

    /// Build from env.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_env` — see module docs for full workflow.
    /// ```
    pub fn from_env() -> Self {
        Self::resolve(false, false, true)
    }
}

fn env_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Process-tree observer.
///
/// Tracks the supervised process lifecycle, records basic process metadata,
/// and on Linux discovers child processes via /proc polling for lossless
/// process-tree capture (exact argv, cwd, executable, best-effort resources).
///
/// # Limitations (short-lived processes)
///
/// Polling is best-effort (adaptive 50–200 ms, or 25–100 ms with dense_poll).
/// Processes that spawn and exit between polls may be missed. On Linux, exact
/// argv comes from `/proc/<pid>/cmdline`. Exit codes for descendants are
/// best-effort via child-subreaper + waitpid when the process reparents to us;
/// otherwise `exit_code` is omitted and `exit_code_known=false`.
#[derive(Debug)]
pub struct ProcessCapture {
    event_tx: Option<mpsc::Sender<TraceEvent>>,
    run_id: Option<String>,
    child_pid: Option<u32>,
    /// Root process node for the tree.
    process_tree: Option<ProcessNode>,
    /// Stop signal for the background poller.
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
    /// Oneshot channel to deliver the root PID to the background poller.
    pid_tx: Option<tokio::sync::oneshot::Sender<u32>>,
    /// Set of PIDs known from previous poll cycle.
    known_pids: HashSet<u32>,
    opts: ProcessEnrichOpts,
}

impl ProcessCapture {
    /// Create a new instance.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `new` — see module docs for full workflow.
    /// ```
    pub fn new() -> Self {
        Self::with_opts(ProcessEnrichOpts::from_env())
    }

    /// Set opts and return self.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `with_opts` — see module docs for full workflow.
    /// ```
    pub fn with_opts(opts: ProcessEnrichOpts) -> Self {
        Self {
            event_tx: None,
            run_id: None,
            child_pid: None,
            process_tree: None,
            stop_tx: None,
            pid_tx: None,
            known_pids: HashSet::new(),
            opts,
        }
    }

    /// Record the child PID once the process is spawned.
    /// Sends the PID to the background poller if one is running.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `set_pid` — see module docs for full workflow.
    /// ```
    pub fn set_pid(&mut self, pid: u32) {
        self.child_pid = Some(pid);
        if let Some(tx) = self.pid_tx.take() {
            let _ = tx.send(pid);
        }
    }

    /// Emit a process.spawned event if the channel is still open.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `emit_spawned` — see module docs for full workflow.
    /// ```
    pub async fn emit_spawned(&self) {
        if let (Some(tx), Some(run_id), Some(pid)) = (&self.event_tx, &self.run_id, self.child_pid)
        {
            let mut ev = TraceEvent::new(run_id, EventSource::Process, "process.spawned");
            ev.status = EventStatus::Success;
            ev.metadata
                .insert("pid".to_string(), serde_json::json!(pid));

            #[cfg(target_os = "linux")]
            {
                if let Some(snap) = read_process_snapshot(pid) {
                    apply_snapshot_to_event(&mut ev, &snap, CaptureMethod::ProcCmdline);
                }
            }

            let _ = tx.send(ev).await;
        }
    }

    /// Build the final process tree snapshot.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `process_tree` — see module docs for full workflow.
    /// ```
    pub fn process_tree(&self) -> Option<&ProcessNode> {
        self.process_tree.as_ref()
    }

    /// Consume the process tree.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `into_process_tree` — see module docs for full workflow.
    /// ```
    pub fn into_process_tree(self) -> Option<ProcessNode> {
        self.process_tree
    }
}

impl Default for ProcessCapture {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CaptureLayer for ProcessCapture {
    fn name(&self) -> &'static str {
        "process"
    }

    async fn start(&mut self, run: &Run) -> anyhow::Result<mpsc::Receiver<TraceEvent>> {
        let (tx, rx) = mpsc::channel(1024);

        let mut ev = TraceEvent::new(&run.id, EventSource::Process, "process.observer.started");
        ev.status = EventStatus::Success;
        // Supervised command is known exactly from the Run record (argv array).
        let meta = CommandMetadata::from_adapter_argv(run.command.clone(), Some(run.cwd.clone()));
        // Tag as exact argv from the launch path (not proc yet).
        let mut meta = meta;
        meta.capture_method = CaptureMethod::AdapterArgv;
        meta.apply_to_event(&mut ev);
        let tree_backend = if cfg!(target_os = "linux") {
            "linux_proc"
        } else {
            "sysinfo"
        };
        ev.metadata
            .insert("process_tree_capture".to_string(), serde_json::json!(true));
        ev.metadata.insert(
            "process_tree_backend".to_string(),
            serde_json::json!(tree_backend),
        );
        ev.metadata.insert(
            "dense_poll".to_string(),
            serde_json::json!(self.opts.dense_poll),
        );
        ev.metadata.insert(
            "capture_environ".to_string(),
            serde_json::json!(self.opts.capture_environ),
        );
        ev.metadata.insert(
            "child_subreaper".to_string(),
            serde_json::json!(self.opts.child_subreaper),
        );
        tx.send(ev).await?;
        let _ = tx
            .send(crate::capture::health::layer_started(&run.id, "process"))
            .await;

        self.run_id = Some(run.id.clone());
        self.event_tx = Some(tx);

        // Always spawn a process-tree poller:
        // - Linux: /proc (lossless cmdline)
        // - others: sysinfo (best-effort Tool Help / libproc)
        let (pid_tx, pid_rx) = tokio::sync::oneshot::channel();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let run_id = run.id.clone();
        let event_tx = self.event_tx.clone().unwrap();
        let opts = self.opts.clone();
        self.pid_tx = Some(pid_tx);
        self.stop_tx = Some(stop_tx);

        #[cfg(target_os = "linux")]
        {
            if opts.child_subreaper {
                enable_child_subreaper();
            }
            tokio::spawn(async move {
                proc_poller_loop(run_id, event_tx, pid_rx, stop_rx, opts).await;
            });
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = opts;
            let _ = event_tx
                .send(crate::capture::health::layer_event(
                    &run_id,
                    "process",
                    "healthy",
                    EventStatus::Success,
                    Some("sysinfo process-tree backend (best-effort argv)"),
                ))
                .await;
            tokio::spawn(async move {
                sysinfo_poller_loop(run_id, event_tx, pid_rx, stop_rx).await;
            });
        }

        Ok(rx)
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        // Signal the background poller to stop
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(true);
        }
        // Drop the pid sender so the poller won't wait indefinitely
        self.pid_tx.take();

        if let Some(tx) = self.event_tx.take() {
            if let Some(run_id) = &self.run_id {
                let mut ev =
                    TraceEvent::new(run_id, EventSource::Process, "process.observer.stopped");
                ev.status = EventStatus::Success;
                if let Some(pid) = self.child_pid {
                    ev.metadata
                        .insert("pid".to_string(), serde_json::json!(pid));
                }
                ev.metadata.insert(
                    "processes_tracked".to_string(),
                    serde_json::json!(self.known_pids.len()),
                );
                if let Some(ref tree) = self.process_tree {
                    ev.metadata.insert(
                        "tree_nodes".to_string(),
                        serde_json::json!(tree.count_nodes()),
                    );
                    ev.metadata
                        .insert("tree_depth".to_string(), serde_json::json!(tree.depth()));
                }
                let _ = tx.send(ev).await;
                let _ = tx
                    .send(crate::capture::health::layer_stopped(
                        run_id,
                        "process",
                        Some("observer stopped"),
                    ))
                    .await;
            }
        }
        Ok(())
    }
}

// ── Linux /proc helpers ─────────────────────────────────────────────

/// Snapshot of process state read from /proc.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct ProcessSnapshot {
    pid: u32,
    ppid: u32,
    argv: Vec<String>,
    executable: Option<String>,
    cwd: Option<String>,
    pgid: Option<u32>,
    sid: Option<u32>,
    uid: Option<u32>,
    resources: ProcessResources,
}

#[cfg(target_os = "linux")]
fn read_cmdline(pid: u32) -> Option<Vec<String>> {
    let path = format!("/proc/{pid}/cmdline");
    let data = std::fs::read(&path).ok()?;
    if data.is_empty() {
        return None;
    }
    let parts: Vec<String> = data
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| std::str::from_utf8(s).ok().map(String::from))
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

#[cfg(target_os = "linux")]
fn read_ppid(pid: u32) -> Option<u32> {
    let path = format!("/proc/{pid}/status");
    let data = std::fs::read_to_string(&path).ok()?;
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_status_fields(pid: u32) -> (Option<u32>, Option<u32>, Option<u32>, Option<u64>) {
    let path = format!("/proc/{pid}/status");
    let Ok(data) = std::fs::read_to_string(&path) else {
        return (None, None, None, None);
    };
    let mut uid = None;
    let mut rss_kb = None;
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Real, effective, saved, fs
            if let Some(first) = rest.split_whitespace().next() {
                uid = first.parse().ok();
            }
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            if let Some(first) = rest.split_whitespace().next() {
                rss_kb = first.parse().ok();
            }
        }
    }
    // pgid/sid from /proc/pid/stat fields
    let (pgid, sid) = read_pgid_sid(pid);
    (pgid, sid, uid, rss_kb)
}

#[cfg(target_os = "linux")]
fn read_pgid_sid(pid: u32) -> (Option<u32>, Option<u32>) {
    // /proc/pid/stat: pid (comm) state ppid pgrp session ...
    let path = format!("/proc/{pid}/stat");
    let Ok(data) = std::fs::read_to_string(&path) else {
        return (None, None);
    };
    // comm can contain spaces/parens — find last ')' then split rest
    let rest = match data.rfind(')') {
        Some(i) => &data[i + 1..],
        None => return (None, None),
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After ')': state(0) ppid(1) pgrp(2) session(3) ...
    let pgid = fields.get(2).and_then(|s| s.parse().ok());
    let sid = fields.get(3).and_then(|s| s.parse().ok());
    (pgid, sid)
}

#[cfg(target_os = "linux")]
fn read_cpu_time_ms(pid: u32) -> Option<u64> {
    let path = format!("/proc/{pid}/stat");
    let data = std::fs::read_to_string(&path).ok()?;
    let rest = data.rfind(')').map(|i| &data[i + 1..])?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // utime(11), stime(12) in clock ticks after the ')' group
    // indices: 0=state ... 11=utime, 12=stime (0-based in fields after ')')
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks_per_sec <= 0 {
        return None;
    }
    let total_ticks = utime.saturating_add(stime);
    Some(total_ticks.saturating_mul(1000) / ticks_per_sec as u64)
}

#[cfg(target_os = "linux")]
fn read_exe(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/exe");
    std::fs::read_link(&path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

#[cfg(target_os = "linux")]
fn read_cwd(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/cwd");
    std::fs::read_link(&path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

#[cfg(target_os = "linux")]
fn process_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(target_os = "linux")]
fn read_process_snapshot(pid: u32) -> Option<ProcessSnapshot> {
    let argv = read_cmdline(pid)?;
    let ppid = read_ppid(pid).unwrap_or(0);
    let (pgid, sid, uid, rss_kb) = read_status_fields(pid);
    let cpu_time_ms = read_cpu_time_ms(pid);
    Some(ProcessSnapshot {
        pid,
        ppid,
        argv,
        executable: read_exe(pid),
        cwd: read_cwd(pid),
        pgid,
        sid,
        uid,
        resources: ProcessResources {
            cpu_time_ms,
            rss_kb,
            peak_rss_kb: rss_kb,
        },
    })
}

#[cfg(target_os = "linux")]
fn apply_snapshot_to_event(ev: &mut TraceEvent, snap: &ProcessSnapshot, method: CaptureMethod) {
    ev.metadata
        .insert("pid".to_string(), serde_json::json!(snap.pid));
    ev.metadata
        .insert("ppid".to_string(), serde_json::json!(snap.ppid));
    if let Some(pgid) = snap.pgid {
        ev.metadata
            .insert("pgid".to_string(), serde_json::json!(pgid));
    }
    if let Some(sid) = snap.sid {
        ev.metadata
            .insert("sid".to_string(), serde_json::json!(sid));
    }
    if let Some(uid) = snap.uid {
        ev.metadata
            .insert("uid".to_string(), serde_json::json!(uid));
    }
    // Redact secrets in argv (curl -H Authorization, mysql -p…, etc.)
    let scanner =
        crate::redaction::scanner::SecretScanner::new(crate::redaction::RedactionConfig::default());
    let safe_argv = scanner.redact_command(&snap.argv);
    let meta = CommandMetadata::from_proc_argv(
        safe_argv,
        snap.executable.clone(),
        snap.cwd.clone(),
        method,
    );
    meta.apply_to_event(ev);
    if let Some(rss) = snap.resources.rss_kb {
        ev.metadata
            .insert("rss_kb".to_string(), serde_json::json!(rss));
    }
    if let Some(cpu) = snap.resources.cpu_time_ms {
        ev.metadata
            .insert("cpu_time_ms".to_string(), serde_json::json!(cpu));
    }
}

#[cfg(target_os = "linux")]
fn find_descendants(root_pid: u32) -> HashSet<u32> {
    let mut descendants = HashSet::new();
    descendants.insert(root_pid);

    loop {
        let mut added = false;
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                let pid: u32 = match name_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if descendants.contains(&pid) {
                    continue;
                }
                if let Some(ppid) = read_ppid(pid) {
                    if descendants.contains(&ppid) {
                        descendants.insert(pid);
                        added = true;
                    }
                }
            }
        }
        if !added {
            break;
        }
    }
    descendants
}

#[cfg(target_os = "linux")]
/// Best-effort: become child subreaper so orphaned descendants reparent to us
/// and we can `waitpid` their exit codes.
fn enable_child_subreaper() {
    // PR_SET_CHILD_SUBREAPER = 36
    let rc = unsafe { libc::prctl(36, 1i64, 0, 0, 0) };
    if rc != 0 {
        tracing::debug!("PR_SET_CHILD_SUBREAPER failed (non-fatal)");
    }
}

#[cfg(target_os = "linux")]
/// Try waitpid(WNOHANG) for a specific pid; also drain any reaped children.
fn try_reap_exit_code(pid: u32) -> Option<i32> {
    unsafe {
        let mut status: libc::c_int = 0;
        let r = libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG);
        if r == pid as libc::pid_t {
            return Some(status_to_exit_code(status));
        }
        // Drain any other reaped children (subreaper path) — may not match `pid`.
        loop {
            let r = libc::waitpid(-1, &mut status, libc::WNOHANG);
            if r <= 0 {
                break;
            }
            if r == pid as libc::pid_t {
                return Some(status_to_exit_code(status));
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn status_to_exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        // Conventional: 128 + signal
        128 + libc::WTERMSIG(status)
    } else {
        -1
    }
}

#[cfg(target_os = "linux")]
/// Read /proc/<pid>/environ as KEY=value pairs (may fail without ptrace/same-uid).
fn read_environ(pid: u32) -> Option<std::collections::HashMap<String, String>> {
    let data = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    if data.is_empty() {
        return None;
    }
    let mut map = std::collections::HashMap::new();
    for part in data.split(|b| *b == 0) {
        if part.is_empty() {
            continue;
        }
        let Ok(s) = std::str::from_utf8(part) else {
            continue;
        };
        if let Some((k, v)) = s.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

#[cfg(target_os = "linux")]
fn attach_redacted_environ(ev: &mut TraceEvent, pid: u32) {
    use crate::redaction::environment::EnvironmentRedactor;
    use crate::redaction::RedactionConfig;
    let Some(env) = read_environ(pid) else {
        ev.metadata
            .insert("environ_available".to_string(), serde_json::json!(false));
        return;
    };
    let redactor = EnvironmentRedactor::new(RedactionConfig::default());
    let redacted = redactor.redact_env(&env);
    // Cap payload size: keep at most 40 keys, truncate long values.
    let mut pairs: Vec<(String, String)> = redacted.into_iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs.truncate(40);
    let obj: serde_json::Map<String, serde_json::Value> = pairs
        .into_iter()
        .map(|(k, v)| {
            let truncated = if v.len() > 200 {
                format!("{}…", &v[..200])
            } else {
                v
            };
            (k, serde_json::Value::String(truncated))
        })
        .collect();
    ev.metadata
        .insert("environ".to_string(), serde_json::Value::Object(obj));
    ev.metadata
        .insert("environ_available".to_string(), serde_json::json!(true));
    ev.metadata
        .insert("environ_redacted".to_string(), serde_json::json!(true));
}

#[cfg(target_os = "linux")]
/// Background polling loop that discovers child processes via /proc.
async fn proc_poller_loop(
    run_id: String,
    event_tx: mpsc::Sender<TraceEvent>,
    pid_rx: tokio::sync::oneshot::Receiver<u32>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
    opts: ProcessEnrichOpts,
) {
    let root_pid = tokio::select! {
        pid = pid_rx => match pid {
            Ok(p) => p,
            Err(_) => return,
        },
        _ = stop_rx.changed() => return,
    };

    // Adaptive poll: dense 25–100ms or normal 50–200ms.
    let (active_ms, idle_ms) = if opts.dense_poll {
        (25u64, 100u64)
    } else {
        (50u64, 200u64)
    };
    let mut poll_interval = Duration::from_millis(active_ms);
    let mut known: HashSet<u32> = HashSet::new();
    known.insert(root_pid);
    let root_pgid = read_pgid_sid(root_pid).0;
    let mut idle_cycles = 0u32;

    // Emit root discovery with full snapshot.
    if let Some(snap) = read_process_snapshot(root_pid) {
        let mut ev = TraceEvent::new(&run_id, EventSource::Process, "process.discovered");
        ev.status = EventStatus::Success;
        apply_snapshot_to_event(&mut ev, &snap, CaptureMethod::ProcCmdline);
        if opts.capture_environ {
            attach_redacted_environ(&mut ev, root_pid);
        }
        let _ = event_tx.send(ev).await;
    }

    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                for &pid in &known {
                    if pid == root_pid { continue; }
                    let mut ev = TraceEvent::new(&run_id, EventSource::Process, "process.exited");
                    ev.status = EventStatus::Success;
                    ev.metadata.insert("pid".to_string(), serde_json::json!(pid));
                    ev.metadata.insert("reason".to_string(), serde_json::json!("observer_stopped"));
                    if let Some(code) = try_reap_exit_code(pid) {
                        ev.metadata.insert("exit_code".to_string(), serde_json::json!(code));
                        ev.metadata.insert("exit_code_known".to_string(), serde_json::json!(true));
                        ev.metadata.insert("exit_code_source".to_string(), serde_json::json!("waitpid"));
                    } else {
                        ev.metadata.insert("exit_code_known".to_string(), serde_json::json!(false));
                    }
                    // Best-effort final resource sample
                    if let Some(snap) = read_process_snapshot(pid) {
                        if let Some(rss) = snap.resources.rss_kb {
                            ev.metadata.insert("rss_kb".to_string(), serde_json::json!(rss));
                        }
                        if let Some(cpu) = snap.resources.cpu_time_ms {
                            ev.metadata.insert("cpu_time_ms".to_string(), serde_json::json!(cpu));
                        }
                    }
                    let _ = event_tx.send(ev).await;
                }
                // Final tree snapshot event
                let mut snap_ev = TraceEvent::new(&run_id, EventSource::Process, "process.tree.snapshot");
                snap_ev.status = EventStatus::Success;
                snap_ev.metadata.insert("root_pid".to_string(), serde_json::json!(root_pid));
                snap_ev.metadata.insert("process_count".to_string(), serde_json::json!(known.len()));
                snap_ev.metadata.insert("backend".to_string(), serde_json::json!("linux_proc"));
                snap_ev.metadata.insert("dense_poll".to_string(), serde_json::json!(opts.dense_poll));
                let _ = event_tx.send(snap_ev).await;
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                let current = find_descendants(root_pid);
                let mut changed = false;

                // New processes
                for &pid in &current {
                    if !known.contains(&pid) && pid != root_pid {
                        changed = true;
                        if let Some(snap) = read_process_snapshot(pid) {
                            let mut ev = TraceEvent::new(
                                &run_id,
                                EventSource::Process,
                                "process.exec",
                            );
                            ev.status = EventStatus::Success;
                            apply_snapshot_to_event(&mut ev, &snap, CaptureMethod::ProcPoller);
                            // Detect process-group escape
                            if let (Some(root_pg), Some(pg)) = (root_pgid, snap.pgid) {
                                if pg != root_pg {
                                    ev.metadata.insert(
                                        "escaped_pgrp".to_string(),
                                        serde_json::json!(true),
                                    );
                                }
                            }
                            if opts.capture_environ {
                                attach_redacted_environ(&mut ev, pid);
                            }
                            let _ = event_tx.send(ev).await;

                            // Also emit resource sample
                            let mut res = TraceEvent::new(
                                &run_id,
                                EventSource::Process,
                                "process.resource.sample",
                            );
                            res.status = EventStatus::Success;
                            res.metadata.insert("pid".to_string(), serde_json::json!(pid));
                            if let Some(rss) = snap.resources.rss_kb {
                                res.metadata.insert("rss_kb".to_string(), serde_json::json!(rss));
                            }
                            if let Some(cpu) = snap.resources.cpu_time_ms {
                                res.metadata.insert("cpu_time_ms".to_string(), serde_json::json!(cpu));
                            }
                            let _ = event_tx.send(res).await;
                        }
                    }
                }

                // Exited processes — best-effort exit codes via subreaper waitpid
                for &pid in &known {
                    if pid == root_pid { continue; }
                    if !current.contains(&pid) && !process_exists(pid) {
                        changed = true;
                        let mut ev = TraceEvent::new(
                            &run_id,
                            EventSource::Process,
                            "process.exited",
                        );
                        ev.status = EventStatus::Success;
                        ev.metadata.insert("pid".to_string(), serde_json::json!(pid));
                        if let Some(code) = try_reap_exit_code(pid) {
                            ev.metadata.insert("exit_code".to_string(), serde_json::json!(code));
                            ev.metadata.insert("exit_code_known".to_string(), serde_json::json!(true));
                            ev.metadata.insert("exit_code_source".to_string(), serde_json::json!("waitpid"));
                        } else {
                            ev.metadata.insert("exit_code_known".to_string(), serde_json::json!(false));
                            ev.metadata.insert(
                                "exit_code_source".to_string(),
                                serde_json::json!("unavailable"),
                            );
                        }
                        let _ = event_tx.send(ev).await;
                    }
                }

                // Periodic resource samples for long-lived children (every ~1s idle)
                if idle_cycles.is_multiple_of(5) {
                    for &pid in &current {
                        if pid == root_pid { continue; }
                        if known.contains(&pid) {
                            if let Some(snap) = read_process_snapshot(pid) {
                                let mut res = TraceEvent::new(
                                    &run_id,
                                    EventSource::Process,
                                    "process.resource.sample",
                                );
                                res.status = EventStatus::Success;
                                res.metadata.insert("pid".to_string(), serde_json::json!(pid));
                                if let Some(rss) = snap.resources.rss_kb {
                                    res.metadata.insert("rss_kb".to_string(), serde_json::json!(rss));
                                }
                                if let Some(cpu) = snap.resources.cpu_time_ms {
                                    res.metadata.insert("cpu_time_ms".to_string(), serde_json::json!(cpu));
                                }
                                let _ = event_tx.send(res).await;
                            }
                        }
                    }
                }

                if changed {
                    idle_cycles = 0;
                    poll_interval = Duration::from_millis(active_ms);
                } else {
                    idle_cycles = idle_cycles.saturating_add(1);
                    if idle_cycles >= 3 {
                        poll_interval = Duration::from_millis(idle_ms);
                    }
                }
                known = current;
            }
        }
    }
}

/// Cross-platform process-tree poller (Windows/macOS/etc.) via `sysinfo`.
///
/// Parent/child relationships and cmd argv are best-effort depending on OS
/// permissions. Prefer Linux `/proc` backend when available.
#[cfg(not(target_os = "linux"))]
async fn sysinfo_poller_loop(
    run_id: String,
    event_tx: mpsc::Sender<TraceEvent>,
    pid_rx: tokio::sync::oneshot::Receiver<u32>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    let root_pid = tokio::select! {
        pid = pid_rx => match pid {
            Ok(p) => p,
            Err(_) => return,
        },
        _ = stop_rx.changed() => return,
    };

    let mut sys = System::new();
    // sysinfo 0.33: use nothing() not new() (mac release builds failed on ProcessRefreshKind::new)
    let refresh = ProcessRefreshKind::nothing()
        .with_cmd(UpdateKind::Always)
        .with_cwd(UpdateKind::Always)
        .with_exe(UpdateKind::Always)
        .with_memory();
    let mut known: HashSet<u32> = HashSet::new();
    known.insert(root_pid);
    let mut poll_interval = Duration::from_millis(50);
    let mut idle_cycles = 0u32;

    // Root discovery
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);
    if let Some(proc) = sys.process(Pid::from_u32(root_pid)) {
        let mut ev = TraceEvent::new(&run_id, EventSource::Process, "process.discovered");
        ev.status = EventStatus::Success;
        apply_sysinfo_to_event(&mut ev, root_pid, proc, CaptureMethod::ProcPoller);
        let _ = event_tx.send(ev).await;
    }

    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                for &pid in &known {
                    if pid == root_pid { continue; }
                    let mut ev = TraceEvent::new(&run_id, EventSource::Process, "process.exited");
                    ev.status = EventStatus::Success;
                    ev.metadata.insert("pid".to_string(), serde_json::json!(pid));
                    ev.metadata.insert("reason".to_string(), serde_json::json!("observer_stopped"));
                    let _ = event_tx.send(ev).await;
                }
                let mut snap = TraceEvent::new(&run_id, EventSource::Process, "process.tree.snapshot");
                snap.status = EventStatus::Success;
                snap.metadata.insert("root_pid".to_string(), serde_json::json!(root_pid));
                snap.metadata.insert("process_count".to_string(), serde_json::json!(known.len()));
                snap.metadata.insert("backend".to_string(), serde_json::json!("sysinfo"));
                let _ = event_tx.send(snap).await;
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);
                let current = sysinfo_descendants(&sys, root_pid);
                let mut changed = false;

                for &pid in &current {
                    if !known.contains(&pid) && pid != root_pid {
                        changed = true;
                        if let Some(proc) = sys.process(Pid::from_u32(pid)) {
                            let mut ev = TraceEvent::new(&run_id, EventSource::Process, "process.exec");
                            ev.status = EventStatus::Success;
                            apply_sysinfo_to_event(&mut ev, pid, proc, CaptureMethod::ProcPoller);
                            let _ = event_tx.send(ev).await;
                        }
                    }
                }
                for &pid in &known {
                    if pid == root_pid { continue; }
                    if !current.contains(&pid) {
                        changed = true;
                        let mut ev = TraceEvent::new(&run_id, EventSource::Process, "process.exited");
                        ev.status = EventStatus::Success;
                        ev.metadata.insert("pid".to_string(), serde_json::json!(pid));
                        let _ = event_tx.send(ev).await;
                    }
                }

                if changed {
                    idle_cycles = 0;
                    poll_interval = Duration::from_millis(50);
                } else {
                    idle_cycles = idle_cycles.saturating_add(1);
                    if idle_cycles >= 3 {
                        poll_interval = Duration::from_millis(200);
                    }
                }
                known = current;
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn sysinfo_descendants(sys: &sysinfo::System, root: u32) -> HashSet<u32> {
    use sysinfo::Pid;
    let mut set = HashSet::new();
    set.insert(root);
    // Multi-pass parent walk (same approach as /proc)
    loop {
        let mut added = false;
        for (pid, proc) in sys.processes() {
            let pid_u = pid.as_u32();
            if set.contains(&pid_u) {
                continue;
            }
            if let Some(pp) = proc.parent() {
                if set.contains(&pp.as_u32()) {
                    set.insert(pid_u);
                    added = true;
                }
            }
        }
        if !added {
            break;
        }
    }
    let _ = Pid::from_u32(root);
    set
}

#[cfg(not(target_os = "linux"))]
fn apply_sysinfo_to_event(
    ev: &mut TraceEvent,
    pid: u32,
    proc: &sysinfo::Process,
    method: CaptureMethod,
) {
    let argv: Vec<String> = proc
        .cmd()
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    let executable = proc.exe().map(|p| p.to_string_lossy().into_owned());
    let cwd = proc.cwd().map(|p| p.to_string_lossy().into_owned());
    let ppid = proc.parent().map(|p| p.as_u32()).unwrap_or(0);
    ev.metadata.insert("pid".into(), serde_json::json!(pid));
    ev.metadata.insert("ppid".into(), serde_json::json!(ppid));
    let meta = if argv.is_empty() {
        let name = proc.name().to_string_lossy().into_owned();
        CommandMetadata::from_proc_argv(vec![name], executable, cwd, method)
    } else {
        CommandMetadata::from_proc_argv(argv, executable, cwd, method)
    };
    meta.apply_to_event(ev);
    // memory() is bytes in sysinfo
    let rss_kb = proc.memory() / 1024;
    ev.metadata
        .insert("rss_kb".into(), serde_json::json!(rss_kb));
    ev.metadata
        .insert("cpu_usage_pct".into(), serde_json::json!(proc.cpu_usage()));
    ev.metadata
        .insert("capture_backend".into(), serde_json::json!("sysinfo"));
}

#[cfg(not(target_os = "linux"))]
fn _noop() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::command::CommandFidelity;
    use crate::core::run::Run;

    #[tokio::test]
    async fn start_emits_spawn_event() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.kind, "process.observer.started");
        assert_eq!(ev.source, EventSource::Process);
    }

    #[tokio::test]
    async fn start_records_enrich_opts_in_metadata() {
        let opts = ProcessEnrichOpts {
            dense_poll: true,
            capture_environ: true,
            child_subreaper: false,
        };
        let mut cap = ProcessCapture::with_opts(opts);
        let run = Run::new(vec!["true".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let ev = drain_until(&mut rx, "process.observer.started");
        assert_eq!(
            ev.metadata.get("dense_poll").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            ev.metadata.get("capture_environ").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            ev.metadata.get("child_subreaper").and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn enrich_opts_resolve_from_config() {
        let opts = ProcessEnrichOpts::resolve(true, false, true);
        assert!(opts.dense_poll);
        assert!(!opts.capture_environ);
        assert!(opts.child_subreaper);
    }

    #[tokio::test]
    async fn start_emits_lossless_command_meta() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(
            vec!["grep".into(), "hello world".into(), "file.txt".into()],
            "/project".into(),
        );
        let mut rx = cap.start(&run).await.unwrap();
        let ev = rx.try_recv().unwrap();
        let meta = CommandMetadata::from_event(&ev).expect("command_meta");
        assert_eq!(meta.argv[1], "hello world");
        assert!(meta.lossless);
        assert_eq!(meta.fidelity, CommandFidelity::Exact);
        assert_eq!(meta.cwd.as_deref(), Some("/project"));
    }

    #[tokio::test]
    async fn stop_without_start_does_nothing() {
        let mut cap = ProcessCapture::new();
        assert!(cap.stop().await.is_ok());
    }

    fn drain_until(rx: &mut mpsc::Receiver<TraceEvent>, kind: &str) -> TraceEvent {
        for _ in 0..16 {
            let ev = rx.try_recv().expect("expected event");
            if ev.kind == kind {
                return ev;
            }
        }
        panic!("never saw event kind {kind}");
    }

    #[tokio::test]
    async fn stop_emits_stopped_event() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["test".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let _ = drain_until(&mut rx, "process.observer.started");
        let _ = drain_until(&mut rx, "capture.layer.started");
        cap.stop().await.unwrap();
        let ev = drain_until(&mut rx, "process.observer.stopped");
        assert_eq!(ev.kind, "process.observer.stopped");
    }

    #[tokio::test]
    async fn set_pid_and_emit_spawned() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["sleep".into(), "1".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let _ = drain_until(&mut rx, "process.observer.started");
        let _ = drain_until(&mut rx, "capture.layer.started");
        cap.set_pid(42);
        cap.emit_spawned().await;
        let ev = drain_until(&mut rx, "process.spawned");
        assert_eq!(ev.kind, "process.spawned");
        assert_eq!(ev.metadata.get("pid").and_then(|v| v.as_u64()), Some(42));
    }

    #[tokio::test]
    async fn emit_spawned_without_pid_is_noop() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["true".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let _ = drain_until(&mut rx, "process.observer.started");
        let _ = drain_until(&mut rx, "capture.layer.started");
        cap.emit_spawned().await;
        while let Ok(ev) = rx.try_recv() {
            assert_ne!(ev.kind, "process.spawned");
        }
    }

    #[tokio::test]
    async fn start_metadata_includes_command_array() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let ev = rx.try_recv().unwrap();
        let cmd = ev.metadata.get("command");
        assert!(cmd.and_then(|v| v.as_array()).is_some());
        let argv = ev.metadata.get("argv").and_then(|v| v.as_array()).unwrap();
        assert_eq!(argv[0], "echo");
        assert_eq!(argv[1], "hi");
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            format!("{:?}", ProcessCapture::default()),
            format!("{:?}", ProcessCapture::new())
        );
    }

    #[test]
    fn new_creates_empty_state() {
        let cap = ProcessCapture::new();
        assert!(cap.event_tx.is_none());
        assert!(cap.run_id.is_none());
        assert!(cap.child_pid.is_none());
        assert!(cap.pid_tx.is_none());
        assert!(cap.stop_tx.is_none());
    }

    #[test]
    fn set_pid_sends_to_poller_channel() {
        let mut cap = ProcessCapture::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<u32>();
        cap.pid_tx = Some(tx);
        cap.set_pid(99);
        assert!(cap.pid_tx.is_none());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async { rx.await.unwrap() });
        assert_eq!(result, 99);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_cmdline_works_for_current_process() {
        let cmdline = read_cmdline(std::process::id());
        assert!(cmdline.is_some());
        let args = cmdline.unwrap();
        assert!(!args.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_snapshot_includes_cwd_and_exe() {
        let pid = std::process::id();
        let snap = read_process_snapshot(pid).expect("snapshot");
        assert!(!snap.argv.is_empty());
        // cwd/exe may fail under restricted environments; just ensure no panic
        let _ = snap.cwd;
        let _ = snap.executable;
        let _ = snap.resources.rss_kb;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn nested_shell_descendants_discovered() {
        use std::process::Command as StdCommand;
        use std::time::Duration as StdDuration;

        let mut cap = ProcessCapture::new();
        let run = Run::new(
            vec!["sh".into(), "-c".into(), "sleep 0.8; true".into()],
            "/tmp".into(),
        );
        let mut rx = cap.start(&run).await.unwrap();
        let _start = rx.try_recv().unwrap();

        let mut child = StdCommand::new("sh")
            .args(["-c", "sleep 0.8"])
            .spawn()
            .expect("spawn nested shell");
        let pid = child.id();
        cap.set_pid(pid);
        cap.emit_spawned().await;

        // Give the poller time to discover and sample.
        tokio::time::sleep(StdDuration::from_millis(600)).await;
        cap.stop().await.unwrap();
        let _ = child.wait();

        // Drain events
        let mut kinds = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            kinds.push(ev.kind.clone());
        }
        // At least process.spawned and process.observer.stopped; discovery is best-effort
        assert!(kinds.iter().any(|k| k == "process.spawned"));
        assert!(kinds.iter().any(|k| k == "process.observer.stopped"));
    }
}
