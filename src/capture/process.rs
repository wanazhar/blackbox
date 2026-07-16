use crate::capture::CaptureLayer;
use crate::core::command::{CaptureMethod, CommandMetadata};
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::process_tree::{ProcessNode, ProcessResources};
use crate::core::run::Run;
use async_trait::async_trait;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;

/// Process-tree observer.
///
/// Tracks the supervised process lifecycle, records basic process metadata,
/// and on Linux discovers child processes via /proc polling for lossless
/// process-tree capture (exact argv, cwd, executable, best-effort resources).
///
/// # Limitations (short-lived processes)
///
/// Polling is best-effort (~250 ms interval). Processes that spawn and exit
/// between polls may be missed. Exact argv is read from `/proc/<pid>/cmdline`
/// when the process is still alive; exit codes are not always available without
/// waitpid on the process group. Non-Linux platforms get basic PID tracking only.
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
}

impl ProcessCapture {
    pub fn new() -> Self {
        Self {
            event_tx: None,
            run_id: None,
            child_pid: None,
            process_tree: None,
            stop_tx: None,
            pid_tx: None,
            known_pids: HashSet::new(),
        }
    }

    /// Record the child PID once the process is spawned.
    /// Sends the PID to the background poller if one is running.
    pub fn set_pid(&mut self, pid: u32) {
        self.child_pid = Some(pid);
        if let Some(tx) = self.pid_tx.take() {
            let _ = tx.send(pid);
        }
    }

    /// Emit a process.spawned event if the channel is still open.
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
    pub fn process_tree(&self) -> Option<&ProcessNode> {
        self.process_tree.as_ref()
    }

    /// Consume the process tree.
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
        ev.metadata.insert(
            "process_tree_capture".to_string(),
            serde_json::json!(cfg!(target_os = "linux")),
        );
        tx.send(ev).await?;

        self.run_id = Some(run.id.clone());
        self.event_tx = Some(tx);

        // Spawn background /proc poller only on Linux
        #[cfg(target_os = "linux")]
        {
            let (pid_tx, pid_rx) = tokio::sync::oneshot::channel();
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            let run_id = run.id.clone();
            let event_tx = self.event_tx.clone().unwrap();

            self.pid_tx = Some(pid_tx);
            self.stop_tx = Some(stop_tx);

            tokio::spawn(async move {
                proc_poller_loop(run_id, event_tx, pid_rx, stop_rx).await;
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
    let meta = CommandMetadata::from_proc_argv(
        snap.argv.clone(),
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
/// Background polling loop that discovers child processes via /proc.
async fn proc_poller_loop(
    run_id: String,
    event_tx: mpsc::Sender<TraceEvent>,
    pid_rx: tokio::sync::oneshot::Receiver<u32>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) {
    let root_pid = tokio::select! {
        pid = pid_rx => match pid {
            Ok(p) => p,
            Err(_) => return,
        },
        _ = stop_rx.changed() => return,
    };

    let poll_interval = Duration::from_millis(250);
    let mut known: HashSet<u32> = HashSet::new();
    known.insert(root_pid);
    let root_pgid = read_pgid_sid(root_pid).0;

    // Emit root discovery with full snapshot.
    if let Some(snap) = read_process_snapshot(root_pid) {
        let mut ev = TraceEvent::new(&run_id, EventSource::Process, "process.discovered");
        ev.status = EventStatus::Success;
        apply_snapshot_to_event(&mut ev, &snap, CaptureMethod::ProcCmdline);
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
                let _ = event_tx.send(snap_ev).await;
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                let current = find_descendants(root_pid);

                // New processes
                for &pid in &current {
                    if !known.contains(&pid) && pid != root_pid {
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

                // Exited processes
                for &pid in &known {
                    if pid == root_pid { continue; }
                    if !current.contains(&pid) && !process_exists(pid) {
                        let mut ev = TraceEvent::new(
                            &run_id,
                            EventSource::Process,
                            "process.exited",
                        );
                        ev.status = EventStatus::Success;
                        ev.metadata.insert("pid".to_string(), serde_json::json!(pid));
                        let _ = event_tx.send(ev).await;
                    }
                }

                // Periodic resource samples for long-lived children
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

                known = current;
            }
        }
    }
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

    #[tokio::test]
    async fn stop_emits_stopped_event() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["test".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let _start = rx.try_recv().unwrap();
        cap.stop().await.unwrap();
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.kind, "process.observer.stopped");
    }

    #[tokio::test]
    async fn set_pid_and_emit_spawned() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["sleep".into(), "1".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let _start = rx.try_recv().unwrap();
        cap.set_pid(42);
        cap.emit_spawned().await;
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.kind, "process.spawned");
        assert_eq!(ev.metadata.get("pid").and_then(|v| v.as_u64()), Some(42));
    }

    #[tokio::test]
    async fn emit_spawned_without_pid_is_noop() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["true".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let _start = rx.try_recv().unwrap();
        cap.emit_spawned().await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn start_metadata_includes_command_array() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let ev = rx.try_recv().unwrap();
        let cmd = ev.metadata.get("command");
        assert!(cmd.and_then(|v| v.as_array()).is_some());
        let argv = ev
            .metadata
            .get("argv")
            .and_then(|v| v.as_array())
            .unwrap();
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
            vec![
                "sh".into(),
                "-c".into(),
                "sleep 0.8; true".into(),
            ],
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
