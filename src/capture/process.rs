use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::process_tree::ProcessNode;
use crate::core::run::Run;
use async_trait::async_trait;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;

/// Process-tree observer.
///
/// Tracks the supervised process lifecycle, records basic process metadata,
/// and on Linux discovers child processes via /proc polling for lossless
/// process-tree capture.
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
        ev.metadata.insert(
            "command".to_string(),
            serde_json::json!(run.command.join(" ")),
        );
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
                        "tree_depth".to_string(),
                        serde_json::json!(tree.count_nodes()),
                    );
                }
                let _ = tx.send(ev).await;
            }
        }
        Ok(())
    }
}

// ── Linux /proc poller ──────────────────────────────────────────────

#[cfg(target_os = "linux")]
/// Read the null-separated command line from /proc/[pid]/cmdline.
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
/// Read the parent PID from /proc/[pid]/status.
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
/// Check if a process with the given PID is alive.
fn process_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(target_os = "linux")]
/// Find all descendant PIDs of the given root PID by walking /proc.
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

    let poll_interval = Duration::from_millis(500);
    let mut known: HashSet<u32> = HashSet::new();
    known.insert(root_pid);

    if let Some(cmdline) = read_cmdline(root_pid) {
        let mut ev = TraceEvent::new(&run_id, EventSource::Process, "process.descendant.spawned");
        ev.status = EventStatus::Success;
        ev.metadata
            .insert("pid".to_string(), serde_json::json!(root_pid));
        ev.metadata.insert("ppid".to_string(), serde_json::json!(0));
        ev.metadata
            .insert("command".to_string(), serde_json::json!(cmdline.join(" ")));
        ev.metadata
            .insert("argv".to_string(), serde_json::json!(cmdline));
        ev.metadata.insert(
            "capture_method".to_string(),
            serde_json::json!("proc_poller"),
        );
        let _ = event_tx.send(ev).await;
    }

    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                for &pid in &known {
                    if pid == root_pid { continue; }
                    let mut ev = TraceEvent::new(&run_id, EventSource::Process, "process.descendant.exited");
                    ev.status = EventStatus::Success;
                    ev.metadata.insert("pid".to_string(), serde_json::json!(pid));
                    ev.metadata.insert("reason".to_string(), serde_json::json!("observer_stopped"));
                    let _ = event_tx.send(ev).await;
                }
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                let current = find_descendants(root_pid);
                for &pid in &current {
                    if !known.contains(&pid) && pid != root_pid {
                        if let Some(cmdline) = read_cmdline(pid) {
                            let ppid = read_ppid(pid).unwrap_or(0);
                            let mut ev = TraceEvent::new(&run_id, EventSource::Process, "process.descendant.spawned");
                            ev.status = EventStatus::Success;
                            ev.metadata.insert("pid".to_string(), serde_json::json!(pid));
                            ev.metadata.insert("ppid".to_string(), serde_json::json!(ppid));
                            ev.metadata.insert("command".to_string(), serde_json::json!(cmdline.join(" ")));
                            ev.metadata.insert("argv".to_string(), serde_json::json!(cmdline));
                            ev.metadata.insert("capture_method".to_string(), serde_json::json!("proc_poller"));
                            let _ = event_tx.send(ev).await;
                        }
                    }
                }
                for &pid in &known {
                    if pid == root_pid { continue; }
                    if !current.contains(&pid) && !process_exists(pid) {
                        let mut ev = TraceEvent::new(&run_id, EventSource::Process, "process.descendant.exited");
                        ev.status = EventStatus::Success;
                        ev.metadata.insert("pid".to_string(), serde_json::json!(pid));
                        let _ = event_tx.send(ev).await;
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
    async fn start_metadata_includes_command() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let ev = rx.try_recv().unwrap();
        let cmd = ev.metadata.get("command").and_then(|v| v.as_str());
        assert_eq!(cmd, Some("echo hi"));
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
        // The pid_tx should have been consumed
        assert!(cap.pid_tx.is_none());
        // The receiver should have the value
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
}
