//! Lossless process-tree and process-invocation schema.
//!
//! Captures exact argv, parent-child relationships, lifecycle, and
//! best-effort resource stats for every process observed during a run.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::command::{CaptureMethod, CommandMetadata};
use crate::core::event::{EventSource, TraceEvent};

/// Best-effort resource sample for a process.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ProcessResources {
    /// Cumulative user+system CPU time in milliseconds, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_time_ms: Option<u64>,
    /// Resident set size in kilobytes (Linux VmRSS), when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rss_kb: Option<u64>,
    /// Peak RSS in kilobytes when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_rss_kb: Option<u64>,
}

/// A single process invocation with lossless argv and lifecycle metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInvocation {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Process group ID, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pgid: Option<u32>,
    /// Session ID, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<u32>,
    /// Full command-line arguments (lossless, unjoined). Prefer `command_meta.argv`.
    pub command: Vec<String>,
    /// Canonical lossless command metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_meta: Option<CommandMetadata>,
    /// Executable path from `/proc/<pid>/exe` when readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// Working directory from `/proc/<pid>/cwd` when readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// UID when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Whether the process left the original process group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escaped_pgrp: Option<bool>,
    /// Process start time (from /proc/stat or spawn time).
    pub start_time: Option<DateTime<Utc>>,
    /// Exit code, if the process has exited.
    pub exit_code: Option<i32>,
    /// When the process exited.
    pub exit_time: Option<DateTime<Utc>>,
    /// Best-effort resource sample.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ProcessResources>,
}

/// A node in the process tree, containing children recursively.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    /// The process invocation details.
    pub invocation: ProcessInvocation,
    /// Child processes spawned by this process.
    pub children: Vec<ProcessNode>,
}

impl ProcessNode {
    /// Create a new root node without children.
    pub fn new(pid: u32, ppid: u32, command: Vec<String>) -> Self {
        let command_meta = if command.is_empty() {
            None
        } else {
            Some(CommandMetadata::from_proc_argv(
                command.clone(),
                command.first().cloned(),
                None,
                CaptureMethod::ProcCmdline,
            ))
        };
        Self {
            invocation: ProcessInvocation {
                pid,
                ppid,
                pgid: None,
                sid: None,
                command,
                command_meta,
                executable: None,
                cwd: None,
                uid: None,
                escaped_pgrp: None,
                start_time: Some(Utc::now()),
                exit_code: None,
                exit_time: None,
                resources: None,
            },
            children: Vec::new(),
        }
    }

    /// Create a node with full metadata.
    pub fn with_meta(
        pid: u32,
        ppid: u32,
        command: Vec<String>,
        executable: Option<String>,
        cwd: Option<String>,
        method: CaptureMethod,
    ) -> Self {
        let command_meta = if command.is_empty() {
            None
        } else {
            Some(CommandMetadata::from_proc_argv(
                command.clone(),
                executable.clone(),
                cwd.clone(),
                method,
            ))
        };
        Self {
            invocation: ProcessInvocation {
                pid,
                ppid,
                pgid: None,
                sid: None,
                command,
                command_meta,
                executable,
                cwd,
                uid: None,
                escaped_pgrp: None,
                start_time: Some(Utc::now()),
                exit_code: None,
                exit_time: None,
                resources: None,
            },
            children: Vec::new(),
        }
    }

    /// Recursively count all nodes in the tree.
    pub fn count_nodes(&self) -> usize {
        1 + self.children.iter().map(|c| c.count_nodes()).sum::<usize>()
    }

    /// Maximum depth of the tree (root = 1).
    pub fn depth(&self) -> usize {
        1 + self
            .children
            .iter()
            .map(|c| c.depth())
            .max()
            .unwrap_or(0)
    }

    /// Find a node by PID (depth-first).
    pub fn find_mut(&mut self, pid: u32) -> Option<&mut ProcessNode> {
        if self.invocation.pid == pid {
            return Some(self);
        }
        for child in &mut self.children {
            if let Some(found) = child.find_mut(pid) {
                return Some(found);
            }
        }
        None
    }

    /// Collect all PIDs in the tree.
    pub fn all_pids(&self) -> Vec<u32> {
        let mut pids = vec![self.invocation.pid];
        for child in &self.children {
            pids.extend(child.all_pids());
        }
        pids
    }

    /// Render a simple ASCII process tree for CLI display.
    pub fn format_tree(&self) -> String {
        let mut lines = Vec::new();
        self.format_tree_inner("", true, true, &mut lines);
        lines.join("\n")
    }

    /// Format a forest of process trees (multiple roots).
    pub fn format_forest(roots: &[ProcessNode]) -> String {
        if roots.is_empty() {
            return String::new();
        }
        if roots.len() == 1 {
            return roots[0].format_tree();
        }
        roots
            .iter()
            .map(|r| r.format_tree())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Rebuild process tree(s) from recorded process events.
///
/// Accepts `process.discovered`, `process.exec`, `process.spawned`, and
/// `process.descendant.spawned` (plus legacy kinds) that carry `pid`/`ppid`/`argv`.
/// Exit codes from `process.exited` (and root from `run.completed`) are applied when present.
pub fn rebuild_from_events(events: &[TraceEvent]) -> Vec<ProcessNode> {
    #[derive(Clone)]
    struct Info {
        ppid: u32,
        command: Vec<String>,
        executable: Option<String>,
        cwd: Option<String>,
        exit_code: Option<i32>,
        exit_time: Option<DateTime<Utc>>,
    }

    let mut by_pid: HashMap<u32, Info> = HashMap::new();
    let mut root_exit: Option<i32> = None;
    let mut root_pid_hint: Option<u32> = None;

    for ev in events {
        // Root exit code from run.completed
        if ev.kind == "run.completed" {
            if let Some(code) = ev.metadata.get("exit_code").and_then(|v| v.as_i64()) {
                root_exit = Some(code as i32);
            }
        }
        if ev.kind == "process.spawned" || ev.kind == "process.discovered" {
            if let Some(p) = ev.metadata.get("pid").and_then(|v| v.as_u64()) {
                root_pid_hint.get_or_insert(p as u32);
            }
        }

        let is_process = ev.source == EventSource::Process || ev.kind.starts_with("process.");
        if !is_process {
            continue;
        }

        let pid = match ev.metadata.get("pid").and_then(|v| v.as_u64()) {
            Some(p) => p as u32,
            None => continue,
        };

        // Apply exit codes from process.exited without requiring full command meta.
        if ev.kind.contains("exit") {
            if let Some(code) = ev.metadata.get("exit_code").and_then(|v| v.as_i64()) {
                by_pid
                    .entry(pid)
                    .and_modify(|info| {
                        info.exit_code = Some(code as i32);
                        info.exit_time = Some(ev.started_at);
                    })
                    .or_insert(Info {
                        ppid: 0,
                        command: Vec::new(),
                        executable: None,
                        cwd: None,
                        exit_code: Some(code as i32),
                        exit_time: Some(ev.started_at),
                    });
            }
            continue;
        }

        // Prefer spawn/exec/discover; skip pure resources/observers for structure.
        let useful = matches!(
            ev.kind.as_str(),
            "process.discovered"
                | "process.exec"
                | "process.spawned"
                | "process.descendant.spawned"
                | "process.command"
        ) || (ev.kind.starts_with("process.")
            && !ev.kind.contains("observer")
            && !ev.kind.contains("resource")
            && !ev.kind.contains("snapshot"));
        if !useful {
            continue;
        }

        let ppid = ev
            .metadata
            .get("ppid")
            .and_then(|v| v.as_u64())
            .map(|p| p as u32)
            .unwrap_or(0);

        let command = if let Some(arr) = ev.metadata.get("argv").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else if let Some(arr) = ev.metadata.get("command").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else if let Some(s) = ev.metadata.get("command").and_then(|v| v.as_str()) {
            // Prefer nested command_meta if present.
            if let Some(meta) = ev.metadata.get("command_meta") {
                if let Some(argv) = meta.get("argv").and_then(|v| v.as_array()) {
                    argv.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                } else {
                    vec![s.to_string()]
                }
            } else {
                vec![s.to_string()]
            }
        } else if let Some(meta) = ev.metadata.get("command_meta") {
            meta.get("argv")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let executable = ev
            .metadata
            .get("executable")
            .and_then(|v| v.as_str())
            .map(String::from);
        let cwd = ev
            .metadata
            .get("cwd")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Later events refine argv if we only had an empty discovery first.
        by_pid
            .entry(pid)
            .and_modify(|info| {
                if info.command.is_empty() && !command.is_empty() {
                    info.command = command.clone();
                }
                if info.executable.is_none() {
                    info.executable = executable.clone();
                }
                if info.cwd.is_none() {
                    info.cwd = cwd.clone();
                }
                // Prefer non-zero ppid if we learn it.
                if info.ppid == 0 && ppid != 0 {
                    info.ppid = ppid;
                }
            })
            .or_insert(Info {
                ppid,
                command,
                executable,
                cwd,
                exit_code: None,
                exit_time: None,
            });
    }

    // Apply root run.completed exit to supervised root when known.
    if let (Some(code), Some(root)) = (root_exit, root_pid_hint) {
        by_pid.entry(root).and_modify(|info| {
            if info.exit_code.is_none() {
                info.exit_code = Some(code);
            }
        });
    }

    if by_pid.is_empty() {
        return Vec::new();
    }

    let pids: HashSet<u32> = by_pid.keys().copied().collect();

    // Children map: ppid -> child pids (only if parent is in set).
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut roots: Vec<u32> = Vec::new();
    for (&pid, info) in &by_pid {
        if info.ppid != 0 && pids.contains(&info.ppid) && info.ppid != pid {
            children.entry(info.ppid).or_default().push(pid);
        } else {
            roots.push(pid);
        }
    }
    roots.sort_unstable();
    for kids in children.values_mut() {
        kids.sort_unstable();
    }

    fn build_node(
        pid: u32,
        by_pid: &HashMap<u32, Info>,
        children: &HashMap<u32, Vec<u32>>,
        visiting: &mut HashSet<u32>,
    ) -> ProcessNode {
        if !visiting.insert(pid) {
            // Cycle guard
            return ProcessNode::new(pid, 0, vec!["[cycle]".into()]);
        }
        let info = by_pid.get(&pid);
        let (ppid, command, executable, cwd, exit_code, exit_time) = match info {
            Some(i) => (
                i.ppid,
                i.command.clone(),
                i.executable.clone(),
                i.cwd.clone(),
                i.exit_code,
                i.exit_time,
            ),
            None => (0, vec![format!("[{pid}]")], None, None, None, None),
        };
        let mut node = ProcessNode::with_meta(
            pid,
            ppid,
            command,
            executable,
            cwd,
            CaptureMethod::ProcPoller,
        );
        node.invocation.exit_code = exit_code;
        node.invocation.exit_time = exit_time;
        if let Some(kids) = children.get(&pid) {
            for &child_pid in kids {
                node.children
                    .push(build_node(child_pid, by_pid, children, visiting));
            }
        }
        visiting.remove(&pid);
        node
    }

    let mut visiting = HashSet::new();
    roots
        .into_iter()
        .map(|pid| build_node(pid, &by_pid, &children, &mut visiting))
        .collect()
}

impl ProcessNode {

    fn format_tree_inner(&self, prefix: &str, is_root: bool, is_last: bool, lines: &mut Vec<String>) {
        let connector = if is_root {
            ""
        } else if is_last {
            "└── "
        } else {
            "├── "
        };
        let cmd = if self.invocation.command.is_empty() {
            format!("[{}]", self.invocation.pid)
        } else {
            self.invocation
                .command
                .iter()
                .map(|a| {
                    if a.contains(' ') || a.contains('"') || a.is_empty() {
                        format!("\"{}\"", a.replace('"', "\\\""))
                    } else {
                        a.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        };
        let exit = self
            .invocation
            .exit_code
            .map(|c| format!(" exit={c}"))
            .unwrap_or_default();
        lines.push(format!(
            "{prefix}{connector}{cmd} (pid={}{exit})",
            self.invocation.pid
        ));
        let child_prefix = if is_root {
            String::new()
        } else if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}│   ")
        };
        let n = self.children.len();
        for (i, child) in self.children.iter().enumerate() {
            child.format_tree_inner(&child_prefix, false, i + 1 == n, lines);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_root_without_children() {
        let node = ProcessNode::new(100, 99, vec!["bash".into(), "-c".into(), "echo hi".into()]);
        assert_eq!(node.invocation.pid, 100);
        assert_eq!(node.invocation.ppid, 99);
        assert_eq!(node.invocation.command, vec!["bash", "-c", "echo hi"]);
        assert!(node.invocation.start_time.is_some());
        assert!(node.invocation.exit_code.is_none());
        assert!(node.children.is_empty());
        let meta = node.invocation.command_meta.as_ref().unwrap();
        assert!(meta.lossless);
        assert_eq!(meta.argv[2], "echo hi");
    }

    #[test]
    fn count_nodes_reflects_tree_size() {
        let mut root = ProcessNode::new(1, 0, vec!["sh".into()]);
        let child = ProcessNode::new(2, 1, vec!["echo".into(), "hello".into()]);
        root.children.push(child);
        assert_eq!(root.count_nodes(), 2);
    }

    #[test]
    fn find_mut_returns_matching_pid() {
        let mut root = ProcessNode::new(1, 0, vec!["sh".into()]);
        let child = ProcessNode::new(2, 1, vec!["echo".into()]);
        root.children.push(child);
        assert!(root.find_mut(2).is_some());
        assert!(root.find_mut(99).is_none());
    }

    #[test]
    fn all_pids_returns_all() {
        let mut root = ProcessNode::new(1, 0, vec!["sh".into()]);
        root.children
            .push(ProcessNode::new(2, 1, vec!["echo".into()]));
        root.children
            .push(ProcessNode::new(3, 1, vec!["ls".into()]));
        let mut pids = root.all_pids();
        pids.sort();
        assert_eq!(pids, vec![1, 2, 3]);
    }

    #[test]
    fn serde_round_trip() {
        let node = ProcessNode::new(42, 41, vec!["make".into(), "test".into()]);
        let json = serde_json::to_string(&node).unwrap();
        let de: ProcessNode = serde_json::from_str(&json).unwrap();
        assert_eq!(de.invocation.pid, 42);
        assert_eq!(de.invocation.command, vec!["make", "test"]);
        assert!(de.invocation.command_meta.is_some());
    }

    #[test]
    fn with_meta_sets_cwd_and_exe() {
        let node = ProcessNode::with_meta(
            10,
            1,
            vec!["rg".into(), "Session".into(), "src/".into()],
            Some("/usr/bin/rg".into()),
            Some("/project".into()),
            CaptureMethod::ProcPoller,
        );
        assert_eq!(node.invocation.cwd.as_deref(), Some("/project"));
        assert_eq!(node.invocation.executable.as_deref(), Some("/usr/bin/rg"));
        let meta = node.invocation.command_meta.as_ref().unwrap();
        assert_eq!(meta.cwd.as_deref(), Some("/project"));
        assert_eq!(meta.argv[1], "Session");
    }

    #[test]
    fn format_tree_shows_quoted_args() {
        let mut root = ProcessNode::new(1, 0, vec!["bash".into()]);
        root.children.push(ProcessNode::new(
            2,
            1,
            vec!["grep".into(), "hello world".into(), "f.txt".into()],
        ));
        let text = root.format_tree();
        assert!(text.contains("bash"));
        assert!(text.contains("hello world") || text.contains("\"hello world\""));
        assert!(text.contains("pid=2"));
    }

    #[test]
    fn depth_counts_levels() {
        let mut root = ProcessNode::new(1, 0, vec!["a".into()]);
        let mut mid = ProcessNode::new(2, 1, vec!["b".into()]);
        mid.children
            .push(ProcessNode::new(3, 2, vec!["c".into()]));
        root.children.push(mid);
        assert_eq!(root.depth(), 3);
    }

    fn proc_ev(kind: &str, pid: u32, ppid: u32, argv: &[&str]) -> TraceEvent {
        let mut ev = TraceEvent::new("run", EventSource::Process, kind);
        ev.metadata.insert("pid".into(), serde_json::json!(pid));
        ev.metadata.insert("ppid".into(), serde_json::json!(ppid));
        ev.metadata
            .insert("argv".into(), serde_json::json!(argv.to_vec()));
        ev
    }

    #[test]
    fn rebuild_from_events_builds_tree() {
        let events = vec![
            proc_ev("process.discovered", 100, 0, &["bash"]),
            proc_ev("process.exec", 101, 100, &["rg", "Session", "src/"]),
            proc_ev("process.exec", 102, 100, &["git", "diff"]),
            proc_ev("process.exec", 103, 101, &["node", "test-runner.js"]),
        ];
        let roots = rebuild_from_events(&events);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].invocation.pid, 100);
        assert_eq!(roots[0].count_nodes(), 4);
        let text = ProcessNode::format_forest(&roots);
        assert!(text.contains("bash"));
        assert!(text.contains("rg") || text.contains("Session"));
        assert!(text.contains("node") || text.contains("test-runner"));
    }

    #[test]
    fn rebuild_empty_without_process_events() {
        let mut ev = TraceEvent::new("run", EventSource::Terminal, "terminal.output");
        ev.metadata
            .insert("preview".into(), serde_json::json!("hi"));
        assert!(rebuild_from_events(&[ev]).is_empty());
    }

    #[test]
    fn rebuild_applies_exit_codes_and_run_completed() {
        let mut events = vec![
            proc_ev("process.spawned", 100, 0, &["bash"]),
            proc_ev("process.exec", 101, 100, &["false"]),
        ];
        let mut exited = TraceEvent::new("run", EventSource::Process, "process.exited");
        exited.metadata.insert("pid".into(), serde_json::json!(101));
        exited
            .metadata
            .insert("exit_code".into(), serde_json::json!(1));
        events.push(exited);
        let mut completed = TraceEvent::new("run", EventSource::System, "run.completed");
        completed
            .metadata
            .insert("exit_code".into(), serde_json::json!(0));
        events.push(completed);

        let roots = rebuild_from_events(&events);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].invocation.exit_code, Some(0));
        assert_eq!(roots[0].children[0].invocation.exit_code, Some(1));
        let text = roots[0].format_tree();
        assert!(text.contains("exit=1"));
        assert!(text.contains("exit=0"));
    }
}
