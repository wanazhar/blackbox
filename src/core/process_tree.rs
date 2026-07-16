//! Lossless process-tree and process-invocation schema.
//!
//! Captures exact argv, parent-child relationships, lifecycle, and
//! best-effort resource stats for every process observed during a run.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::command::{CaptureMethod, CommandMetadata};

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
        lines.push(format!(
            "{prefix}{connector}{cmd} (pid={})",
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
}
