//! Lossless process-tree and process-invocation schema.
//!
//! Captures exact argv, parent-child relationships, and lifecycle
//! for every process observed during a run.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single process invocation with lossless argv and lifecycle metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInvocation {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Full command-line arguments (lossless, unjoined).
    pub command: Vec<String>,
    /// Process start time (from /proc/stat or spawn time).
    pub start_time: Option<DateTime<Utc>>,
    /// Exit code, if the process has exited.
    pub exit_code: Option<i32>,
    /// When the process exited.
    pub exit_time: Option<DateTime<Utc>>,
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
        Self {
            invocation: ProcessInvocation {
                pid,
                ppid,
                command,
                start_time: Some(Utc::now()),
                exit_code: None,
                exit_time: None,
            },
            children: Vec::new(),
        }
    }

    /// Recursively count all nodes in the tree.
    pub fn count_nodes(&self) -> usize {
        1 + self.children.iter().map(|c| c.count_nodes()).sum::<usize>()
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
    }
}
