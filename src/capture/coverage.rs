//! Capture-coverage model — honest reporting of what was captured.
//!
//! After each run, a `CaptureCoverage` summary is emitted as run metadata
//! so consumers can assess which observation surfaces were available,
//! active, and how many events each produced.

use serde::{Deserialize, Serialize};

/// Overall capture coverage for a run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaptureCoverage {
    /// Per-surface coverage reports.
    pub surfaces: Vec<CaptureSurface>,
    /// Total trace events across all surfaces.
    pub total_events: u64,
    /// Any notes about capture limitations.
    pub notes: Vec<String>,
}

/// Status of a single capture surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSurface {
    /// Surface name (pty, process, git, filesystem, environment, native_logs).
    pub name: String,
    /// Whether this surface was enabled for the run.
    pub enabled: bool,
    /// Number of events produced by this surface.
    pub events_count: u64,
    /// Human-readable note about the surface's availability or limitations.
    pub note: Option<String>,
}

impl CaptureCoverage {
    /// Merge another coverage report into this one.
    pub fn merge(&mut self, other: &CaptureCoverage) {
        for s in &other.surfaces {
            if let Some(existing) = self.surfaces.iter_mut().find(|x| x.name == s.name) {
                existing.events_count += s.events_count;
                existing.enabled = existing.enabled || s.enabled;
                if s.note.is_some() {
                    existing.note = s.note.clone();
                }
            } else {
                self.surfaces.push(s.clone());
            }
        }
        self.total_events += other.total_events;
        self.notes.extend(other.notes.clone());
    }

    /// Build a coverage report from per-surface event counts.
    pub fn from_surface_counts(
        pty_events: u64,
        process_events: u64,
        git_events: u64,
        fs_events: u64,
        env_events: u64,
        process_tree_available: bool,
    ) -> Self {
        let mut surfaces = Vec::new();

        surfaces.push(CaptureSurface {
            name: "pty".into(),
            enabled: true,
            events_count: pty_events,
            note: None,
        });

        surfaces.push(CaptureSurface {
            name: "process".into(),
            enabled: true,
            events_count: process_events,
            note: if process_tree_available {
                Some("process-tree capture active".into())
            } else {
                Some("basic PID tracking only (no /proc)".into())
            },
        });
        surfaces.push(CaptureSurface {
            name: "git".into(),
            enabled: git_events > 0,
            events_count: git_events,
            note: if git_events == 0 {
                Some("no git repository detected or no changes".into())
            } else {
                None
            },
        });

        surfaces.push(CaptureSurface {
            name: "filesystem".into(),
            enabled: fs_events > 0,
            events_count: fs_events,
            note: if fs_events == 0 {
                Some("no filesystem events captured".into())
            } else {
                None
            },
        });

        surfaces.push(CaptureSurface {
            name: "environment".into(),
            enabled: true,
            events_count: env_events,
            note: Some("captured at run start".into()),
        });

        let total_events = pty_events + process_events + git_events + fs_events + env_events;

        let mut notes = Vec::new();
        if !process_tree_available {
            notes.push("process-tree capture requires Linux /proc".into());
        }

        Self {
            surfaces,
            total_events,
            notes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let cov = CaptureCoverage::default();
        assert!(cov.surfaces.is_empty());
        assert_eq!(cov.total_events, 0);
    }

    #[test]
    fn from_surface_counts_basic() {
        let cov = CaptureCoverage::from_surface_counts(10, 5, 2, 8, 1, true);
        assert_eq!(cov.total_events, 26);
        assert_eq!(cov.surfaces.len(), 5);
        assert!(cov
            .surfaces
            .iter()
            .any(|s| s.name == "pty" && s.events_count == 10));
        assert!(cov
            .surfaces
            .iter()
            .any(|s| s.name == "process" && s.events_count == 5));
        assert!(cov
            .surfaces
            .iter()
            .any(|s| s.name == "environment" && s.events_count == 1));
    }

    #[test]
    fn process_tree_note_on_linux() {
        let cov = CaptureCoverage::from_surface_counts(0, 0, 0, 0, 0, true);
        let process = cov.surfaces.iter().find(|s| s.name == "process").unwrap();
        assert_eq!(process.note.as_deref(), Some("process-tree capture active"));
    }

    #[test]
    fn process_tree_note_non_linux() {
        let cov = CaptureCoverage::from_surface_counts(0, 0, 0, 0, 0, false);
        let process = cov.surfaces.iter().find(|s| s.name == "process").unwrap();
        assert_eq!(
            process.note.as_deref(),
            Some("basic PID tracking only (no /proc)")
        );
        assert!(cov.notes.iter().any(|n| n.contains("/proc")));
    }

    #[test]
    fn merge_combines_surface_counts() {
        let mut cov = CaptureCoverage::from_surface_counts(10, 0, 0, 0, 0, false);
        let other = CaptureCoverage::from_surface_counts(5, 3, 0, 0, 0, false);
        cov.merge(&other);
        let pty = cov.surfaces.iter().find(|s| s.name == "pty").unwrap();
        assert_eq!(pty.events_count, 15);
        let proc = cov.surfaces.iter().find(|s| s.name == "process").unwrap();
        assert_eq!(proc.events_count, 3);
        assert_eq!(cov.total_events, 18);
    }

    #[test]
    fn git_note_when_no_events() {
        let cov = CaptureCoverage::from_surface_counts(0, 0, 0, 0, 0, false);
        let git = cov.surfaces.iter().find(|s| s.name == "git").unwrap();
        assert!(!git.enabled);
        assert!(git
            .note
            .as_deref()
            .unwrap_or("")
            .contains("no git repository"));
    }
}
