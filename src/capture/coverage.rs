//! Capture-coverage model — honest reporting of what was captured.
//!
//! After each run, a `CaptureCoverage` summary is emitted as run metadata
//! so consumers can assess which observation surfaces were available,
//! active, and how many events each produced. Coverage status distinguishes
//! **disabled**, **unavailable**, **failed**, **partial**, and **complete**.

use serde::{Deserialize, Serialize};

/// Status of a single capture surface for a run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceStatus {
    /// Surface was intentionally not enabled.
    Disabled,
    /// Surface cannot operate on this platform/environment.
    Unavailable,
    /// Surface was enabled but failed during the run.
    Failed,
    /// Surface produced some events but with known gaps.
    Partial,
    /// Surface operated normally for the run.
    Complete,
    /// Status not established.
    #[default]
    Unknown,
}

impl SurfaceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Unavailable => "unavailable",
            Self::Failed => "failed",
            Self::Partial => "partial",
            Self::Complete => "complete",
            Self::Unknown => "unknown",
        }
    }

    /// Contribution weight for quality scoring (0.0–1.0).
    pub fn quality_weight(self) -> f64 {
        match self {
            Self::Complete => 1.0,
            Self::Partial => 0.5,
            Self::Failed => 0.1,
            Self::Unavailable => 0.0,
            Self::Disabled => 0.0,
            Self::Unknown => 0.0,
        }
    }
}

/// Overall capture coverage for a run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaptureCoverage {
    /// Per-surface coverage reports.
    pub surfaces: Vec<CaptureSurface>,
    /// Total trace events across all surfaces.
    pub total_events: u64,
    /// Aggregate quality score 0–100 (documented algorithm in `quality_score`).
    #[serde(default)]
    pub quality_score: u8,
    /// Any notes about capture limitations.
    pub notes: Vec<String>,
}

/// Status of a single capture surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSurface {
    /// Surface name (pty, process, git, filesystem, environment, native_logs, network).
    pub name: String,
    /// Whether this surface was enabled for the run.
    pub enabled: bool,
    /// Honest status: disabled / unavailable / failed / partial / complete.
    #[serde(default)]
    pub status: SurfaceStatus,
    /// Number of events produced by this surface.
    pub events_count: u64,
    /// Human-readable note about the surface's availability or limitations.
    pub note: Option<String>,
}

/// Weights used by the documented quality scoring algorithm.
///
/// Score = 100 × Σ(weight_i × status_weight_i) / Σ(weight_i for non-disabled)
/// Surfaces that are disabled do not penalize the score.
const SURFACE_WEIGHTS: &[(&str, f64)] = &[
    ("pty", 0.30),
    ("process", 0.25),
    ("git", 0.15),
    ("filesystem", 0.15),
    ("environment", 0.05),
    ("native_logs", 0.10),
];

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
                // Prefer more severe status when merging.
                existing.status = worse_status(existing.status, s.status);
            } else {
                self.surfaces.push(s.clone());
            }
        }
        self.total_events += other.total_events;
        self.notes.extend(other.notes.clone());
        self.recompute_quality_score();
    }

    /// Documented scoring algorithm:
    ///
    /// For each surface with a known weight that is not `Disabled`:
    /// contribute `weight × status_quality` to the numerator and `weight` to
    /// the denominator. Disabled surfaces are omitted so opting out of a
    /// layer does not tank the score. Network is never assumed present.
    ///
    /// Returns an integer 0–100.
    pub fn compute_quality_score(surfaces: &[CaptureSurface]) -> u8 {
        let mut num = 0.0;
        let mut den = 0.0;
        for (name, weight) in SURFACE_WEIGHTS {
            let surface = surfaces.iter().find(|s| s.name == *name);
            let status = surface.map(|s| s.status).unwrap_or(SurfaceStatus::Unknown);
            if status == SurfaceStatus::Disabled {
                continue;
            }
            // If surface missing entirely, treat as unknown (no contribution to den
            // only when we have zero info — still include so absence is visible).
            if surface.is_none() {
                den += weight;
                continue;
            }
            den += weight;
            num += weight * status.quality_weight();
        }
        if den <= 0.0 {
            return 0;
        }
        ((num / den) * 100.0).round().clamp(0.0, 100.0) as u8
    }

    pub fn recompute_quality_score(&mut self) {
        self.quality_score = Self::compute_quality_score(&self.surfaces);
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
        Self::from_surface_counts_ext(
            pty_events,
            process_events,
            git_events,
            fs_events,
            env_events,
            process_tree_available,
            None,
            None,
        )
    }

    /// Extended builder with optional native-log count and process-layer error.
    #[allow(clippy::too_many_arguments)]
    pub fn from_surface_counts_ext(
        pty_events: u64,
        process_events: u64,
        git_events: u64,
        fs_events: u64,
        env_events: u64,
        process_tree_available: bool,
        native_log_events: Option<u64>,
        process_failed: Option<bool>,
    ) -> Self {
        let mut surfaces = Vec::new();

        surfaces.push(CaptureSurface {
            name: "pty".into(),
            enabled: true,
            status: if pty_events > 0 {
                SurfaceStatus::Complete
            } else {
                SurfaceStatus::Partial
            },
            events_count: pty_events,
            note: if pty_events == 0 {
                Some("no PTY output captured".into())
            } else {
                None
            },
        });

        let process_status = if process_failed == Some(true) {
            SurfaceStatus::Failed
        } else if !process_tree_available {
            if process_events > 0 {
                SurfaceStatus::Partial
            } else {
                SurfaceStatus::Unavailable
            }
        } else if process_events > 0 {
            SurfaceStatus::Complete
        } else {
            SurfaceStatus::Partial
        };

        surfaces.push(CaptureSurface {
            name: "process".into(),
            enabled: true,
            status: process_status,
            events_count: process_events,
            note: if process_failed == Some(true) {
                Some("process capture layer failed".into())
            } else if process_tree_available {
                Some("process-tree capture active".into())
            } else {
                Some("basic PID tracking only (no /proc)".into())
            },
        });

        surfaces.push(CaptureSurface {
            name: "git".into(),
            enabled: git_events > 0,
            status: if git_events > 0 {
                SurfaceStatus::Complete
            } else {
                // No events may mean clean repo — partial, not unavailable.
                SurfaceStatus::Partial
            },
            events_count: git_events,
            note: if git_events == 0 {
                Some("no git repository detected or no changes".into())
            } else {
                None
            },
        });

        surfaces.push(CaptureSurface {
            name: "filesystem".into(),
            enabled: true, // watcher is on by default
            status: if fs_events > 0 {
                SurfaceStatus::Complete
            } else {
                SurfaceStatus::Partial
            },
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
            status: if env_events > 0 {
                SurfaceStatus::Complete
            } else {
                SurfaceStatus::Partial
            },
            events_count: env_events,
            note: Some("captured at run start".into()),
        });

        // Network is never claimed present without a real layer.
        surfaces.push(CaptureSurface {
            name: "network".into(),
            enabled: false,
            status: SurfaceStatus::Unavailable,
            events_count: 0,
            note: Some("network capture not implemented".into()),
        });

        if let Some(n) = native_log_events {
            surfaces.push(CaptureSurface {
                name: "native_logs".into(),
                enabled: n > 0,
                status: if n > 0 {
                    SurfaceStatus::Complete
                } else {
                    SurfaceStatus::Unavailable
                },
                events_count: n,
                note: if n == 0 {
                    Some("no native harness logs discovered".into())
                } else {
                    Some("native harness logs available".into())
                },
            });
        } else {
            surfaces.push(CaptureSurface {
                name: "native_logs".into(),
                enabled: false,
                status: SurfaceStatus::Unavailable,
                events_count: 0,
                note: Some("native-log polling not reported for this run".into()),
            });
        }

        let total_events = pty_events
            + process_events
            + git_events
            + fs_events
            + env_events
            + native_log_events.unwrap_or(0);

        let mut notes = Vec::new();
        if !process_tree_available {
            notes.push("process-tree capture requires Linux /proc".into());
        }
        notes.push(
            "quality_score: weighted average of surface status (pty 30%, process 25%, git 15%, fs 15%, env 5%, native_logs 10%); disabled surfaces omitted".into(),
        );

        let mut cov = Self {
            surfaces,
            total_events,
            quality_score: 0,
            notes,
        };
        cov.recompute_quality_score();
        cov
    }
}

fn worse_status(a: SurfaceStatus, b: SurfaceStatus) -> SurfaceStatus {
    // Order of severity for merge: failed > unavailable > partial > unknown > complete > disabled
    let rank = |s: SurfaceStatus| match s {
        SurfaceStatus::Failed => 5,
        SurfaceStatus::Unavailable => 4,
        SurfaceStatus::Partial => 3,
        SurfaceStatus::Unknown => 2,
        SurfaceStatus::Complete => 1,
        SurfaceStatus::Disabled => 0,
    };
    if rank(a) >= rank(b) {
        a
    } else {
        b
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
        assert_eq!(cov.quality_score, 0);
    }

    #[test]
    fn from_surface_counts_basic() {
        let cov = CaptureCoverage::from_surface_counts(10, 5, 2, 8, 1, true);
        assert_eq!(cov.total_events, 26);
        assert!(cov.surfaces.len() >= 5);
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
        assert!(cov.quality_score > 0);
    }

    #[test]
    fn process_tree_note_on_linux() {
        let cov = CaptureCoverage::from_surface_counts(0, 0, 0, 0, 0, true);
        let process = cov.surfaces.iter().find(|s| s.name == "process").unwrap();
        assert_eq!(process.note.as_deref(), Some("process-tree capture active"));
        assert_eq!(process.status, SurfaceStatus::Partial);
    }

    #[test]
    fn process_tree_note_non_linux() {
        let cov = CaptureCoverage::from_surface_counts(0, 0, 0, 0, 0, false);
        let process = cov.surfaces.iter().find(|s| s.name == "process").unwrap();
        assert_eq!(
            process.note.as_deref(),
            Some("basic PID tracking only (no /proc)")
        );
        assert_eq!(process.status, SurfaceStatus::Unavailable);
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

    #[test]
    fn network_is_unavailable_not_absent() {
        let cov = CaptureCoverage::from_surface_counts(10, 5, 2, 8, 1, true);
        let net = cov.surfaces.iter().find(|s| s.name == "network").unwrap();
        assert_eq!(net.status, SurfaceStatus::Unavailable);
        assert!(!net.enabled);
    }

    #[test]
    fn quality_score_higher_with_full_capture() {
        let full = CaptureCoverage::from_surface_counts(10, 5, 2, 8, 1, true);
        let thin = CaptureCoverage::from_surface_counts(0, 0, 0, 0, 0, false);
        assert!(full.quality_score > thin.quality_score);
    }

    #[test]
    fn process_failed_lowers_status() {
        let cov = CaptureCoverage::from_surface_counts_ext(5, 0, 0, 0, 0, true, None, Some(true));
        let process = cov.surfaces.iter().find(|s| s.name == "process").unwrap();
        assert_eq!(process.status, SurfaceStatus::Failed);
    }

    #[test]
    fn disabled_surface_omitted_from_score() {
        let mut surfaces = vec![
            CaptureSurface {
                name: "pty".into(),
                enabled: true,
                status: SurfaceStatus::Complete,
                events_count: 1,
                note: None,
            },
            CaptureSurface {
                name: "process".into(),
                enabled: false,
                status: SurfaceStatus::Disabled,
                events_count: 0,
                note: None,
            },
        ];
        // Fill remaining so den is stable
        for name in ["git", "filesystem", "environment", "native_logs"] {
            surfaces.push(CaptureSurface {
                name: name.into(),
                enabled: true,
                status: SurfaceStatus::Complete,
                events_count: 1,
                note: None,
            });
        }
        let score = CaptureCoverage::compute_quality_score(&surfaces);
        // process is disabled → omitted; all others complete → 100
        assert_eq!(score, 100);
    }

    #[test]
    fn distinguishes_disabled_unavailable_failed() {
        assert_ne!(SurfaceStatus::Disabled, SurfaceStatus::Unavailable);
        assert_ne!(SurfaceStatus::Unavailable, SurfaceStatus::Failed);
        assert_eq!(SurfaceStatus::Disabled.quality_weight(), 0.0);
        assert_eq!(SurfaceStatus::Failed.quality_weight(), 0.1);
    }
}
