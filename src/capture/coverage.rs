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

/// End-of-run signals used to build an honest coverage report.
#[derive(Debug, Clone, Default)]
pub struct RunCoverageSignals {
    pub pty_events: u64,
    pub process_events: u64,
    pub git_events: u64,
    pub fs_events: u64,
    pub env_events: u64,
    pub process_tree_available: bool,
    pub native_log_events: Option<u64>,
    pub process_failed: bool,
    pub pty_failed: bool,
    pub git_failed: bool,
    pub fs_failed: bool,
    /// Soft lag note from EventWriter health (store falling behind).
    pub capture_lag_note: Option<String>,
    /// Structured tool.call count (adapter drought detection).
    pub tool_call_count: u64,
    /// Known harness adapter id when present (claude, codex, …).
    pub adapter_id: Option<String>,
    /// Wall duration of the run in ms (for drought threshold).
    pub duration_ms: Option<u64>,
    /// Total events in the rollup window.
    pub total_events_window: u64,
}

/// Adapters that normally emit structured `tool.call` events.
pub fn structured_harness_adapters() -> &'static [&'static str] {
    &[
        "claude", "codex", "aider", "gemini", "cursor", "opencode", "grok",
    ]
}

/// True when a known harness produced no tool.call despite enough activity.
///
/// Threshold: adapter is structured **and** tool_call_count == 0 **and**
/// (events ≥ 20 **or** duration ≥ 5s). Short `true` / setup samples do not fire.
pub fn adapter_tool_drought(sig: &RunCoverageSignals) -> Option<String> {
    let adapter = sig.adapter_id.as_deref()?;
    if !structured_harness_adapters()
        .iter()
        .any(|a| a.eq_ignore_ascii_case(adapter))
    {
        return None;
    }
    if sig.tool_call_count > 0 {
        return None;
    }
    let long_enough = sig.total_events_window >= 20 || sig.duration_ms.is_some_and(|d| d >= 5_000);
    if !long_enough {
        return None;
    }
    Some(format!(
        "adapter drought: harness={adapter} produced 0 tool.call events \
         (events={} duration_ms={:?}) — check stream-json / native logs / adapter health",
        sig.total_events_window, sig.duration_ms
    ))
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
                existing.status = worse_status(existing.status, s.status);
            } else {
                self.surfaces.push(s.clone());
            }
        }
        self.total_events += other.total_events;
        self.notes.extend(other.notes.clone());
        self.recompute_quality_score();
    }

    /// Documented scoring algorithm (see module docs / `docs/guide/overhead.md`).
    pub fn compute_quality_score(surfaces: &[CaptureSurface]) -> u8 {
        let mut num = 0.0;
        let mut den = 0.0;
        for (name, weight) in SURFACE_WEIGHTS {
            let surface = surfaces.iter().find(|s| s.name == *name);
            let status = surface.map(|s| s.status).unwrap_or(SurfaceStatus::Unknown);
            if status == SurfaceStatus::Disabled {
                continue;
            }
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

    /// Mark a surface as failed (capture-layer error path).
    pub fn mark_surface_failed(&mut self, name: &str, reason: impl Into<String>) {
        let reason = reason.into();
        if let Some(s) = self.surfaces.iter_mut().find(|x| x.name == name) {
            s.status = SurfaceStatus::Failed;
            s.enabled = true;
            s.note = Some(reason.clone());
        } else {
            self.surfaces.push(CaptureSurface {
                name: name.into(),
                enabled: true,
                status: SurfaceStatus::Failed,
                events_count: 0,
                note: Some(reason.clone()),
            });
        }
        self.notes.push(format!("{name} capture failed: {reason}"));
        self.recompute_quality_score();
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
        Self::from_run_signals(RunCoverageSignals {
            pty_events,
            process_events,
            git_events,
            fs_events,
            env_events,
            process_tree_available,
            native_log_events: None,
            process_failed: false,
            pty_failed: false,
            git_failed: false,
            fs_failed: false,
            capture_lag_note: None,
            tool_call_count: 0,
            adapter_id: None,
            duration_ms: None,
            total_events_window: 0,
        })
    }

    /// Extended builder (compat).
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
        Self::from_run_signals(RunCoverageSignals {
            pty_events,
            process_events,
            git_events,
            fs_events,
            env_events,
            process_tree_available,
            native_log_events,
            process_failed: process_failed.unwrap_or(false),
            pty_failed: false,
            git_failed: false,
            fs_failed: false,
            capture_lag_note: None,
            tool_call_count: 0,
            adapter_id: None,
            duration_ms: None,
            total_events_window: 0,
        })
    }

    /// Preferred end-of-run builder with failure + lag signals.
    pub fn from_run_signals(sig: RunCoverageSignals) -> Self {
        let mut surfaces = Vec::new();

        surfaces.push(CaptureSurface {
            name: "pty".into(),
            enabled: true,
            status: if sig.pty_failed {
                SurfaceStatus::Failed
            } else if sig.pty_events > 0 {
                SurfaceStatus::Complete
            } else {
                SurfaceStatus::Partial
            },
            events_count: sig.pty_events,
            note: if sig.pty_failed {
                Some("PTY capture layer reported failure".into())
            } else if sig.pty_events == 0 {
                Some("no PTY output captured".into())
            } else {
                None
            },
        });

        surfaces.push(CaptureSurface {
            name: "process".into(),
            enabled: true,
            status: if sig.process_failed {
                SurfaceStatus::Failed
            } else if !sig.process_tree_available {
                if sig.process_events > 0 {
                    SurfaceStatus::Partial
                } else {
                    SurfaceStatus::Unavailable
                }
            } else if sig.process_events > 0 {
                SurfaceStatus::Complete
            } else {
                SurfaceStatus::Partial
            },
            events_count: sig.process_events,
            note: if sig.process_failed {
                Some("process capture layer failed".into())
            } else if sig.process_tree_available {
                Some(
                    "process-tree capture active (short-lived children may be missed between polls)"
                        .into(),
                )
            } else {
                Some("basic PID tracking only (no /proc)".into())
            },
        });

        surfaces.push(CaptureSurface {
            name: "git".into(),
            enabled: !sig.git_failed,
            status: if sig.git_failed {
                SurfaceStatus::Failed
            } else if sig.git_events > 0 {
                SurfaceStatus::Complete
            } else {
                SurfaceStatus::Partial
            },
            events_count: sig.git_events,
            note: if sig.git_failed {
                Some("git capture layer failed".into())
            } else if sig.git_events == 0 {
                Some("no git repository detected or no changes".into())
            } else {
                None
            },
        });

        surfaces.push(CaptureSurface {
            name: "filesystem".into(),
            enabled: true,
            status: if sig.fs_failed {
                SurfaceStatus::Failed
            } else if sig.fs_events > 0 {
                SurfaceStatus::Complete
            } else {
                SurfaceStatus::Partial
            },
            events_count: sig.fs_events,
            note: if sig.fs_failed {
                Some("filesystem capture layer failed".into())
            } else if sig.fs_events == 0 {
                Some("no filesystem events captured".into())
            } else {
                None
            },
        });

        surfaces.push(CaptureSurface {
            name: "environment".into(),
            enabled: true,
            status: if sig.env_events > 0 {
                SurfaceStatus::Complete
            } else {
                SurfaceStatus::Partial
            },
            events_count: sig.env_events,
            note: Some("captured at run start".into()),
        });

        surfaces.push(CaptureSurface {
            name: "network".into(),
            enabled: false,
            status: SurfaceStatus::Unavailable,
            events_count: 0,
            note: Some("network capture not implemented".into()),
        });

        if let Some(n) = sig.native_log_events {
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

        let total_events = sig.pty_events
            + sig.process_events
            + sig.git_events
            + sig.fs_events
            + sig.env_events
            + sig.native_log_events.unwrap_or(0);

        let mut notes = Vec::new();
        if !sig.process_tree_available {
            notes.push("process-tree capture requires Linux /proc".into());
        }
        notes.push(
            "quality_score: weighted average of surface status (pty 30%, process 25%, git 15%, fs 15%, env 5%, native_logs 10%); disabled surfaces omitted".into(),
        );
        if let Some(ref lag) = sig.capture_lag_note {
            notes.push(lag.clone());
        }
        if let Some(drought) = adapter_tool_drought(&sig) {
            notes.push(drought);
        }

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
        assert!(cov.quality_score > 0);
    }

    #[test]
    fn process_failed_lowers_status() {
        let cov = CaptureCoverage::from_surface_counts_ext(5, 0, 0, 0, 0, true, None, Some(true));
        let process = cov.surfaces.iter().find(|s| s.name == "process").unwrap();
        assert_eq!(process.status, SurfaceStatus::Failed);
    }

    #[test]
    fn mark_surface_failed_updates_score() {
        let mut cov = CaptureCoverage::from_surface_counts(10, 5, 2, 8, 1, true);
        let before = cov.quality_score;
        cov.mark_surface_failed("filesystem", "watcher crashed");
        assert!(cov.quality_score <= before);
        let fs = cov
            .surfaces
            .iter()
            .find(|s| s.name == "filesystem")
            .unwrap();
        assert_eq!(fs.status, SurfaceStatus::Failed);
    }

    #[test]
    fn lag_note_appears() {
        let cov = CaptureCoverage::from_run_signals(RunCoverageSignals {
            pty_events: 3,
            process_events: 1,
            git_events: 0,
            fs_events: 0,
            env_events: 1,
            process_tree_available: true,
            native_log_events: Some(0),
            capture_lag_note: Some("capture lag: 6 slow writes".into()),
            ..Default::default()
        });
        assert!(cov.notes.iter().any(|n| n.contains("capture lag")));
    }

    #[test]
    fn adapter_drought_fires_for_long_claude_without_tools() {
        let msg = adapter_tool_drought(&RunCoverageSignals {
            adapter_id: Some("claude".into()),
            tool_call_count: 0,
            total_events_window: 40,
            duration_ms: Some(12_000),
            ..Default::default()
        });
        assert!(msg.unwrap().contains("adapter drought"));
    }

    #[test]
    fn adapter_drought_skips_short_or_generic() {
        assert!(adapter_tool_drought(&RunCoverageSignals {
            adapter_id: Some("claude".into()),
            tool_call_count: 0,
            total_events_window: 5,
            duration_ms: Some(100),
            ..Default::default()
        })
        .is_none());
        assert!(adapter_tool_drought(&RunCoverageSignals {
            adapter_id: Some("generic".into()),
            tool_call_count: 0,
            total_events_window: 100,
            duration_ms: Some(60_000),
            ..Default::default()
        })
        .is_none());
        assert!(adapter_tool_drought(&RunCoverageSignals {
            adapter_id: Some("claude".into()),
            tool_call_count: 3,
            total_events_window: 100,
            duration_ms: Some(60_000),
            ..Default::default()
        })
        .is_none());
    }

    #[test]
    fn network_is_unavailable_not_absent() {
        let cov = CaptureCoverage::from_surface_counts(10, 5, 2, 8, 1, true);
        let net = cov.surfaces.iter().find(|s| s.name == "network").unwrap();
        assert_eq!(net.status, SurfaceStatus::Unavailable);
        assert!(!net.enabled);
    }

    #[test]
    fn distinguishes_disabled_unavailable_failed() {
        assert_ne!(SurfaceStatus::Disabled, SurfaceStatus::Unavailable);
        assert_ne!(SurfaceStatus::Unavailable, SurfaceStatus::Failed);
    }
}
