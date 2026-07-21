//! Capture-coverage model — honest reporting of what was captured.
//!
//! After each run, a `CaptureCoverage` summary is emitted as run metadata
//! so consumers can assess which observation surfaces were available,
//! active, and how many events each produced.
//!
//! Coverage status (1.4 C1):
//! **complete**, **partial**, **failed**, **unavailable**, **disabled**,
//! **not_applicable**, **unknown**.
//!
//! `not_applicable` surfaces are **excluded** from the quality-score
//! denominator so non-git trees and generic harnesses are not penalized.

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
    /// Surface does not apply to this run context (excluded from score).
    NotApplicable,
    /// Status not established.
    #[default]
    Unknown,
}

impl SurfaceStatus {
    /// View as str.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `as_str` — see module docs for full workflow.
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Unavailable => "unavailable",
            Self::Failed => "failed",
            Self::Partial => "partial",
            Self::Complete => "complete",
            Self::NotApplicable => "not_applicable",
            Self::Unknown => "unknown",
        }
    }

    /// Contribution weight for quality scoring (0.0–1.0).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `quality_weight` — see module docs for full workflow.
    /// ```
    pub fn quality_weight(self) -> f64 {
        match self {
            Self::Complete => 1.0,
            Self::Partial => 0.5,
            Self::Failed => 0.1,
            Self::Unavailable => 0.0,
            Self::Disabled => 0.0,
            Self::NotApplicable => 0.0,
            Self::Unknown => 0.0,
        }
    }

    /// Whether this status is omitted from the quality-score denominator.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `excluded_from_score` — see module docs for full workflow.
    /// ```
    pub fn excluded_from_score(self) -> bool {
        matches!(self, Self::Disabled | Self::NotApplicable)
    }
}

/// End-of-run signals used to build an honest coverage report.
#[derive(Debug, Clone, Default)]
pub struct RunCoverageSignals {
    /// Pty events.
    pub pty_events: u64,
    /// Process events.
    pub process_events: u64,
    /// Git events.
    pub git_events: u64,
    /// Fs events.
    pub fs_events: u64,
    /// Env events.
    pub env_events: u64,
    /// Process tree available.
    pub process_tree_available: bool,
    /// Native log events.
    pub native_log_events: Option<u64>,
    /// Process failed.
    pub process_failed: bool,
    /// Pty failed.
    pub pty_failed: bool,
    /// Git failed.
    pub git_failed: bool,
    /// Fs failed.
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
    /// Git surface is not applicable (no repository) — 1.4 C1.
    pub git_not_a_repo: bool,
    /// Native-log surface does not apply (generic / no native capability).
    pub native_logs_not_applicable: bool,
    /// Native logs intentionally disabled (scope=off).
    pub native_logs_disabled: bool,
    // ── Process completeness signals (1.4 C2) ──────────────────────
    /// Process observer started.
    pub process_observer_started: bool,
    /// Process root spawned.
    pub process_root_spawned: bool,
    /// Process tree snapshot.
    pub process_tree_snapshot: bool,
    /// Process observer stopped.
    pub process_observer_stopped: bool,
    /// Process backend.
    pub process_backend: Option<String>,
}

/// Adapters that normally emit structured `tool.call` events.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `structured_harness_adapters` — see module docs for full workflow.
/// ```
pub fn structured_harness_adapters() -> &'static [&'static str] {
    &[
        "claude", "codex", "aider", "gemini", "cursor", "opencode", "grok",
    ]
}

/// True when a known harness produced no tool.call despite enough activity.
///
/// Threshold: adapter is structured **and** tool_call_count == 0 **and**
/// (events ≥ 20 **or** duration ≥ 5s). Short `true` / setup samples do not fire.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `adapter_tool_drought` — see module docs for full workflow.
/// ```
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

/// Weighted contribution of one surface to the quality score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreContribution {
    /// Surface.
    pub surface: String,
    /// Status value.
    pub status: SurfaceStatus,
    /// Weight.
    pub weight: f64,
    /// Points contributed to numerator (weight × status_weight), or 0 when excluded.
    pub points: f64,
    /// True when surface is omitted from the score denominator.
    #[serde(default)]
    pub excluded: bool,
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
    /// Weighted contribution math (1.4 C3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributions: Vec<ScoreContribution>,
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
    /// Honest status: disabled / unavailable / failed / partial / complete / not_applicable.
    #[serde(default)]
    pub status: SurfaceStatus,
    /// Number of events produced by this surface.
    pub events_count: u64,
    /// Human-readable note about the surface's availability or limitations.
    pub note: Option<String>,
}

/// Weights used by the documented quality scoring algorithm.
///
/// Score = 100 × Σ(weight_i × status_weight_i) / Σ(weight_i for non-excluded)
/// Surfaces that are disabled or not_applicable do not penalize the score.
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `merge` — see module docs for full workflow.
    /// ```
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

    /// Build contribution rows and quality score from surfaces.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `compute_contributions` — see module docs for full workflow.
    /// ```
    pub fn compute_contributions(surfaces: &[CaptureSurface]) -> (u8, Vec<ScoreContribution>) {
        let mut num = 0.0;
        let mut den = 0.0;
        let mut contributions = Vec::new();
        for (name, weight) in SURFACE_WEIGHTS {
            let surface = surfaces.iter().find(|s| s.name == *name);
            let status = surface.map(|s| s.status).unwrap_or(SurfaceStatus::Unknown);
            let excluded = status.excluded_from_score();
            if excluded {
                contributions.push(ScoreContribution {
                    surface: (*name).into(),
                    status,
                    weight: *weight,
                    points: 0.0,
                    excluded: true,
                });
                continue;
            }
            if surface.is_none() {
                den += weight;
                contributions.push(ScoreContribution {
                    surface: (*name).into(),
                    status: SurfaceStatus::Unknown,
                    weight: *weight,
                    points: 0.0,
                    excluded: false,
                });
                continue;
            }
            let points = weight * status.quality_weight();
            den += weight;
            num += points;
            contributions.push(ScoreContribution {
                surface: (*name).into(),
                status,
                weight: *weight,
                points,
                excluded: false,
            });
        }
        let score = if den <= 0.0 {
            0
        } else {
            ((num / den) * 100.0).round().clamp(0.0, 100.0) as u8
        };
        (score, contributions)
    }

    /// Documented scoring algorithm (see module docs / doctor notes).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `compute_quality_score` — see module docs for full workflow.
    /// ```
    pub fn compute_quality_score(surfaces: &[CaptureSurface]) -> u8 {
        Self::compute_contributions(surfaces).0
    }

    /// Recompute quality score.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `recompute_quality_score` — see module docs for full workflow.
    /// ```
    pub fn recompute_quality_score(&mut self) {
        let (score, contribs) = Self::compute_contributions(&self.surfaces);
        self.quality_score = score;
        self.contributions = contribs;
    }

    /// Mark a surface as failed (capture-layer error path).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `mark_surface_failed` — see module docs for full workflow.
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_surface_counts` — see module docs for full workflow.
    /// ```
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
            git_not_a_repo: false,
            native_logs_not_applicable: false,
            native_logs_disabled: false,
            process_observer_started: process_events > 0,
            process_root_spawned: process_events > 0,
            process_tree_snapshot: process_tree_available && process_events > 0,
            process_observer_stopped: process_events > 0,
            process_backend: if process_tree_available {
                Some("assumed".into())
            } else {
                None
            },
        })
    }

    /// Extended builder (compat).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_surface_counts_ext` — see module docs for full workflow.
    /// ```
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
            git_not_a_repo: false,
            native_logs_not_applicable: false,
            native_logs_disabled: false,
            process_observer_started: process_events > 0,
            process_root_spawned: process_events > 0,
            process_tree_snapshot: process_tree_available && process_events > 0,
            process_observer_stopped: process_events > 0,
            process_backend: if process_tree_available {
                Some("assumed".into())
            } else {
                None
            },
        })
    }

    /// Preferred end-of-run builder with failure + lag + applicability signals.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_run_signals` — see module docs for full workflow.
    /// ```
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

        surfaces.push(process_surface(&sig));

        // Git: not_applicable when no repository (git.not_a_repo).
        if sig.git_not_a_repo && !sig.git_failed {
            surfaces.push(CaptureSurface {
                name: "git".into(),
                enabled: false,
                status: SurfaceStatus::NotApplicable,
                events_count: sig.git_events,
                note: Some("not a git repository".into()),
            });
        } else {
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
                    Some("no git changes observed".into())
                } else {
                    None
                },
            });
        }

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

        // Network may have occurred but was not captured — unavailable, not N/A.
        surfaces.push(CaptureSurface {
            name: "network".into(),
            enabled: false,
            status: SurfaceStatus::Unavailable,
            events_count: 0,
            note: Some("network capture not implemented".into()),
        });

        if sig.native_logs_disabled {
            surfaces.push(CaptureSurface {
                name: "native_logs".into(),
                enabled: false,
                status: SurfaceStatus::Disabled,
                events_count: 0,
                note: Some("native_log_scope=off".into()),
            });
        } else if sig.native_logs_not_applicable {
            surfaces.push(CaptureSurface {
                name: "native_logs".into(),
                enabled: false,
                status: SurfaceStatus::NotApplicable,
                events_count: sig.native_log_events.unwrap_or(0),
                note: Some("adapter has no native-log surface".into()),
            });
        } else if let Some(n) = sig.native_log_events {
            surfaces.push(CaptureSurface {
                name: "native_logs".into(),
                enabled: n > 0,
                status: if n > 0 {
                    SurfaceStatus::Complete
                } else {
                    // Known harness but no logs discovered this run — partial/unavailable.
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
            notes.push("process-tree capture requires Linux /proc or sysinfo backend".into());
        }
        notes.push(
            "quality_score: weighted average of applicable surfaces (pty 30%, process 25%, git 15%, fs 15%, env 5%, native_logs 10%); disabled and not_applicable surfaces omitted".into(),
        );
        notes.push(
            "pty: normalized searchable transcript is not a full-screen TUI frame replay; raw redacted blobs preserve byte stream when stored".into(),
        );
        notes.push(
            "backpressure: merge path does not silently drop events; lag samples and send_failures are counted and surfaced".into(),
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
            contributions: Vec::new(),
            notes,
        };
        cov.recompute_quality_score();
        cov
    }
}

/// Process surface status from lifecycle completeness signals (1.4 C2).
fn process_surface(sig: &RunCoverageSignals) -> CaptureSurface {
    let note_backend = sig
        .process_backend
        .as_deref()
        .map(|b| format!("backend={b}"))
        .unwrap_or_else(|| "backend=unknown".into());

    if sig.process_failed {
        return CaptureSurface {
            name: "process".into(),
            enabled: true,
            status: SurfaceStatus::Failed,
            events_count: sig.process_events,
            note: Some(format!("process capture layer failed ({note_backend})")),
        };
    }

    if !sig.process_tree_available {
        let status = if sig.process_events > 0 {
            SurfaceStatus::Partial
        } else {
            SurfaceStatus::Unavailable
        };
        return CaptureSurface {
            name: "process".into(),
            enabled: true,
            status,
            events_count: sig.process_events,
            note: Some("basic PID tracking only (no process-tree backend)".into()),
        };
    }

    // Completeness requires the full observer lifecycle, not mere event count.
    let lifecycle_ok = sig.process_observer_started
        && sig.process_root_spawned
        && sig.process_observer_stopped
        && sig.process_backend.is_some();

    let material_lag = sig
        .capture_lag_note
        .as_ref()
        .map(|n| n.contains("lag") || n.contains("drop"))
        .unwrap_or(false);

    let status = if lifecycle_ok && sig.process_tree_snapshot && !material_lag {
        SurfaceStatus::Complete
    } else {
        // Events without full lifecycle, or empty process surface → partial
        // (not complete; not failed unless process_failed above).
        SurfaceStatus::Partial
    };

    let mut note_parts = vec![note_backend];
    if !sig.process_observer_started {
        note_parts.push("observer.started missing".into());
    }
    if !sig.process_root_spawned {
        note_parts.push("root process.spawned missing".into());
    }
    if !sig.process_tree_snapshot {
        note_parts.push("tree snapshot missing (short-lived children may be missed)".into());
    }
    if !sig.process_observer_stopped {
        note_parts.push("observer.stopped missing".into());
    }
    if material_lag {
        note_parts.push("material capture lag/drop".into());
    }
    if status == SurfaceStatus::Complete {
        note_parts.push(
            "process-tree capture active (short-lived children may be missed between polls)".into(),
        );
    }

    CaptureSurface {
        name: "process".into(),
        enabled: true,
        status,
        events_count: sig.process_events,
        note: Some(note_parts.join("; ")),
    }
}

fn worse_status(a: SurfaceStatus, b: SurfaceStatus) -> SurfaceStatus {
    let rank = |s: SurfaceStatus| match s {
        SurfaceStatus::Failed => 6,
        SurfaceStatus::Unavailable => 5,
        SurfaceStatus::Partial => 4,
        SurfaceStatus::Unknown => 3,
        SurfaceStatus::Complete => 2,
        SurfaceStatus::NotApplicable => 1,
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
        assert!(!cov.contributions.is_empty());
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
            process_observer_started: true,
            process_root_spawned: true,
            process_tree_snapshot: true,
            process_observer_stopped: true,
            process_backend: Some("linux_proc".into()),
            ..Default::default()
        });
        assert!(cov.notes.iter().any(|n| n.contains("capture lag")));
        let process = cov.surfaces.iter().find(|s| s.name == "process").unwrap();
        assert_eq!(
            process.status,
            SurfaceStatus::Partial,
            "material lag must downgrade process from complete"
        );
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
        assert_ne!(SurfaceStatus::NotApplicable, SurfaceStatus::Unavailable);
    }

    #[test]
    fn git_not_a_repo_is_not_applicable_and_excluded() {
        let cov = CaptureCoverage::from_run_signals(RunCoverageSignals {
            pty_events: 10,
            process_events: 5,
            git_events: 1, // git.not_a_repo event still counts
            fs_events: 8,
            env_events: 1,
            process_tree_available: true,
            git_not_a_repo: true,
            native_log_events: Some(2),
            process_observer_started: true,
            process_root_spawned: true,
            process_tree_snapshot: true,
            process_observer_stopped: true,
            process_backend: Some("linux_proc".into()),
            ..Default::default()
        });
        let git = cov.surfaces.iter().find(|s| s.name == "git").unwrap();
        assert_eq!(git.status, SurfaceStatus::NotApplicable);
        let git_c = cov
            .contributions
            .iter()
            .find(|c| c.surface == "git")
            .unwrap();
        assert!(git_c.excluded);
        // Non-git complete run should still be high score
        assert!(
            cov.quality_score >= 90,
            "score={} contributions={:?}",
            cov.quality_score,
            cov.contributions
        );
    }

    #[test]
    fn native_logs_not_applicable_for_generic() {
        let cov = CaptureCoverage::from_run_signals(RunCoverageSignals {
            pty_events: 5,
            process_events: 3,
            git_events: 1,
            fs_events: 2,
            env_events: 1,
            process_tree_available: true,
            native_logs_not_applicable: true,
            native_log_events: Some(0),
            process_observer_started: true,
            process_root_spawned: true,
            process_tree_snapshot: true,
            process_observer_stopped: true,
            process_backend: Some("linux_proc".into()),
            ..Default::default()
        });
        let nl = cov
            .surfaces
            .iter()
            .find(|s| s.name == "native_logs")
            .unwrap();
        assert_eq!(nl.status, SurfaceStatus::NotApplicable);
    }

    #[test]
    fn process_not_complete_without_lifecycle() {
        let cov = CaptureCoverage::from_run_signals(RunCoverageSignals {
            pty_events: 1,
            process_events: 4, // events exist but lifecycle incomplete
            process_tree_available: true,
            process_observer_started: true,
            process_root_spawned: false,
            process_tree_snapshot: false,
            process_observer_stopped: false,
            process_backend: Some("linux_proc".into()),
            env_events: 1,
            ..Default::default()
        });
        let process = cov.surfaces.iter().find(|s| s.name == "process").unwrap();
        assert_eq!(process.status, SurfaceStatus::Partial);
    }

    #[test]
    fn process_complete_with_full_lifecycle() {
        let cov = CaptureCoverage::from_run_signals(RunCoverageSignals {
            pty_events: 1,
            process_events: 4,
            process_tree_available: true,
            process_observer_started: true,
            process_root_spawned: true,
            process_tree_snapshot: true,
            process_observer_stopped: true,
            process_backend: Some("linux_proc".into()),
            env_events: 1,
            git_events: 1,
            fs_events: 1,
            native_log_events: Some(1),
            ..Default::default()
        });
        let process = cov.surfaces.iter().find(|s| s.name == "process").unwrap();
        assert_eq!(process.status, SurfaceStatus::Complete);
        assert_eq!(cov.quality_score, 100);
    }

    #[test]
    fn non_git_can_reach_100() {
        let cov = CaptureCoverage::from_run_signals(RunCoverageSignals {
            pty_events: 10,
            process_events: 5,
            git_events: 0,
            fs_events: 8,
            env_events: 1,
            process_tree_available: true,
            git_not_a_repo: true,
            native_log_events: Some(3),
            process_observer_started: true,
            process_root_spawned: true,
            process_tree_snapshot: true,
            process_observer_stopped: true,
            process_backend: Some("linux_proc".into()),
            ..Default::default()
        });
        assert_eq!(cov.quality_score, 100);
    }
}
