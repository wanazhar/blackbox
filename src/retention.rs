//! Policy-driven retention (keep window OR max age; pinned tag never deleted).

use chrono::{Duration, Utc};

use crate::config::RetentionConfig;
use crate::core::run::Run;

/// Candidate for deletion under a retention policy.
#[derive(Debug, Clone)]
pub struct RetentionCandidate {
    pub id: String,
    pub reason: String,
}

/// Compute the delete set (K22).
///
/// 1. Exclude runs tagged `pinned`.
/// 2. Newest `keep_runs` unpinned runs are the keep window.
/// 3. Age-expired if `coalesce(ended_at, started_at)` older than `max_age_days`.
/// 4. Delete = unpinned AND (outside keep window OR age-expired).
pub fn plan_deletions(runs: &[Run], cfg: &RetentionConfig) -> Vec<RetentionCandidate> {
    // runs assumed most-recent-first (list_runs order)
    let keep = cfg.keep_runs as usize;
    let age = cfg.max_age_days.map(|d| Duration::days(d as i64));
    let now = Utc::now();

    let mut unpinned: Vec<&Run> = runs
        .iter()
        .filter(|r| !r.tags.iter().any(|t| t == "pinned"))
        .collect();

    // Index of unpinned by recency
    let mut candidates = Vec::new();
    for (i, run) in unpinned.iter().enumerate() {
        let outside_keep = i >= keep;
        let age_expired = if let Some(max_age) = age {
            let t = run.ended_at.unwrap_or(run.started_at);
            now.signed_duration_since(t) > max_age
        } else {
            false
        };

        if outside_keep || age_expired {
            let mut reasons = Vec::new();
            if outside_keep {
                reasons.push(format!("outside keep window (keep={keep})"));
            }
            if age_expired {
                reasons.push(format!("older than {} days", cfg.max_age_days.unwrap_or(0)));
            }
            candidates.push(RetentionCandidate {
                id: run.id.clone(),
                reason: reasons.join("; "),
            });
        }
    }

    // Silence unused mut if empty
    let _ = &mut unpinned;
    candidates
}

/// Soft progressive-degradation advice when store is large.
/// Prefer GC order: oldest success runs → blob GC → keep failures longer.
pub fn progressive_gc_advice(run_count: usize, total_bytes: u64, keep_runs: u32) -> Vec<String> {
    let mut tips = Vec::new();
    if total_bytes > 512 * 1024 * 1024 {
        tips.push(
            "store >512MiB: run `blackbox gc --apply` then `blackbox scrub --gc`".into(),
        );
    }
    if run_count as u32 > keep_runs.saturating_mul(2).max(20) {
        tips.push(format!(
            "run count {run_count} exceeds 2× keep_runs ({keep_runs}): tighten retention or gc"
        ));
    }
    if total_bytes > 1024 * 1024 * 1024 {
        tips.push(
            "store >1GiB: consider lowering keep_runs and enabling retention.auto_apply".into(),
        );
    }
    tips
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::run::{Run, RunStatus};
    use chrono::TimeZone;

    fn run_at(id: &str, days_ago: i64, tags: &[&str]) -> Run {
        let started =
            Utc.with_ymd_and_hms(2026, 7, 12, 12, 0, 0).unwrap() - Duration::days(days_ago);
        let mut r = Run::new(vec!["echo".into()], "/tmp".into());
        r.id = id.into();
        r.started_at = started;
        r.ended_at = Some(started + Duration::seconds(1));
        r.status = RunStatus::Succeeded;
        r.tags = tags.iter().map(|s| s.to_string()).collect();
        r
    }

    #[test]
    fn keep_window_only() {
        let runs = vec![
            run_at("new", 0, &[]),
            run_at("mid", 1, &[]),
            run_at("old", 2, &[]),
        ];
        let cfg = RetentionConfig {
            keep_runs: 2,
            max_age_days: None,
            ..Default::default()
        };
        let plan = plan_deletions(&runs, &cfg);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].id, "old");
    }

    #[test]
    fn pinned_never_deleted() {
        let runs = vec![
            run_at("new", 0, &[]),
            run_at("pinned-old", 100, &["pinned"]),
            run_at("old", 100, &[]),
        ];
        let cfg = RetentionConfig {
            keep_runs: 1,
            max_age_days: Some(30),
            ..Default::default()
        };
        let plan = plan_deletions(&runs, &cfg);
        assert!(plan.iter().all(|c| c.id != "pinned-old"));
        assert!(plan.iter().any(|c| c.id == "old"));
    }

    #[test]
    fn age_expires_even_in_keep_window() {
        // keep=50 but age 1 day — recent flood of 2 runs both age-expired if old
        let runs = vec![run_at("a", 10, &[]), run_at("b", 11, &[])];
        let cfg = RetentionConfig {
            keep_runs: 50,
            max_age_days: Some(5),
            ..Default::default()
        };
        let plan = plan_deletions(&runs, &cfg);
        assert_eq!(plan.len(), 2);
    }

    #[test]
    fn progressive_advice_on_large_store() {
        let tips = progressive_gc_advice(100, 600 * 1024 * 1024, 20);
        assert!(!tips.is_empty());
    }
}
