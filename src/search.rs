//! Full-text search across runs and events (FTS5 when available).

use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::storage::TraceStore;

/// One search hit.
#[derive(Debug, Clone)]
pub struct SearchHit {
    pub run_id: String,
    pub run_label: String,
    pub event_id: Option<String>,
    pub sequence: Option<u64>,
    pub kind: String,
    pub snippet: String,
    pub score: u32,
    /// Backend used: "fts5" or "scan"
    pub backend: &'static str,
}

/// Search runs + events for a case-insensitive query.
///
/// Prefer SQLite FTS5 for events when the store supports it; fall back to
/// scanning recent runs. Run-level matches always use a linear scan of
/// run metadata (command/name/tags/notes).
pub async fn search_store(
    store: &dyn TraceStore,
    query: &str,
    max_runs: usize,
    limit: usize,
) -> anyhow::Result<Vec<SearchHit>> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let terms: Vec<&str> = q.split_whitespace().collect();

    let runs = store.list_runs().await?;
    let mut hits = Vec::new();
    let mut backend: &'static str = "scan";

    // Run-level hits (always)
    for run in runs.iter().take(max_runs) {
        if let Some(hit) = score_run(run, &terms) {
            hits.push(hit);
        }
    }

    // Event hits: FTS preferred
    if let Some(fts_rows) = store.fts_event_ids(query, limit.saturating_mul(3)).await? {
        backend = "fts5";
        for (event_id, run_id, rank) in fts_rows {
            let Some(ev) = store.get_event(&event_id).await? else {
                continue;
            };
            let run = store
                .get_run(&run_id)
                .await?
                .unwrap_or_else(|| Run::new(vec!["?".into()], ".".into()));
            // Fix run id if synthetic
            let mut run = run;
            if run.command == ["?"] {
                run.id = run_id.clone();
            }
            let mut hit = event_to_hit(&run, &ev, backend);
            // FTS rank is negative (better = more negative); invert for display score
            hit.score = rank_to_score(rank);
            hits.push(hit);
        }
    } else {
        // L-30: Fallback linear scan when FTS5 is unavailable. This is O(n*m)
        // over all runs × events — acceptable for small stores but may be slow
        // for large histories. Consider adding an in-memory inverted index as
        // an intermediate tier.
        for run in runs.into_iter().take(max_runs) {
            let events = store.get_events(&run.id).await?;
            for ev in events {
                if let Some(hit) = score_event(&run, &ev, &terms, backend) {
                    hits.push(hit);
                }
            }
        }
    }

    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.sequence.unwrap_or(0).cmp(&a.sequence.unwrap_or(0)))
    });
    hits.truncate(limit);
    Ok(hits)
}

fn rank_to_score(rank: f64) -> u32 {
    // bm25-style ranks are negative; map to a positive display score
    let s = (-rank * 10.0).clamp(1.0, 1000.0);
    s as u32
}

fn run_label(run: &Run) -> String {
    run.name.clone().unwrap_or_else(|| run.command.join(" "))
}

fn score_run(run: &Run, terms: &[&str]) -> Option<SearchHit> {
    let mut hay = String::new();
    hay.push_str(&run.id);
    hay.push(' ');
    hay.push_str(&run.command.join(" "));
    if let Some(n) = &run.name {
        hay.push(' ');
        hay.push_str(n);
    }
    if let Some(n) = &run.notes {
        hay.push(' ');
        hay.push_str(n);
    }
    for t in &run.tags {
        hay.push(' ');
        hay.push_str(t);
    }
    let hay_l = hay.to_lowercase();
    let score = term_score(&hay_l, terms, 2);
    if score == 0 {
        return None;
    }
    Some(SearchHit {
        run_id: run.id.clone(),
        run_label: run_label(run),
        event_id: None,
        sequence: None,
        kind: "run".into(),
        snippet: truncate(&hay, 120),
        score,
        backend: "scan",
    })
}

fn score_event(
    run: &Run,
    ev: &TraceEvent,
    terms: &[&str],
    backend: &'static str,
) -> Option<SearchHit> {
    let mut hay = format!("{} {} {:?} {:?}", ev.kind, ev.id, ev.source, ev.status);
    for (k, v) in &ev.metadata {
        hay.push(' ');
        hay.push_str(k);
        hay.push('=');
        match v {
            serde_json::Value::String(s) => hay.push_str(s),
            other => hay.push_str(&other.to_string()),
        }
    }
    let hay_l = hay.to_lowercase();
    let mut score = term_score(&hay_l, terms, 1);
    if score == 0 {
        return None;
    }
    if ev.kind == "tool.call" || ev.kind == "tool.result" {
        score += 2;
    }
    if matches!(ev.status, crate::core::event::EventStatus::Error) {
        score += 2;
    }
    if ev.kind.contains("error") {
        score += 1;
    }
    let mut hit = event_to_hit(run, ev, backend);
    hit.score = score;
    Some(hit)
}

fn event_to_hit(run: &Run, ev: &TraceEvent, backend: &'static str) -> SearchHit {
    let snippet = ev
        .metadata
        .get("preview")
        .and_then(|v| v.as_str())
        .or_else(|| ev.metadata.get("tool_name").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{} seq={}", ev.kind, ev.sequence));

    SearchHit {
        run_id: run.id.clone(),
        run_label: run_label(run),
        event_id: Some(ev.id.clone()),
        sequence: Some(ev.sequence),
        kind: ev.kind.clone(),
        snippet: truncate(&snippet, 100),
        score: 1,
        backend,
    }
}

fn term_score(hay: &str, terms: &[&str], weight: u32) -> u32 {
    let mut score = 0u32;
    for t in terms {
        if hay.contains(t) {
            score += weight;
        } else {
            return 0;
        }
    }
    score
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.replace('\n', " ");
    if s.len() <= max {
        s
    } else {
        format!("{}…", &s[..s.floor_char_boundary(max)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};
    use crate::storage::sqlite::SqliteStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn finds_tool_by_name_fts() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = Run::new(
            vec!["claude".into(), "-p".into(), "x".into()],
            "/tmp".into(),
        );
        store.insert_run(&run).await.unwrap();
        let mut ev = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
        ev.status = EventStatus::Running;
        ev.metadata
            .insert("tool_name".into(), serde_json::json!("Bash"));
        ev.metadata
            .insert("input".into(), serde_json::json!({"command": "ls src"}));
        store.insert_event(&ev).await.unwrap();

        let hits = search_store(store.as_ref(), "bash", 10, 20).await.unwrap();
        assert!(!hits.is_empty());
        assert!(hits.iter().any(|h| h.kind == "tool.call"));
        // Should prefer FTS on sqlite
        assert!(hits.iter().any(|h| h.backend == "fts5"));
    }
}
