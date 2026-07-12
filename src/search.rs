//! Full-text-ish search across runs and events.

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
}

/// Search runs + events for a case-insensitive query.
///
/// Scans up to `max_runs` most recent runs. Scores higher when the query
/// matches tool names, kinds, or multiple fields.
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

    for run in runs.into_iter().take(max_runs) {
        // Run-level hits
        if let Some(hit) = score_run(&run, &terms) {
            hits.push(hit);
        }

        let events = store.get_events(&run.id).await?;
        for ev in events {
            if let Some(hit) = score_event(&run, &ev, &terms) {
                hits.push(hit);
            }
        }
    }

    hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| b.run_id.cmp(&a.run_id)));
    hits.truncate(limit);
    Ok(hits)
}

fn run_label(run: &Run) -> String {
    run.name
        .clone()
        .unwrap_or_else(|| run.command.join(" "))
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
    })
}

fn score_event(run: &Run, ev: &TraceEvent, terms: &[&str]) -> Option<SearchHit> {
    let mut hay = format!(
        "{} {} {:?} {:?}",
        ev.kind, ev.id, ev.source, ev.status
    );
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
    // Boost tool / error hits
    if ev.kind == "tool.call" || ev.kind == "tool.result" {
        score += 2;
    }
    if matches!(ev.status, crate::core::event::EventStatus::Error) {
        score += 2;
    }
    if ev.kind.contains("error") {
        score += 1;
    }

    let snippet = ev
        .metadata
        .get("preview")
        .and_then(|v| v.as_str())
        .or_else(|| {
            ev.metadata
                .get("tool_name")
                .and_then(|v| v.as_str())
        })
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{} seq={}", ev.kind, ev.sequence));

    Some(SearchHit {
        run_id: run.id.clone(),
        run_label: run_label(run),
        event_id: Some(ev.id.clone()),
        sequence: Some(ev.sequence),
        kind: ev.kind.clone(),
        snippet: truncate(&snippet, 100),
        score,
    })
}

fn term_score(hay: &str, terms: &[&str], weight: u32) -> u32 {
    let mut score = 0u32;
    for t in terms {
        if hay.contains(t) {
            score += weight;
        } else {
            return 0; // require all terms
        }
    }
    score
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.replace('\n', " ");
    if s.len() <= max {
        s
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};
    use crate::storage::sqlite::SqliteStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn finds_tool_by_name() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let run = Run::new(vec!["claude".into(), "-p".into(), "x".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let mut ev = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
        ev.status = EventStatus::Running;
        ev.metadata
            .insert("tool_name".into(), serde_json::json!("Bash"));
        ev.metadata.insert(
            "input".into(),
            serde_json::json!({"command": "ls src"}),
        );
        store.insert_event(&ev).await.unwrap();

        let hits = search_store(store.as_ref(), "bash", 10, 20).await.unwrap();
        assert!(!hits.is_empty());
        assert!(hits.iter().any(|h| h.kind == "tool.call"));
    }
}
