//! Local HTTP dashboard for browsing runs without the TUI.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use crate::export::html::export_html;
use crate::search::search_store;
use crate::storage::sqlite::SqliteStore;
use crate::storage::TraceStore;
use crate::transcript::{rebuild_terminal_transcript, rebuild_tool_transcript};

#[derive(Clone)]
struct AppState {
    store: Arc<SqliteStore>,
}

/// Bind and serve the dashboard until cancelled.
pub async fn serve(store: Arc<SqliteStore>, addr: SocketAddr) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(index))
        .route("/runs/{id}", get(run_page))
        .route("/runs/{id}/export.html", get(run_export_html))
        .route("/api/runs", get(api_runs))
        .route("/api/runs/{id}", get(api_run))
        .route("/api/runs/{id}/events", get(api_events))
        .route("/api/search", get(api_search))
        .route("/search", get(search_page))
        .with_state(AppState { store });

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "blackbox dashboard listening");
    println!("blackbox dashboard → http://{addr}");
    println!("  Press Ctrl+C to stop.");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let runs = state.store.list_runs().await?;
    let mut rows = String::new();
    for run in runs.iter().take(100) {
        let label = run
            .name
            .clone()
            .unwrap_or_else(|| run.command.join(" "));
        let status = format!("{:?}", run.status);
        let tags = if run.tags.is_empty() {
            String::new()
        } else {
            format!(
                "<span class=\"tags\">{}</span>",
                html_escape(&run.tags.join(", "))
            )
        };
        rows.push_str(&format!(
            r#"<tr>
  <td class="mono"><a href="/runs/{id}">{short}</a></td>
  <td><span class="badge">{status}</span></td>
  <td>{exit}</td>
  <td>{label} {tags}</td>
  <td class="muted">{started}</td>
</tr>"#,
            id = urlencoding(&run.id),
            short = html_escape(&run.id[..8.min(run.id.len())]),
            status = html_escape(&status),
            exit = run
                .exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".into()),
            label = html_escape(&label),
            tags = tags,
            started = html_escape(&run.started_at.to_rfc3339()),
        ));
    }

    Ok(Html(shell(
        "Runs",
        &format!(
            r#"<div class="bar">
  <form action="/search" method="get" class="search">
    <input name="q" placeholder="Search tools, kinds, previews…" />
    <button type="submit">Search</button>
  </form>
  <a class="btn" href="/api/runs">JSON API</a>
</div>
<p class="muted">{n} run(s) · store {db}</p>
<table>
  <thead><tr><th>ID</th><th>Status</th><th>Exit</th><th>Label</th><th>Started</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"#,
            n = runs.len(),
            db = html_escape(&state.store.db_path().display().to_string()),
            rows = rows,
        ),
    )))
}

async fn run_page(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    let Some(run) = state.store.get_run(&run_id).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let events = state.store.get_events(&run_id).await?;
    let tools = rebuild_tool_transcript(&events);
    let transcript = rebuild_terminal_transcript(state.store.as_ref(), &events)
        .await
        .unwrap_or_default();

    let mut timeline = String::new();
    for ev in events.iter().filter(|e| {
        !matches!(
            e.kind.as_str(),
            "pty.started"
                | "pty.stopped"
                | "git.observer.started"
                | "git.observer.stopped"
                | "filesystem.observer.started"
                | "filesystem.observer.stopped"
                | "process.observer.started"
                | "process.observer.stopped"
                | "terminal.recording"
        )
    }) {
        let detail = ev
            .metadata
            .get("preview")
            .and_then(|v| v.as_str())
            .or_else(|| ev.metadata.get("tool_name").and_then(|v| v.as_str()))
            .unwrap_or("");
        timeline.push_str(&format!(
            "<tr><td class=\"num\">{seq}</td><td>{src:?}</td><td class=\"mono\">{kind}</td><td>{detail}</td></tr>",
            seq = ev.sequence,
            src = ev.source,
            kind = html_escape(&ev.kind),
            detail = html_escape(&detail.replace('\n', " ")),
        ));
    }

    let body = format!(
        r#"<p><a href="/">← Runs</a> · <a href="/runs/{id}/export.html">Full HTML export</a></p>
<h1>{title}</h1>
<p class="mono muted">{full_id}</p>
<div class="meta">
  <div><b>Status</b> {:?}</div>
  <div><b>Exit</b> {:?}</div>
  <div><b>Command</b> <span class="mono">{}</span></div>
  <div><b>Events</b> {}</div>
  <div><b>Tags</b> {}</div>
</div>
<h2>Tools</h2>
<pre>{}</pre>
<h2>Terminal</h2>
<pre class="term">{}</pre>
<h2>Timeline (semantic)</h2>
<table>
  <thead><tr><th>Seq</th><th>Src</th><th>Kind</th><th>Detail</th></tr></thead>
  <tbody>{}</tbody>
</table>"#,
        run.status,
        run.exit_code,
        html_escape(&run.command.join(" ")),
        events.len(),
        if run.tags.is_empty() {
            "—".into()
        } else {
            html_escape(&run.tags.join(", "))
        },
        html_escape(&tools),
        html_escape(&transcript),
        timeline,
        id = urlencoding(&run_id),
        title = html_escape(run.name.as_deref().unwrap_or("Run")),
        full_id = html_escape(&run_id),
    );

    Ok(Html(shell(&format!("Run {}", &run_id[..8.min(run_id.len())]), &body)).into_response())
}

async fn run_export_html(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    let Some(run) = state.store.get_run(&run_id).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let events = state.store.get_events(&run_id).await?;
    let html = export_html(&run, &events, true)?;
    Ok(Html(html).into_response())
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
}

async fn search_page(
    State(state): State<AppState>,
    Query(q): Query<SearchQuery>,
) -> Result<Html<String>, AppError> {
    let query = q.q.unwrap_or_default();
    if query.trim().is_empty() {
        return Ok(Html(shell(
            "Search",
            r#"<form action="/search" method="get"><input name="q" placeholder="Query…" autofocus><button>Search</button></form>"#,
        )));
    }
    let hits = search_store(state.store.as_ref(), &query, 50, 40).await?;
    let mut rows = String::new();
    for h in &hits {
        let link = if let Some(ref eid) = h.event_id {
            format!(
                "<a href=\"/runs/{}\">{}</a> · seq {:?}",
                urlencoding(&h.run_id),
                html_escape(&h.run_id[..8.min(h.run_id.len())]),
                h.sequence
            )
        } else {
            format!(
                "<a href=\"/runs/{}\">{}</a>",
                urlencoding(&h.run_id),
                html_escape(&h.run_id[..8.min(h.run_id.len())])
            )
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td class=\"muted\">{}</td></tr>",
            link,
            h.score,
            html_escape(&h.kind),
            html_escape(&h.snippet),
            h.backend,
        ));
    }
    Ok(Html(shell(
        "Search",
        &format!(
            r#"<form action="/search" method="get"><input name="q" value="{q}"><button>Search</button></form>
<p class="muted">{n} hit(s)</p>
<table><thead><tr><th>Run</th><th>Score</th><th>Kind</th><th>Snippet</th><th>Backend</th></tr></thead>
<tbody>{rows}</tbody></table>"#,
            q = html_escape(&query),
            n = hits.len(),
            rows = rows,
        ),
    )))
}

async fn api_runs(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let runs = state.store.list_runs().await?;
    Ok(Json(serde_json::to_value(runs)?))
}

async fn api_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    match state.store.get_run(&run_id).await? {
        Some(run) => Ok(Json(serde_json::to_value(run)?).into_response()),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

async fn api_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    let events = state.store.get_events(&run_id).await?;
    Ok(Json(serde_json::to_value(events)?).into_response())
}

async fn api_search(
    State(state): State<AppState>,
    Query(q): Query<SearchQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let query = q.q.unwrap_or_default();
    let hits = search_store(state.store.as_ref(), &query, 50, 40).await?;
    let json: Vec<serde_json::Value> = hits
        .into_iter()
        .map(|h| {
            serde_json::json!({
                "run_id": h.run_id,
                "event_id": h.event_id,
                "sequence": h.sequence,
                "kind": h.kind,
                "snippet": h.snippet,
                "score": h.score,
                "backend": h.backend,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "hits": json })))
}

async fn resolve_prefix(store: &dyn TraceStore, spec: &str) -> anyhow::Result<String> {
    if spec == "latest" {
        return store
            .list_runs()
            .await?
            .first()
            .map(|r| r.id.clone())
            .ok_or_else(|| anyhow::anyhow!("no runs"));
    }
    if store.get_run(spec).await?.is_some() {
        return Ok(spec.to_string());
    }
    let runs = store.list_runs().await?;
    let matches: Vec<_> = runs
        .into_iter()
        .filter(|r| r.id.starts_with(spec))
        .map(|r| r.id)
        .collect();
    match matches.len() {
        1 => Ok(matches[0].clone()),
        0 => Err(anyhow::anyhow!("run not found: {spec}")),
        _ => Err(anyhow::anyhow!("ambiguous run id: {spec}")),
    }
}

fn shell(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>blackbox · {title}</title>
<style>
:root {{ --bg:#0b0f14; --card:#121820; --fg:#e5e7eb; --muted:#9ca3af; --border:#1f2937; --accent:#60a5fa; }}
@media (prefers-color-scheme: light) {{
  :root {{ --bg:#f6f7f9; --card:#fff; --fg:#111827; --muted:#6b7280; --border:#e5e7eb; --accent:#2563eb; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:ui-sans-serif,system-ui,sans-serif; background:var(--bg); color:var(--fg); padding:1.25rem clamp(1rem,3vw,2rem); line-height:1.5; }}
a {{ color:var(--accent); text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
h1 {{ font-size:1.35rem; margin:0.4rem 0; }}
h2 {{ font-size:1.05rem; margin:1.4rem 0 0.5rem; }}
table {{ width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--border); border-radius:10px; overflow:hidden; font-size:0.9rem; }}
th,td {{ padding:0.45rem 0.65rem; border-bottom:1px solid var(--border); text-align:left; vertical-align:top; }}
th {{ color:var(--muted); font-size:0.75rem; text-transform:uppercase; letter-spacing:0.04em; }}
.mono {{ font-family:ui-monospace,Menlo,monospace; font-size:0.85rem; }}
.muted {{ color:var(--muted); }}
.num {{ font-family:ui-monospace,Menlo,monospace; text-align:right; }}
.badge {{ display:inline-block; padding:0.1em 0.45em; border-radius:4px; background:color-mix(in srgb,var(--accent) 18%,transparent); font-size:0.8rem; }}
.tags {{ color:var(--muted); font-size:0.8rem; margin-left:0.4rem; }}
pre {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:0.85rem 1rem; overflow:auto; font-size:0.82rem; white-space:pre-wrap; }}
pre.term {{ max-height:22rem; }}
.meta {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:0.6rem; background:var(--card); border:1px solid var(--border); border-radius:10px; padding:0.85rem; margin:0.75rem 0; }}
.bar {{ display:flex; gap:0.75rem; flex-wrap:wrap; align-items:center; margin-bottom:0.75rem; }}
.search {{ display:flex; gap:0.4rem; flex:1; min-width:220px; }}
input {{ flex:1; background:var(--card); color:var(--fg); border:1px solid var(--border); border-radius:8px; padding:0.45rem 0.65rem; }}
button,.btn {{ background:var(--accent); color:#fff; border:0; border-radius:8px; padding:0.45rem 0.8rem; cursor:pointer; font-weight:600; }}
</style>
</head>
<body>
<header class="bar"><strong><a href="/">blackbox</a></strong> <span class="muted">local dashboard</span></header>
{body}
</body>
</html>"#,
        title = html_escape(title),
        body = body,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn urlencoding(s: &str) -> String {
    // IDs are UUID-safe; keep simple
    s.to_string()
}

struct AppError(anyhow::Error);

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        Self(e)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        Self(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("error: {}", self.0),
        )
            .into_response()
    }
}

