//! Local HTTP dashboard with live SSE event streams.

use std::collections::{HashSet, VecDeque};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::stream::{self, Stream};
use serde::Deserialize;

use crate::export::html::export_html;
use crate::search::search_store;
use crate::storage::sqlite::SqliteStore;
use crate::storage::TraceStore;
use crate::transcript::{rebuild_terminal_transcript, rebuild_tool_transcript};

#[derive(Clone)]
struct AppState {
    store: Arc<SqliteStore>,
    /// Optional shared secret. When set, all routes require it.
    token: Option<String>,
}

/// Dashboard configuration.
pub struct ServeOptions {
    pub addr: SocketAddr,
    pub token: Option<String>,
    pub reindex: bool,
}

/// Bind and serve the dashboard until cancelled.
pub async fn serve(store: Arc<SqliteStore>, opts: ServeOptions) -> anyhow::Result<()> {
    if opts.reindex {
        let n = store.reindex_fts()?;
        println!("Reindexed FTS ({n} events)");
    }

    let state = AppState {
        store,
        token: opts.token.clone(),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/runs/{id}", get(run_page))
        .route("/runs/{id}/live", get(run_live_page))
        .route("/runs/{id}/export.html", get(run_export_html))
        .route("/watch", get(watch_latest_page))
        .route("/api/runs", get(api_runs))
        .route("/api/runs/stream", get(api_runs_stream))
        .route("/api/runs/{id}", get(api_run))
        .route("/api/runs/{id}/events", get(api_events))
        .route("/api/runs/{id}/events/stream", get(api_event_stream))
        .route("/api/search", get(api_search))
        .route("/search", get(search_page))
        .layer(from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(opts.addr).await?;
    tracing::info!(addr = %opts.addr, auth = opts.token.is_some(), "dashboard listening");
    println!("blackbox dashboard → http://{}", opts.addr);
    if opts.token.is_some() {
        println!("  auth:    Bearer token required (Authorization header or ?token=)");
    }
    println!("  live:    http://{}/watch", opts.addr);
    println!("  api:     http://{}/api/runs", opts.addr);
    println!("  Press Ctrl+C to stop.");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(ref expected) = state.token else {
        return next.run(request).await;
    };

    if token_ok(expected, request.headers(), request.uri().query()) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "unauthorized: pass Authorization: Bearer <token> or ?token=",
        )
            .into_response()
    }
}

fn token_ok(expected: &str, headers: &HeaderMap, query: Option<&str>) -> bool {
    if let Some(auth) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if auth == expected || auth == format!("Bearer {expected}") {
            return true;
        }
    }
    if let Some(q) = query {
        for pair in q.split('&') {
            if let Some(v) = pair.strip_prefix("token=") {
                if v == expected {
                    return true;
                }
            }
        }
    }
    false
}

// ── Pages ─────────────────────────────────────────────────────────

async fn index(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let runs = state.store.list_runs().await?;
    let mut rows = String::new();
    for run in runs.iter().take(100) {
        rows.push_str(&run_row_html(run));
    }

    Ok(Html(shell(
        "Runs",
        &format!(
            r#"<div class="bar">
  <form action="/search" method="get" class="search">
    <input name="q" placeholder="Search tools, kinds, previews…" />
    <button type="submit">Search</button>
  </form>
  <a class="btn" href="/watch">Live watch</a>
  <a class="btn secondary" href="/api/runs">JSON API</a>
  <span class="muted" id="stream">live list: connecting…</span>
</div>
<p class="muted"><span id="count">{n}</span> run(s) · store {db}</p>
<table>
  <thead><tr><th>ID</th><th>Status</th><th>Exit</th><th>Label</th><th>Started</th></tr></thead>
  <tbody id="runs">{rows}</tbody>
</table>
<script>
const tbody = document.getElementById('runs');
const countEl = document.getElementById('count');
const streamEl = document.getElementById('stream');
const rows = new Map();
// seed from initial DOM
for (const tr of tbody.querySelectorAll('tr[data-id]')) {{
  rows.set(tr.dataset.id, tr);
}}
function upsert(run) {{
  const id = run.id;
  const short = id.slice(0, 8);
  const label = run.name || (run.command || []).join(' ');
  const status = run.status || '?';
  const exit = run.exit_code == null ? '-' : String(run.exit_code);
  const started = run.started_at || '';
  const tags = (run.tags && run.tags.length) ? `<span class="tags">${{run.tags.join(', ')}}</span>` : '';
  let tr = rows.get(id);
  if (!tr) {{
    tr = document.createElement('tr');
    tr.dataset.id = id;
    tbody.insertBefore(tr, tbody.firstChild);
    rows.set(id, tr);
    countEl.textContent = String(rows.size);
    tr.classList.add('flash');
  }}
  tr.innerHTML = `<td class="mono"><a href="/runs/${{id}}">${{short}}</a></td>
<td><span class="badge">${{status}}</span> <a class="muted" href="/runs/${{id}}/live">live</a></td>
<td>${{exit}}</td><td></td><td class="muted">${{started}}</td>`;
  tr.children[3].textContent = label + ' ';
  if (tags) tr.children[3].insertAdjacentHTML('beforeend', tags);
}}
const qs = new URLSearchParams(location.search);
const token = qs.get('token');
const url = '/api/runs/stream' + (token ? ('?token=' + encodeURIComponent(token)) : '');
const es = new EventSource(url);
es.addEventListener('run', (e) => {{ try {{ upsert(JSON.parse(e.data)); }} catch(_){{}} }});
es.addEventListener('open', () => {{ streamEl.textContent = 'live list: connected'; }});
es.onerror = () => {{ streamEl.textContent = 'live list: reconnecting…'; }};
</script>
<style>.flash {{ animation: flash 1.2s ease; }} @keyframes flash {{ from {{ background: color-mix(in srgb, var(--accent) 35%, transparent); }} to {{ background: transparent; }} }}</style>"#,
            n = runs.len(),
            db = html_escape(&state.store.db_path().display().to_string()),
            rows = rows,
        ),
    )))
}

fn run_row_html(run: &crate::core::run::Run) -> String {
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
    format!(
        r#"<tr data-id="{id}">
  <td class="mono"><a href="/runs/{id}">{short}</a></td>
  <td><span class="badge">{status}</span> <a class="muted" href="/runs/{id}/live">live</a></td>
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
    )
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
    for ev in events.iter().filter(|e| !is_bookkeeping(&e.kind)) {
        timeline.push_str(&event_row_html(ev));
    }

    let body = format!(
        r#"<p><a href="/">← Runs</a> · <a href="/runs/{id}/live">Live view</a> · <a href="/runs/{id}/export.html">Full HTML export</a></p>
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

    Ok(Html(shell(
        &format!("Run {}", &run_id[..8.min(run_id.len())]),
        &body,
    ))
    .into_response())
}

/// Live-updating run page powered by SSE.
async fn run_live_page(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    let Some(run) = state.store.get_run(&run_id).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let label = run
        .name
        .clone()
        .unwrap_or_else(|| run.command.join(" "));

    let body = format!(
        r#"<p><a href="/">← Runs</a> · <a href="/runs/{id}">Static view</a></p>
<h1>Live · {title}</h1>
<p class="mono muted">{full_id}</p>
<div class="meta">
  <div><b>Status</b> <span id="status">{status:?}</span></div>
  <div><b>Events</b> <span id="count">0</span></div>
  <div><b>Stream</b> <span id="stream" class="muted">connecting…</span></div>
</div>
<div class="bar">
  <label><input type="checkbox" id="semantic" checked> semantic only</label>
  <button type="button" id="clear" class="secondary">Clear</button>
</div>
<table>
  <thead><tr><th>Seq</th><th>Src</th><th>Kind</th><th>Detail</th></tr></thead>
  <tbody id="tl"></tbody>
</table>
<script>
const runId = {run_id_js};
const tl = document.getElementById('tl');
const countEl = document.getElementById('count');
const statusEl = document.getElementById('status');
const streamEl = document.getElementById('stream');
const semantic = document.getElementById('semantic');
const bookkeeping = new Set([
  'pty.started','pty.stopped','git.observer.started','git.observer.stopped',
  'filesystem.observer.started','filesystem.observer.stopped',
  'process.observer.started','process.observer.stopped','terminal.recording',
  'git.commit','git.commit.after'
]);
let n = 0;
function detail(ev) {{
  const m = ev.metadata || {{}};
  return (m.preview || m.tool_name || m.path || (m.exit_code != null ? 'exit='+m.exit_code : '') || '').toString().replace(/\n/g,'⏎');
}}
function add(ev) {{
  if (semantic.checked && bookkeeping.has(ev.kind)) return;
  const tr = document.createElement('tr');
  if (ev.kind && ev.kind.startsWith('tool.')) tr.className = 'row-tool';
  if (ev.status === 'Error') tr.className = 'row-error';
  tr.innerHTML = `<td class="num">${{ev.sequence}}</td><td>${{ev.source}}</td><td class="mono">${{ev.kind}}</td><td class="detail"></td>`;
  tr.querySelector('.detail').textContent = detail(ev);
  tl.appendChild(tr);
  n++;
  countEl.textContent = String(n);
  tr.scrollIntoView({{block:'nearest'}});
}}
const qs = new URLSearchParams(location.search);
const token = qs.get('token');
const url = `/api/runs/${{encodeURIComponent(runId)}}/events/stream` + (token ? `?token=${{encodeURIComponent(token)}}` : '');
const es = new EventSource(url);
es.addEventListener('event', (e) => {{
  try {{ add(JSON.parse(e.data)); }} catch (_) {{}}
}});
es.addEventListener('status', (e) => {{
  try {{
    const s = JSON.parse(e.data);
    statusEl.textContent = s.status || statusEl.textContent;
    if (s.exit_code != null) statusEl.textContent += ' exit=' + s.exit_code;
  }} catch (_) {{}}
}});
es.addEventListener('open', () => {{ streamEl.textContent = 'connected'; }});
es.onerror = () => {{ streamEl.textContent = 'reconnecting…'; }};
document.getElementById('clear').onclick = () => {{ tl.innerHTML=''; n=0; countEl.textContent='0'; }};
</script>"#,
        id = urlencoding(&run_id),
        title = html_escape(&label),
        full_id = html_escape(&run_id),
        status = run.status,
        run_id_js = serde_json::to_string(&run_id).unwrap_or_else(|_| "\"\"".into()),
    );

    Ok(Html(shell("Live run", &body)).into_response())
}

async fn watch_latest_page(State(state): State<AppState>) -> Result<Response, AppError> {
    let runs = state.store.list_runs().await?;
    let Some(run) = runs.first() else {
        return Ok(Html(shell(
            "Watch",
            r#"<p class="muted">No runs yet. <code>blackbox run -- echo hi</code></p>"#,
        ))
        .into_response());
    };
    // Redirect-style: serve live page for latest
    Ok(axum::response::Redirect::temporary(&format!(
        "/runs/{}/live",
        urlencoding(&run.id)
    ))
    .into_response())
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
            r#"<form action="/search" method="get" class="search"><input name="q" placeholder="Query…" autofocus><button>Search</button></form>"#,
        )));
    }
    let hits = search_store(state.store.as_ref(), &query, 50, 40).await?;
    let mut rows = String::new();
    for h in &hits {
        let link = format!(
            "<a href=\"/runs/{}\">{}</a>{}",
            urlencoding(&h.run_id),
            html_escape(&h.run_id[..8.min(h.run_id.len())]),
            h.sequence
                .map(|s| format!(" · seq {s}"))
                .unwrap_or_default()
        );
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
            r#"<form action="/search" method="get" class="search"><input name="q" value="{q}"><button>Search</button></form>
<p class="muted">{n} hit(s)</p>
<table><thead><tr><th>Run</th><th>Score</th><th>Kind</th><th>Snippet</th><th>Backend</th></tr></thead>
<tbody>{rows}</tbody></table>"#,
            q = html_escape(&query),
            n = hits.len(),
            rows = rows,
        ),
    )))
}

// ── JSON / SSE API ────────────────────────────────────────────────

async fn api_runs(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let runs = state.store.list_runs().await?;
    Ok(Json(serde_json::to_value(runs)?))
}

/// SSE stream of run snapshots (initial + updates / new runs).
async fn api_runs_stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let store = state.store.clone();
    let stream = stream::unfold(
        RunsStreamState {
            store,
            known: std::collections::HashMap::new(),
            bootstrapped: false,
        },
        |mut st| async move {
            let runs = match st.store.list_runs().await {
                Ok(r) => r,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(800)).await;
                    return Some((Ok(Event::default().event("ping").data("ok")), st));
                }
            };

            for run in runs.iter().take(100) {
                let fingerprint = format!(
                    "{:?}|{:?}|{}",
                    run.status,
                    run.exit_code,
                    run.tags.join(",")
                );
                let changed = st
                    .known
                    .get(&run.id)
                    .map(|f| f != &fingerprint)
                    .unwrap_or(true);
                if changed {
                    st.known.insert(run.id.clone(), fingerprint);
                    if let Ok(data) = serde_json::to_string(run) {
                        // One SSE frame per tick; remaining changes flush next poll.
                        return Some((Ok(Event::default().event("run").data(data)), st));
                    }
                }
            }

            st.bootstrapped = true;
            tokio::time::sleep(Duration::from_millis(750)).await;
            Some((Ok(Event::default().event("ping").data("ok")), st))
        },
    );
    Sse::new(stream).keep_alive(KeepAlive::default())
}

struct RunsStreamState {
    store: Arc<SqliteStore>,
    known: std::collections::HashMap<String, String>,
    #[allow(dead_code)]
    bootstrapped: bool,
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

/// Server-Sent Events stream of run events (historical first, then live tail).
async fn api_event_stream(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    let store = state.store.clone();

    let stream = stream::unfold(
        StreamState {
            store,
            run_id,
            seen: HashSet::new(),
            queue: VecDeque::new(),
            ticks_idle: 0,
            finished: false,
        },
        |mut st| async move {
            // Drain queued events first
            if let Some(ev) = st.queue.pop_front() {
                return Some((Ok(ev), st));
            }

            // Load new events from store
            if let Ok(events) = st.store.get_events(&st.run_id).await {
                for e in events {
                    if st.seen.insert(e.id.clone()) {
                        if let Ok(data) = serde_json::to_string(&e) {
                            st.queue
                                .push_back(Event::default().event("event").data(data));
                        }
                    }
                }
            }

            // Status snapshot occasionally
            if let Ok(Some(run)) = st.store.get_run(&st.run_id).await {
                let finished = !matches!(
                    run.status,
                    crate::core::run::RunStatus::Running | crate::core::run::RunStatus::Pending
                );
                let data = serde_json::json!({
                    "status": format!("{:?}", run.status),
                    "exit_code": run.exit_code,
                });
                if finished && !st.finished {
                    st.finished = true;
                    st.queue.push_back(
                        Event::default()
                            .event("status")
                            .data(data.to_string()),
                    );
                } else if st.ticks_idle % 5 == 0 {
                    st.queue.push_back(
                        Event::default()
                            .event("status")
                            .data(data.to_string()),
                    );
                }
                if finished {
                    st.ticks_idle += 1;
                } else {
                    st.ticks_idle = 0;
                }
            }

            if let Some(ev) = st.queue.pop_front() {
                return Some((Ok(ev), st));
            }

            // Stop after run finished + ~15s idle (no new events)
            if st.finished && st.ticks_idle > 30 {
                return None;
            }

            tokio::time::sleep(Duration::from_millis(400)).await;
            st.ticks_idle += 1;
            // heartbeat comment via empty data event name "ping"
            Some((
                Ok(Event::default().event("ping").data("ok")),
                st,
            ))
        },
    );

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

struct StreamState {
    store: Arc<SqliteStore>,
    run_id: String,
    seen: HashSet<String>,
    queue: VecDeque<Event>,
    ticks_idle: u32,
    finished: bool,
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

// ── Helpers ───────────────────────────────────────────────────────

fn is_bookkeeping(kind: &str) -> bool {
    matches!(
        kind,
        "pty.started"
            | "pty.stopped"
            | "git.observer.started"
            | "git.observer.stopped"
            | "filesystem.observer.started"
            | "filesystem.observer.stopped"
            | "process.observer.started"
            | "process.observer.stopped"
            | "terminal.recording"
            | "git.commit"
            | "git.commit.after"
    )
}

fn event_row_html(ev: &crate::core::event::TraceEvent) -> String {
    let detail = ev
        .metadata
        .get("preview")
        .and_then(|v| v.as_str())
        .or_else(|| ev.metadata.get("tool_name").and_then(|v| v.as_str()))
        .unwrap_or("");
    format!(
        "<tr><td class=\"num\">{seq}</td><td>{src:?}</td><td class=\"mono\">{kind}</td><td>{detail}</td></tr>",
        seq = ev.sequence,
        src = ev.source,
        kind = html_escape(&ev.kind),
        detail = html_escape(&detail.replace('\n', " ")),
    )
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
:root {{ --bg:#0b0f14; --card:#121820; --fg:#e5e7eb; --muted:#9ca3af; --border:#1f2937; --accent:#60a5fa; --tool:#0f1c2e; --err:#2a1215; }}
@media (prefers-color-scheme: light) {{
  :root {{ --bg:#f6f7f9; --card:#fff; --fg:#111827; --muted:#6b7280; --border:#e5e7eb; --accent:#2563eb; --tool:#eff6ff; --err:#fef2f2; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:ui-sans-serif,system-ui,sans-serif; background:var(--bg); color:var(--fg); padding:1.25rem clamp(1rem,3vw,2rem); line-height:1.5; }}
a {{ color:var(--accent); text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
h1 {{ font-size:1.35rem; margin:0.4rem 0; }}
h2 {{ font-size:1.05rem; margin:1.4rem 0 0.5rem; }}
table {{ width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--border); border-radius:10px; overflow:hidden; font-size:0.9rem; }}
th,td {{ padding:0.45rem 0.65rem; border-bottom:1px solid var(--border); text-align:left; vertical-align:top; }}
th {{ color:var(--muted); font-size:0.75rem; text-transform:uppercase; letter-spacing:0.04em; position:sticky; top:0; background:var(--card); }}
.mono {{ font-family:ui-monospace,Menlo,monospace; font-size:0.85rem; }}
.muted {{ color:var(--muted); }}
.num {{ font-family:ui-monospace,Menlo,monospace; text-align:right; }}
.detail {{ color:var(--muted); max-width:32rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.badge {{ display:inline-block; padding:0.1em 0.45em; border-radius:4px; background:color-mix(in srgb,var(--accent) 18%,transparent); font-size:0.8rem; }}
.tags {{ color:var(--muted); font-size:0.8rem; margin-left:0.4rem; }}
.row-tool {{ background:var(--tool); }}
.row-error {{ background:var(--err); }}
pre {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:0.85rem 1rem; overflow:auto; font-size:0.82rem; white-space:pre-wrap; }}
pre.term {{ max-height:22rem; }}
.meta {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:0.6rem; background:var(--card); border:1px solid var(--border); border-radius:10px; padding:0.85rem; margin:0.75rem 0; }}
.bar {{ display:flex; gap:0.75rem; flex-wrap:wrap; align-items:center; margin-bottom:0.75rem; }}
.search {{ display:flex; gap:0.4rem; flex:1; min-width:220px; }}
input[type=text],input:not([type]),input[type=search] {{ flex:1; background:var(--card); color:var(--fg); border:1px solid var(--border); border-radius:8px; padding:0.45rem 0.65rem; }}
button,.btn {{ background:var(--accent); color:#fff; border:0; border-radius:8px; padding:0.45rem 0.8rem; cursor:pointer; font-weight:600; text-decoration:none; display:inline-block; }}
.btn.secondary,button.secondary {{ background:transparent; color:var(--accent); border:1px solid var(--border); }}
label {{ font-size:0.9rem; color:var(--muted); }}
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
