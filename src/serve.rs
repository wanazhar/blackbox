//! Local HTTP dashboard with live SSE event streams.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::export::portable::import_portable;
use crate::export::{export_html_secure, export_portable_secure};
use crate::search::search_store;
use crate::storage::sqlite::SqliteStore;
use crate::storage::TraceStore;
use crate::sync::manifest_from_store;
use crate::transcript::{rebuild_terminal_transcript, rebuild_tool_transcript};
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use futures_util::stream::{self, Stream};
use parking_lot::Mutex;
use serde::Deserialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Browser session cookie name (HttpOnly; not readable by JS).
pub const SESSION_COOKIE: &str = "blackbox_session";
/// Default browser session TTL.
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
/// Failed login attempts retained for rate limiting.
const LOGIN_FAIL_WINDOW: Duration = Duration::from_secs(60);
/// Max failed POSTs /session in the window before 429.
const LOGIN_FAIL_MAX: usize = 20;
/// Hard cap for `GET /api/runs/{id}/events` (no unlimited dumps).
const API_EVENTS_HARD_CAP: usize = 50_000;

#[derive(Clone)]
struct AppState {
    store: Arc<SqliteStore>,
    /// Optional shared secret. When set, all routes require it.
    token: Option<String>,
    /// Semaphore limiting concurrent SSE streams (max 100).
    sse_semaphore: Arc<Semaphore>,
    /// Server-side browser sessions (id → expiry).
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
    /// Failed login timestamps (sliding window rate limit).
    login_failures: Arc<Mutex<Vec<Instant>>>,
    /// Set Secure flag on session cookies (TLS / explicit).
    secure_cookies: bool,
}

/// Dashboard configuration.
pub struct ServeOptions {
    /// Addr.
    pub addr: SocketAddr,
    /// Token.
    pub token: Option<String>,
    /// Reindex.
    pub reindex: bool,
    /// Optional Unix domain socket path (restrictive mode/ownership).
    pub unix_socket: Option<PathBuf>,
    /// Force Secure cookie flag (also implied for non-loopback binds).
    pub secure_cookies: bool,
    /// Danger: allow unauthenticated access on loopback/unix only.
    /// Default is **false** — when no token is supplied, one is auto-generated.
    pub allow_anonymous: bool,
}

/// Bind and serve the dashboard until cancelled.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `serve` — see module docs for full workflow.
/// ```
pub async fn serve(store: Arc<SqliteStore>, opts: ServeOptions) -> anyhow::Result<()> {
    let is_loopback = crate::privacy::is_loopback_addr(&opts.addr);
    let on_unix = opts.unix_socket.is_some();

    // Resolve auth: explicit token → auto-generate → (danger) allow anonymous.
    let mut token = opts.token.clone();
    let mut auto_generated = false;
    if token.as_ref().is_some_and(|t| t.is_empty()) {
        token = None;
    }
    if token.is_none() {
        if opts.allow_anonymous {
            if !is_loopback && !on_unix {
                anyhow::bail!(
                    "refusing --allow-anonymous on non-loopback address {}. \
                     Use --token / BLACKBOX_SERVE_TOKEN, or bind 127.0.0.1.",
                    opts.addr
                );
            }
        } else {
            // Fail-closed default: never serve history without a shared secret.
            token = Some(uuid::Uuid::new_v4().simple().to_string());
            auto_generated = true;
        }
    }

    // Privacy: non-loopback bind still requires a token (auto or explicit).
    if !is_loopback && !on_unix && token.is_none() {
        anyhow::bail!(
            "refusing to serve on non-loopback address {} without authentication. \
             Set --token or BLACKBOX_SERVE_TOKEN (or bind 127.0.0.1).",
            opts.addr
        );
    }

    if opts.reindex {
        let n = store.reindex_fts()?;
        println!("Reindexed FTS ({n} events)");
    }

    let secure_cookies = opts.secure_cookies || !is_loopback;
    let state = AppState {
        store,
        token: token.clone(),
        sse_semaphore: Arc::new(Semaphore::new(100)),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        login_failures: Arc::new(Mutex::new(Vec::new())),
        secure_cookies,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/login", get(login_page))
        .route("/session", post(create_session))
        .route("/logout", post(logout_session))
        .route("/runs/{id}", get(run_page))
        .route("/runs/{id}/live", get(run_live_page))
        .route("/runs/{id}/export.html", get(run_export_html))
        .route("/incidents", get(incidents_page))
        .route("/incidents/{id}", get(incident_page))
        .route("/watch", get(watch_latest_page))
        .route("/status", get(status_page))
        .route("/handoff", get(handoff_page))
        .route("/api/runs", get(api_runs))
        .route("/api/runs/stream", get(api_runs_stream))
        .route("/api/runs/{id}", get(api_run))
        .route("/api/runs/{id}/events", get(api_events))
        .route("/api/runs/{id}/events/page", get(api_events_page))
        .route("/api/runs/{id}/events/stream", get(api_event_stream))
        .route("/api/runs/{id}/anomalies", get(api_anomalies))
        .route("/api/runs/{id}/boundary", get(api_run_boundary))
        .route("/api/runs/{id}/findings", get(api_run_findings))
        .route("/api/runs/{id}/evidence", get(api_run_evidence))
        .route("/api/incidents", get(api_incidents))
        .route("/api/incidents/{id}", get(api_incident))
        .route("/api/search", get(api_search))
        .route("/api/status", get(api_status))
        .route("/api/handoff", get(api_handoff))
        .route("/api/sync/manifest", get(api_sync_manifest))
        .route(
            "/api/sync/runs/{id}",
            get(api_sync_get_run).put(api_sync_put_run),
        )
        .route("/search", get(search_page))
        .layer(from_fn_with_state(state.clone(), auth_middleware))
        .layer(from_fn_with_state(state.clone(), timeout_middleware))
        .with_state(state);

    if let Some(ref sock_path) = opts.unix_socket {
        return serve_unix(app, sock_path).await;
    }

    let listener = tokio::net::TcpListener::bind(opts.addr).await?;
    tracing::info!(addr = %opts.addr, auth = token.is_some(), "dashboard listening");
    println!("blackbox dashboard → http://{}", opts.addr);
    if let Some(ref t) = token {
        if auto_generated {
            println!("  token:   {t}  (auto-generated; not stored — pass --token next time)");
            println!("  note:    set BLACKBOX_SERVE_TOKEN or --token to pin the secret");
            println!("  danger:  --allow-anonymous opts out of auth on loopback only");
        }
        println!(
            "  auth:    browser → GET /login then session cookie; API → Authorization: Bearer"
        );
        println!("  login:   http://{}/login", opts.addr);
    } else {
        eprintln!(
            "WARNING: dashboard is running WITHOUT authentication (--allow-anonymous) — \
             any local user can curl http://{} and read full run history.",
            opts.addr
        );
    }
    println!("  live:    http://{}/watch", opts.addr);
    println!("  status:  http://{}/status", opts.addr);
    println!("  handoff: http://{}/handoff", opts.addr);
    println!(
        "  api:     http://{}/api/runs  ·  /api/runs/{{id}}/anomalies  ·  /api/status",
        opts.addr
    );
    println!("  sync:    http://{}/api/sync/manifest", opts.addr);
    println!("  Press Ctrl+C to stop.");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Serve over a Unix domain socket with restrictive permissions (1.5 H1).
async fn serve_unix(app: Router, sock_path: &std::path::Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if sock_path.exists() {
            let _ = std::fs::remove_file(sock_path);
        }
        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent)?;
            crate::privacy::restrict_dir(parent);
        }
        let listener = tokio::net::UnixListener::bind(sock_path)?;
        // Owner read/write only (0600).
        std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600))?;
        crate::privacy::restrict_file(sock_path);
        println!(
            "blackbox dashboard → unix:{} (mode 0600)",
            sock_path.display()
        );
        println!("  Press Ctrl+C to stop.");
        // axum 0.8: serve with into_make_service via hyper unix — use
        // axum::serve with UnixListener when available.
        axum::serve(listener, app).await?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = app;
        anyhow::bail!(
            "Unix domain sockets are not supported on this platform ({})",
            sock_path.display()
        );
    }
}

async fn auth_middleware(State(state): State<AppState>, request: Request, next: Next) -> Response {
    // Public auth endpoints when token protection is enabled.
    let path = request.uri().path();
    let method = request.method().clone();
    let public = matches!(
        (method.as_str(), path),
        ("GET", "/login") | ("POST", "/session")
    );

    let mut response = if let Some(expected) = &state.token {
        if public || authorized(&state, expected, request.headers()) {
            next.run(request).await
        } else {
            let wants_html = request
                .headers()
                .get(header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.contains("text/html"))
                .unwrap_or(false)
                && method == Method::GET
                && !path.starts_with("/api/");
            if wants_html {
                Redirect::temporary("/login").into_response()
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Bearer")],
                    "Unauthorized",
                )
                    .into_response()
            }
        }
    } else {
        next.run(request).await
    };

    let headers = response.headers_mut();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    headers.insert(
        header::CACHE_CONTROL,
        "no-store, no-cache, must-revalidate".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'".parse().unwrap(),
    );
    response
}

/// Per-request timeout middleware (30 seconds).
async fn timeout_middleware(
    State(_state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    match tokio::time::timeout(Duration::from_secs(30), next.run(request)).await {
        Ok(response) => response,
        Err(_) => (StatusCode::REQUEST_TIMEOUT, "request timed out").into_response(),
    }
}

/// Authenticate via `Authorization: Bearer` **or** HttpOnly session cookie.
///
/// Query `?token=` is **not** accepted — tokens in URLs leak into history,
/// proxy logs, and Referer. Browsers use POST /session → cookie; APIs use Bearer.
fn authorized(state: &AppState, expected: &str, headers: &HeaderMap) -> bool {
    if bearer_token_ok(expected, headers) {
        return true;
    }
    session_cookie_ok(state, headers)
}

fn bearer_token_ok(expected: &str, headers: &HeaderMap) -> bool {
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let provided = auth.strip_prefix("Bearer ").unwrap_or(auth);
        return constant_time_eq(provided.as_bytes(), expected.as_bytes());
    }
    false
}

fn session_cookie_ok(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(sid) = cookie_value(headers, SESSION_COOKIE) else {
        return false;
    };
    let mut sessions = state.sessions.lock();
    // Opportunistic expiry sweep.
    let now = Instant::now();
    sessions.retain(|_, exp| *exp > now);
    matches!(sessions.get(&sid), Some(exp) if *exp > now)
}

/// Parse a single cookie value from the Cookie header.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `cookie_value` — see module docs for full workflow.
/// ```
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(name) {
            if let Some(val) = rest.strip_prefix('=') {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn session_cookie_header(session_id: &str, secure: bool, max_age_secs: u64) -> String {
    // HttpOnly + SameSite=Strict; Secure when TLS / non-loopback.
    let mut c = format!(
        "{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}"
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn clear_session_cookie(secure: bool) -> String {
    let mut c = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    if secure {
        c.push_str("; Secure");
    }
    c
}

#[derive(Debug, Deserialize)]
struct SessionForm {
    token: String,
}

async fn login_page(State(state): State<AppState>) -> impl IntoResponse {
    if state.token.is_none() {
        return Redirect::temporary("/").into_response();
    }
    Html(login_html(None)).into_response()
}

async fn create_session(
    State(state): State<AppState>,
    Form(form): Form<SessionForm>,
) -> impl IntoResponse {
    let Some(expected) = state.token.as_deref() else {
        return Redirect::temporary("/").into_response();
    };
    // Sliding-window rate limit failed logins (token brute-force mitigation).
    {
        let mut fails = state.login_failures.lock();
        let cutoff = Instant::now() - LOGIN_FAIL_WINDOW;
        fails.retain(|t| *t > cutoff);
        if fails.len() >= LOGIN_FAIL_MAX {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Html(login_html(Some(
                    "Too many failed sign-in attempts. Wait a minute and try again.",
                ))),
            )
                .into_response();
        }
    }
    if !constant_time_eq(form.token.trim().as_bytes(), expected.as_bytes()) {
        state.login_failures.lock().push(Instant::now());
        return (
            StatusCode::UNAUTHORIZED,
            Html(login_html(Some("Invalid token"))),
        )
            .into_response();
    }
    // Successful login: clear failure window.
    state.login_failures.lock().clear();
    let sid = uuid::Uuid::new_v4().to_string();
    {
        let mut sessions = state.sessions.lock();
        sessions.insert(sid.clone(), Instant::now() + SESSION_TTL);
    }
    let mut res = Redirect::temporary("/").into_response();
    if let Ok(val) = HeaderValue::from_str(&session_cookie_header(
        &sid,
        state.secure_cookies,
        SESSION_TTL.as_secs(),
    )) {
        res.headers_mut().insert(header::SET_COOKIE, val);
    }
    res
}

async fn logout_session(State(state): State<AppState>, request: Request) -> impl IntoResponse {
    if let Some(sid) = cookie_value(request.headers(), SESSION_COOKIE) {
        state.sessions.lock().remove(&sid);
    }
    let mut res = Redirect::temporary("/login").into_response();
    if let Ok(val) = HeaderValue::from_str(&clear_session_cookie(state.secure_cookies)) {
        res.headers_mut().insert(header::SET_COOKIE, val);
    }
    res
}

fn login_html(error: Option<&str>) -> String {
    let err = error
        .map(|e| format!(r#"<p class="err">{e}</p>"#))
        .unwrap_or_default();
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>blackbox · login</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem;color:#1a1a1a}}
 label{{display:block;margin:.75rem 0 .25rem;font-weight:600}}
 input[type=password]{{width:100%;padding:.5rem;font-size:1rem;box-sizing:border-box}}
 button{{margin-top:1rem;padding:.5rem 1rem;font-size:1rem;cursor:pointer}}
 .err{{color:#b00020}}
 .hint{{color:#555;font-size:.9rem}}
</style></head><body>
<h1>blackbox dashboard</h1>
<p class="hint">Enter the serve token. A session cookie is set (HttpOnly, SameSite=Strict). API clients should use <code>Authorization: Bearer</code> instead.</p>
{err}
<form method="post" action="/session" autocomplete="off">
  <label for="token">Token</label>
  <input id="token" name="token" type="password" required autofocus/>
  <button type="submit">Sign in</button>
</form>
</body></html>"#
    )
}

/// Byte-wise equality comparison that runs in constant time regardless of
/// where the first difference occurs, preventing timing side-channel attacks
/// on bearer-token validation.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() != b.len()) as u8;
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
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
  <a class="btn" href="/incidents">Incidents</a>
  <a class="btn" href="/handoff">Handoff</a>
  <a class="btn secondary" href="/status">Status</a>
  <a class="btn secondary" href="/api/runs">JSON API</a>
  <span class="muted" id="stream">live list: connecting…</span>
</div>
<p class="muted"><span id="count">{n}</span> run(s)</p>
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
function esc(s) {{ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }}
function upsert(run) {{
  const id = run.id;
  const short = id.slice(0, 8);
  const label = run.name || (run.command || []).join(' ');
  const status = run.status || '?';
  const exit = run.exit_code == null ? '-' : String(run.exit_code);
  const started = run.started_at || '';
  const tags = (run.tags && run.tags.length) ? run.tags.join(', ') : '';
  let tr = rows.get(id);
  if (!tr) {{
    tr = document.createElement('tr');
    tr.dataset.id = id;
    tbody.insertBefore(tr, tbody.firstChild);
    rows.set(id, tr);
    countEl.textContent = String(rows.size);
    tr.classList.add('flash');
  }}
  tr.textContent = '';
  const td1 = document.createElement('td'); td1.className = 'mono';
  const a1 = document.createElement('a'); a1.href = `/runs/${{encodeURIComponent(id)}}`; a1.textContent = short;
  td1.appendChild(a1); tr.appendChild(td1);
  const td2 = document.createElement('td');
  const badge = document.createElement('span'); badge.className = 'badge'; badge.textContent = status;
  td2.appendChild(badge); td2.appendChild(document.createTextNode(' '));
  const a2 = document.createElement('a'); a2.className = 'muted'; a2.href = `/runs/${{encodeURIComponent(id)}}/live`; a2.textContent = 'live';
  td2.appendChild(a2);
  const anomSlot = document.createElement('span'); anomSlot.className = 'anom-slot'; anomSlot.dataset.for = id;
  td2.appendChild(document.createTextNode(' ')); td2.appendChild(anomSlot);
  tr.appendChild(td2);
  const td3 = document.createElement('td'); td3.textContent = exit; tr.appendChild(td3);
  const td4 = document.createElement('td'); td4.textContent = label + ' '; tr.appendChild(td4);
  if (tags) {{ const span = document.createElement('span'); span.className = 'tags'; span.textContent = tags; td4.appendChild(span); }}
  // Lazy anomaly badge for finished / failed runs
  if (status === 'Failed' || status === 'Completed' || status === 'Cancelled') {{
    refreshAnom(id, anomSlot);
  }}
}}
const qs = new URLSearchParams(location.search);
// Token via sessionStorage after ?token= once (migrated off query auth).
const urlTok = qs.get('token');
if (urlTok) {{
  try {{ sessionStorage.setItem('bb_token', urlTok); }} catch(_){{}}
  const u = new URL(location.href); u.searchParams.delete('token');
  history.replaceState(null, '', u.pathname + u.search + u.hash);
}}
function bbToken() {{ try {{ return sessionStorage.getItem('bb_token') || ''; }} catch(_) {{ return ''; }} }}
function authHeaders() {{
  const headers = {{}};
  const t = bbToken();
  if (t) headers['Authorization'] = 'Bearer ' + t;
  return headers;
}}
async function refreshAnom(id, slot) {{
  try {{
    const res = await fetch('/api/runs/' + encodeURIComponent(id) + '/anomalies', {{ headers: authHeaders() }});
    if (!res.ok) return;
    const body = await res.json();
    const list = body.anomalies || body || [];
    const n = Array.isArray(list) ? list.length : 0;
    if (!n) {{ slot.textContent = ''; return; }}
    const high = list.filter(a => a.severity === 'high').length;
    const warn = list.filter(a => a.severity === 'warn').length;
    const sev = high ? 'high' : (warn ? 'warn' : 'info');
    slot.innerHTML = '';
    const b = document.createElement('span');
    b.className = 'badge badge-anom badge-' + sev;
    b.title = list.map(a => '[' + a.severity + '|' + a.kind + '] ' + (a.detail || '')).slice(0, 5).join('\\n');
    b.textContent = '⚠ ' + n;
    slot.appendChild(b);
  }} catch (_) {{}}
}}
async function openSse(path, handlers) {{
  const headers = authHeaders();
  streamEl.textContent = 'live list: connecting…';
  try {{
    const res = await fetch(path, {{ headers }});
    if (!res.ok) {{ streamEl.textContent = 'live list: ' + res.status; return; }}
    streamEl.textContent = 'live list: connected';
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    let evName = 'message';
    let dataLines = [];
    while (true) {{
      const {{ value, done }} = await reader.read();
      if (done) break;
      buf += dec.decode(value, {{ stream: true }});
      const parts = buf.split('\\n');
      buf = parts.pop() || '';
      for (const line of parts) {{
        if (line.startsWith('event:')) {{ evName = line.slice(6).trim(); }}
        else if (line.startsWith('data:')) {{ dataLines.push(line.slice(5).trimStart()); }}
        else if (line === '') {{
          if (dataLines.length) {{
            const data = dataLines.join('\\n');
            const h = handlers[evName] || handlers.message;
            if (h) try {{ h(data); }} catch(_){{}}
          }}
          evName = 'message'; dataLines = [];
        }}
      }}
    }}
  }} catch (e) {{
    streamEl.textContent = 'live list: reconnecting…';
    setTimeout(() => openSse(path, handlers), 1500);
  }}
}}
openSse('/api/runs/stream', {{
  run: (data) => {{ try {{ upsert(JSON.parse(data)); }} catch(_){{}} }},
}});
// Seed anomaly badges for initial rows
for (const tr of tbody.querySelectorAll('tr[data-id]')) {{
  const slot = tr.querySelector('.anom-slot');
  if (slot) refreshAnom(tr.dataset.id, slot);
}}
</script>
<style>.flash {{ animation: flash 1.2s ease; }} @keyframes flash {{ from {{ background: color-mix(in srgb, var(--accent) 35%, transparent); }} to {{ background: transparent; }} }}</style>"#,
            n = runs.len(),
            rows = rows,
        ),
    )))
}

fn run_row_html(run: &crate::core::run::Run) -> String {
    let label = run.name.clone().unwrap_or_else(|| run.command.join(" "));
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
  <td><span class="badge">{status}</span> <a class="muted" href="/runs/{id}/live">live</a> <span class="anom-slot" data-for="{id}"></span></td>
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

/// HTML chips for anomaly markers on the run detail page.
fn anomaly_badges_html(anomalies: &[crate::analysis::Anomaly]) -> String {
    if anomalies.is_empty() {
        return String::new();
    }
    let mut chips = String::new();
    for a in anomalies.iter().take(12) {
        let sev = match a.severity.as_str() {
            "high" => "high",
            "warn" => "warn",
            _ => "info",
        };
        let label = if let Some(c) = a.count {
            format!("{}×{}", a.kind, c)
        } else {
            a.kind.clone()
        };
        let seq = a.sequence.map(|s| format!(" seq={s}")).unwrap_or_default();
        chips.push_str(&format!(
            r#" <span class="badge badge-anom badge-{sev}" title="{title}">{label}</span>"#,
            sev = sev,
            label = html_escape(&label),
            title = html_escape(&format!("[{}] {}{}", a.severity, a.detail, seq)),
        ));
    }
    format!(
        r#"<div class="meta anom-bar"><div><b>Anomalies</b> {n}{chips}</div></div>"#,
        n = anomalies.len(),
        chips = chips,
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
    let anomalies = crate::analysis::detect_anomalies(&events);
    let tools = rebuild_tool_transcript(&events);
    let transcript = rebuild_terminal_transcript(state.store.as_ref(), &events)
        .await
        .unwrap_or_default();

    // 1.7 boundary trust + findings for HTML.
    let boundary = state.store.get_run_boundary(&run_id).await.ok().flatten();
    let findings = state
        .store
        .list_boundary_findings(&run_id)
        .await
        .unwrap_or_default();
    let containment = state
        .store
        .list_containment_receipts(&run_id)
        .await
        .unwrap_or_default();
    let provenance = state
        .store
        .list_provenance_records(&run_id)
        .await
        .unwrap_or_default();
    let external = state
        .store
        .list_external_evidence_for_run(&run_id)
        .await
        .unwrap_or_default();
    let trust = crate::boundary::build_boundary_trust(
        boundary.as_ref(),
        &findings,
        &containment,
        &provenance,
        &external,
        &[],
    );
    let trust_html = boundary_trust_html(&trust, &findings, &external);

    let mut timeline = String::new();
    for ev in events.iter().filter(|e| !is_bookkeeping(&e.kind)) {
        timeline.push_str(&event_row_html(ev));
    }

    let body = format!(
        r#"<p><a href="/">← Runs</a> · <a href="/runs/{id}/live">Live view</a> · <a href="/runs/{id}/export.html">Full HTML export</a> · <a class="muted" href="/api/runs/{id}/boundary">boundary JSON</a> · <a class="muted" href="/api/runs/{id}/anomalies">anomalies JSON</a></p>
<h1>{title}</h1>
<p class="mono muted">{full_id}</p>
<div class="meta">
  <div><b>Status</b> {:?}</div>
  <div><b>Exit</b> {:?}</div>
  <div><b>Command</b> <span class="mono">{}</span></div>
  <div><b>Events</b> {}</div>
  <div><b>Tags</b> {}</div>
</div>
{anom}
{trust}
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
        anom = anomaly_badges_html(&anomalies),
        trust = trust_html,
    );

    Ok(Html(shell(
        &format!("Run {}", &run_id[..8.min(run_id.len())]),
        &body,
    ))
    .into_response())
}

fn boundary_trust_html(
    trust: &crate::boundary::BoundaryTrustView,
    findings: &[crate::boundary::BoundaryFinding],
    external: &[crate::evidence::ExternalEvidenceEvent],
) -> String {
    if !trust.has_boundary && findings.is_empty() && external.is_empty() {
        return String::new();
    }
    let ok = if trust.trust_ok {
        "trust-ok"
    } else {
        "trust-bad"
    };
    let mut finding_rows = String::new();
    for f in findings.iter().take(20) {
        finding_rows.push_str(&format!(
            "<tr><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
            html_escape(f.severity.as_str()),
            html_escape(&f.detector),
            html_escape(&f.summary),
        ));
    }
    if finding_rows.is_empty() {
        finding_rows = "<tr><td colspan=\"3\" class=\"muted\">No findings</td></tr>".into();
    }
    format!(
        r#"<div class="meta trust-panel {ok}">
  <div><b>Boundary trust</b> {}</div>
  <div><b>Policy</b> <span class="mono">{}</span></div>
  <div><b>Evidence</b> {}</div>
  <div><b>Provenance</b> {}</div>
  <div><b>Findings</b> {} (critical {})</div>
  <div><b>External evidence</b> {}</div>
</div>
<h2>Boundary findings</h2>
<table>
  <thead><tr><th>Sev</th><th>Detector</th><th>Summary</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"#,
        if trust.trust_ok { "ok" } else { "attention" },
        html_escape(
            trust
                .policy_hash
                .as_deref()
                .map(|h| &h[..16.min(h.len())])
                .unwrap_or("—")
        ),
        html_escape(trust.evidence_status.as_deref().unwrap_or("—")),
        html_escape(trust.provenance_status.as_deref().unwrap_or("—")),
        trust.finding_count,
        trust.critical_finding_count,
        external.len(),
        ok = ok,
        rows = finding_rows,
    )
}

async fn incidents_page(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let page = state.store.list_incidents_page(None, 50).await?;
    let mut rows = String::new();
    for inc in &page.incidents {
        rows.push_str(&format!(
            r#"<tr>
  <td class="mono"><a href="/incidents/{id}">{short}</a></td>
  <td>{title}</td>
  <td>{runs}</td>
  <td class="muted">{created}</td>
</tr>"#,
            id = urlencoding(&inc.id),
            short = html_escape(&inc.id[..8.min(inc.id.len())]),
            title = html_escape(inc.title.as_deref().unwrap_or("—")),
            runs = inc.run_ids().len(),
            created = html_escape(&inc.created_at.to_rfc3339()),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="4" class="muted">No incidents yet. Create with <code>blackbox incident create</code>.</td></tr>"#.into();
    }
    Ok(Html(shell(
        "Incidents",
        &format!(
            r#"<p><a href="/">← Runs</a> · <a class="muted" href="/api/incidents">JSON</a></p>
<h1>Incidents</h1>
<p class="muted">{n} shown{more}</p>
<table>
  <thead><tr><th>ID</th><th>Title</th><th>Runs</th><th>Created</th></tr></thead>
  <tbody>{rows}</tbody>
</table>"#,
            n = page.incidents.len(),
            more = if page.has_more {
                " (more available via API cursor)"
            } else {
                ""
            },
            rows = rows,
        ),
    )))
}

async fn incident_page(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let Some(inc) = state.store.get_incident(&id).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };

    // Build full reconstruction graph for the HTML UI.
    let mut findings_by_run = Vec::new();
    let mut external = Vec::new();
    let mut edges = Vec::new();
    let mut run_end_times = Vec::new();
    for rid in inc.run_ids() {
        let findings = state
            .store
            .list_boundary_findings(rid)
            .await
            .unwrap_or_default();
        findings_by_run.push((rid.to_string(), findings));
        external.extend(
            state
                .store
                .list_external_evidence_for_run(rid)
                .await
                .unwrap_or_default(),
        );
        edges.extend(
            state
                .store
                .list_evidence_edges(rid)
                .await
                .unwrap_or_default(),
        );
        if let Ok(Some(run)) = state.store.get_run(rid).await {
            run_end_times.push((rid.to_string(), run.ended_at));
        }
    }
    let graph = crate::incident::build_incident_graph(
        &inc,
        &crate::incident::GraphInputs {
            findings_by_run: findings_by_run.clone(),
            external: external.clone(),
            edges: edges.clone(),
            run_end_times,
        },
    );
    // Persist earliest signal when computed.
    if graph.earliest_signal.is_some()
        && (inc.earliest_signal_id.is_none() || inc.continued_after_signal.is_none())
    {
        let mut updated = inc.clone();
        updated.earliest_signal_id = graph.earliest_signal.as_ref().map(|s| s.ref_id.clone());
        updated.continued_after_signal = graph.continued_after_signal;
        updated.updated_at = Some(chrono::Utc::now());
        let _ = state.store.upsert_incident(&updated).await;
    }

    let aggregates = crate::incident::compute_incident_aggregates_from_graph(
        &inc,
        &graph,
        0,
        graph.finding_count,
    );

    let detail_status = match graph.is_detail_truncated() {
        Some(true) => {
            let truncation = graph
                .truncation
                .as_ref()
                .expect("known graph truncation must include totals");
            format!(
                "truncated (nodes {}/{}, edges {}/{}, flows {}/{}, techniques {}/{})",
                truncation.nodes.included,
                truncation.nodes.total,
                truncation.edges.included,
                truncation.edges.total,
                truncation.flows.included,
                truncation.flows.total,
                truncation.techniques.included,
                truncation.techniques.total,
            )
        }
        Some(false) => "complete".into(),
        None => "unknown legacy detail; counts are lower bounds".into(),
    };

    let body = format!(
        r#"<p><a href="/incidents">← Incidents</a> · <a class="muted" href="/api/incidents/{id}">JSON</a></p>
<h1>{title}</h1>
<p class="mono muted">{full}</p>
{signal_banner}
<div class="meta">
  <div><b>Runs</b> {runs}</div>
  <div><b>Attachments</b> {atts}</div>
  <div><b>Findings</b> {find_n}</div>
  <div><b>Evidence</b> {ev_n}</div>
  <div><b>Techniques</b> {tech_n}</div>
  <div><b>Reuse</b> {reuse}</div>
  <div><b>Graph detail</b> {detail_status}</div>
  <div><b>Continued after signal</b> {cont}</div>
</div>
{graph_svg}
<h2>Attachments</h2>
<table>
  <thead><tr><th>Kind</th><th>Ref</th><th>Reason</th></tr></thead>
  <tbody>{attach}</tbody>
</table>
<h2>Technique discovery & reuse</h2>
<table>
  <thead><tr><th>Technique</th><th>First run</th><th>Reused by</th></tr></thead>
  <tbody>{tech_rows}</tbody>
</table>
<h2>Findings timeline</h2>
<table>
  <thead><tr><th>When</th><th>Run</th><th>Sev</th><th>Detector</th><th>Summary</th></tr></thead>
  <tbody>{finding_rows}</tbody>
</table>
<h2>Correlation edges</h2>
<table>
  <thead><tr><th>Relation</th><th>Confidence</th><th>From</th><th>To</th><th>Reasons</th></tr></thead>
  <tbody>{edge_rows}</tbody>
</table>
<h2>Linked runs</h2>
<ul>{run_list}</ul>"#,
        id = urlencoding(&inc.id),
        title = html_escape(inc.title.as_deref().unwrap_or("Incident")),
        full = html_escape(&inc.id),
        signal_banner = incident_signal_banner(&graph),
        runs = aggregates.run_count,
        atts = aggregates.attachment_count,
        find_n = aggregates.finding_count,
        ev_n = aggregates.external_evidence_count,
        tech_n = aggregates.technique_count,
        reuse = aggregates.reuse_count,
        detail_status = html_escape(&detail_status),
        cont = graph
            .continued_after_signal
            .or(inc.continued_after_signal)
            .map(|c| c.to_string())
            .unwrap_or_else(|| "—".into()),
        graph_svg = incident_graph_svg(&graph),
        attach = incident_attach_rows(&inc),
        tech_rows = incident_technique_rows(&graph),
        finding_rows = incident_finding_rows(&findings_by_run),
        edge_rows = incident_edge_rows(&graph.edges),
        run_list = incident_run_list(&findings_by_run),
    );
    Ok(Html(shell("Incident", &body)).into_response())
}

fn incident_signal_banner(graph: &crate::incident::IncidentGraph) -> String {
    let Some(ref s) = graph.earliest_signal else {
        return r#"<div class="meta"><div><b>Earliest signal</b> none yet</div></div>"#.into();
    };
    let cont = graph
        .continued_after_signal
        .map(|c| {
            if c {
                "yes — activity continued after signal"
            } else {
                "no"
            }
        })
        .unwrap_or("unknown");
    format!(
        r#"<div class="meta trust-panel trust-bad signal-banner">
  <div><b>Earliest actionable signal</b></div>
  <div class="mono">{id}</div>
  <div>{kind}</div>
  <div>{summary}</div>
  <div class="muted">{at}</div>
  <div><b>Continued after signal</b> {cont}</div>
</div>"#,
        id = html_escape(&s.ref_id[..8.min(s.ref_id.len())]),
        kind = html_escape(&s.kind),
        summary = html_escape(&s.summary),
        at = html_escape(&s.at.to_rfc3339()),
        cont = cont,
    )
}

fn incident_attach_rows(inc: &crate::incident::Incident) -> String {
    let mut attach_rows = String::new();
    for a in &inc.attachments {
        let link = if matches!(a.kind, crate::incident::IncidentAttachmentKind::Run) {
            format!(
                r#"<a href="/runs/{0}">{1}</a>"#,
                urlencoding(&a.ref_id),
                html_escape(&a.ref_id[..8.min(a.ref_id.len())])
            )
        } else {
            html_escape(&a.ref_id[..8.min(a.ref_id.len())])
        };
        attach_rows.push_str(&format!(
            "<tr><td>{}</td><td class=\"mono\">{}</td><td class=\"muted\">{}</td></tr>",
            html_escape(a.kind.as_str()),
            link,
            html_escape(a.reason.as_deref().unwrap_or("—")),
        ));
    }
    if attach_rows.is_empty() {
        attach_rows = r#"<tr><td colspan="3" class="muted">No attachments</td></tr>"#.into();
    }
    attach_rows
}

fn incident_technique_rows(graph: &crate::incident::IncidentGraph) -> String {
    let mut rows = String::new();
    for t in &graph.techniques {
        let reused = if t.reused_by_runs.is_empty() {
            "—".into()
        } else {
            t.reused_by_runs
                .iter()
                .map(|r| {
                    format!(
                        r#"<a href="/runs/{0}">{1}</a>"#,
                        urlencoding(r),
                        html_escape(&r[..8.min(r.len())])
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        rows.push_str(&format!(
            r#"<tr><td class="mono">{tech}</td><td class="mono"><a href="/runs/{first_u}">{first}</a></td><td>{reused}</td></tr>"#,
            tech = html_escape(&t.technique),
            first_u = urlencoding(&t.first_run_id),
            first = html_escape(&t.first_run_id[..8.min(t.first_run_id.len())]),
            reused = reused,
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="3" class="muted">No techniques recorded</td></tr>"#.into();
    }
    rows
}

fn incident_finding_rows(
    findings_by_run: &[(String, Vec<crate::boundary::BoundaryFinding>)],
) -> String {
    let mut all: Vec<(&str, &crate::boundary::BoundaryFinding)> = Vec::new();
    for (rid, fs) in findings_by_run {
        for f in fs {
            all.push((rid.as_str(), f));
        }
    }
    all.sort_by_key(|(_, f)| f.created_at);
    let mut rows = String::new();
    for (rid, f) in all.iter().take(100) {
        rows.push_str(&format!(
            r#"<tr><td class="muted">{at}</td><td class="mono"><a href="/runs/{ru}">{r}</a></td><td>{sev}</td><td class="mono">{det}</td><td>{sum}</td></tr>"#,
            at = html_escape(&f.created_at.to_rfc3339()),
            ru = urlencoding(rid),
            r = html_escape(&rid[..8.min(rid.len())]),
            sev = html_escape(f.severity.as_str()),
            det = html_escape(&f.detector),
            sum = html_escape(&f.summary),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="5" class="muted">No findings</td></tr>"#.into();
    }
    rows
}

fn incident_edge_rows(edges: &[crate::boundary::EvidenceEdge]) -> String {
    let mut rows = String::new();
    for e in edges.iter().take(50) {
        rows.push_str(&format!(
            r#"<tr><td class="mono">{rel}</td><td>{conf}</td><td class="mono">{from}</td><td class="mono">{to}</td><td class="muted">{why}</td></tr>"#,
            rel = html_escape(e.relation.as_str()),
            conf = html_escape(e.confidence.as_str()),
            from = html_escape(&e.from_id[..8.min(e.from_id.len())]),
            to = html_escape(&e.to_id[..8.min(e.to_id.len())]),
            why = html_escape(&e.reasons.join(", ")),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="5" class="muted">No correlation edges</td></tr>"#.into();
    }
    rows
}

fn incident_run_list(
    findings_by_run: &[(String, Vec<crate::boundary::BoundaryFinding>)],
) -> String {
    let mut out = String::new();
    for (rid, fs) in findings_by_run {
        out.push_str(&format!(
            r#"<li><a href="/runs/{0}">{1}</a> — {n} finding(s)</li>"#,
            urlencoding(rid),
            html_escape(&rid[..8.min(rid.len())]),
            n = fs.len(),
        ));
    }
    if out.is_empty() {
        out = "<li class=\"muted\">No runs attached</li>".into();
    }
    out
}

/// Simple SVG layout: runs on a horizontal row, technique labels below with reuse arcs.
fn incident_graph_svg(graph: &crate::incident::IncidentGraph) -> String {
    let runs: Vec<String> = {
        let mut r: Vec<String> = graph
            .nodes
            .iter()
            .filter(|n| n.kind == "run")
            .map(|n| n.id.clone())
            .collect();
        if r.is_empty() {
            // Fall back from techniques
            for t in &graph.techniques {
                if !r.contains(&t.first_run_id) {
                    r.push(t.first_run_id.clone());
                }
                for u in &t.reused_by_runs {
                    if !r.contains(u) {
                        r.push(u.clone());
                    }
                }
            }
        }
        r
    };
    if runs.is_empty() {
        return r#"<div class="muted">No graph nodes yet.</div>"#.into();
    }
    let n = runs.len().max(1);
    let width = (n as i32 * 140 + 80).max(320);
    let height = 220 + (graph.techniques.len().min(8) as i32) * 18;
    let mut circles = String::new();
    let mut labels = String::new();
    let mut run_pos = std::collections::BTreeMap::new();
    for (i, rid) in runs.iter().enumerate() {
        let x = 60 + (i as i32) * 140;
        let y = 60;
        run_pos.insert(rid.clone(), (x, y));
        circles.push_str(&format!(
            r#"<a href="/runs/{href}"><circle cx="{x}" cy="{y}" r="22" class="g-run"/><title>{title}</title></a>"#,
            href = urlencoding(rid),
            x = x,
            y = y,
            title = html_escape(rid),
        ));
        labels.push_str(&format!(
            r#"<text x="{x}" y="{y}" text-anchor="middle" dy="5" class="g-label">{short}</text>"#,
            x = x,
            y = y,
            short = html_escape(&rid[..8.min(rid.len())]),
        ));
    }
    // Technique reuse edges as curves under the run row.
    let mut paths = String::new();
    for (ti, t) in graph.techniques.iter().take(12).enumerate() {
        let Some(&(x1, y1)) = run_pos.get(&t.first_run_id) else {
            continue;
        };
        for (ri, reused) in t.reused_by_runs.iter().enumerate() {
            let Some(&(x2, y2)) = run_pos.get(reused) else {
                continue;
            };
            let mid_y = 110 + ((ti + ri) as i32 % 5) * 14;
            paths.push_str(&format!(
                r#"<path d="M {x1} {y1} C {x1} {mid_y}, {x2} {mid_y}, {x2} {y2}" class="g-edge" />"#,
                x1 = x1,
                y1 = y1 + 22,
                mid_y = mid_y,
                x2 = x2,
                y2 = y2 + 22,
            ));
        }
    }
    // Earliest signal marker on its run.
    let mut signal = String::new();
    if let Some(ref s) = graph.earliest_signal {
        if let Some(ref rid) = s.run_id {
            if let Some(&(x, y)) = run_pos.get(rid) {
                signal.push_str(&format!(
                    r#"<circle cx="{x}" cy="{y}" r="28" class="g-signal" fill="none"/><text x="{x}" y="{ty}" text-anchor="middle" class="g-signal-label">signal</text>"#,
                    x = x,
                    y = y,
                    ty = y - 36,
                ));
            }
        }
    }
    format!(
        r#"<h2>Reconstruction graph</h2>
<div class="graph-wrap">
<svg viewBox="0 0 {w} {h}" class="incident-graph" role="img" aria-label="Incident reconstruction graph">
  {paths}
  {circles}
  {labels}
  {signal}
</svg>
<p class="muted">Runs as nodes; curves show technique reuse. Highlight ring = earliest actionable signal run.</p>
</div>"#,
        w = width,
        h = height,
        paths = paths,
        circles = circles,
        labels = labels,
        signal = signal,
    )
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
    let label = run.name.clone().unwrap_or_else(|| run.command.join(" "));

    let body = format!(
        r#"<p><a href="/">← Runs</a> · <a href="/runs/{id}">Static view</a></p>
<h1>Live · {title}</h1>
<p class="mono muted">{full_id}</p>
<div class="meta">
  <div><b>Status</b> <span id="status">{status:?}</span></div>
  <div><b>Events</b> <span id="count">0</span></div>
  <div><b>Stream</b> <span id="stream" class="muted">connecting…</span></div>
  <div><b>Anomalies</b> <span id="anoms" class="muted">…</span></div>
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
const anomsEl = document.getElementById('anoms');
const semantic = document.getElementById('semantic');
const bookkeeping = new Set([
  'pty.started','pty.stopped','git.observer.started','git.observer.stopped',
  'filesystem.observer.started','filesystem.observer.stopped',
  'process.observer.started','process.observer.stopped','terminal.recording',
  'git.commit','git.commit.after'
]);
let n = 0;
let anomRefreshAt = 0;
function esc(s) {{ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }}
function detail(ev) {{
  const m = ev.metadata || {{}};
  return (m.preview || m.tool_name || m.path || (m.exit_code != null ? 'exit='+m.exit_code : '') || '').toString().replace(/\n/g,'⏎');
}}
function add(ev) {{
  if (semantic.checked && bookkeeping.has(ev.kind)) return;
  const tr = document.createElement('tr');
  if (ev.kind && ev.kind.startsWith('tool.')) tr.className = 'row-tool';
  if (ev.status === 'Error') tr.className = 'row-error';
  tr.textContent = '';
  const td1 = document.createElement('td'); td1.className = 'num'; td1.textContent = String(ev.sequence);
  const td2 = document.createElement('td'); td2.textContent = String(ev.source);
  const td3 = document.createElement('td'); td3.className = 'mono'; td3.textContent = String(ev.kind);
  const td4 = document.createElement('td'); td4.className = 'detail'; td4.textContent = detail(ev);
  tr.append(td1, td2, td3, td4);
  tl.appendChild(tr);
  n++;
  countEl.textContent = String(n);
  tr.scrollIntoView({{block:'nearest'}});
  // Throttle anomaly refresh (~every 25 events or 4s)
  const now = Date.now();
  if (n % 25 === 0 || now - anomRefreshAt > 4000) refreshAnoms();
}}
const qs = new URLSearchParams(location.search);
const urlTok = qs.get('token');
if (urlTok) {{
  try {{ sessionStorage.setItem('bb_token', urlTok); }} catch(_){{}}
  const u = new URL(location.href); u.searchParams.delete('token');
  history.replaceState(null, '', u.pathname + u.search + u.hash);
}}
function bbToken() {{ try {{ return sessionStorage.getItem('bb_token') || ''; }} catch(_) {{ return ''; }} }}
function authHeaders() {{
  const headers = {{}};
  const t = bbToken();
  if (t) headers['Authorization'] = 'Bearer ' + t;
  return headers;
}}
async function refreshAnoms() {{
  anomRefreshAt = Date.now();
  try {{
    const res = await fetch('/api/runs/' + encodeURIComponent(runId) + '/anomalies', {{ headers: authHeaders() }});
    if (!res.ok) {{ anomsEl.textContent = '—'; return; }}
    const body = await res.json();
    const list = body.anomalies || [];
    if (!list.length) {{ anomsEl.innerHTML = '<span class="muted">none</span>'; return; }}
    anomsEl.innerHTML = list.slice(0, 8).map(a => {{
      const sev = a.severity === 'high' ? 'high' : (a.severity === 'warn' ? 'warn' : 'info');
      const label = a.count ? (a.kind + '×' + a.count) : a.kind;
      return '<span class="badge badge-anom badge-' + sev + '" title="' + esc('[' + a.severity + '] ' + (a.detail||'')) + '">' + esc(label) + '</span>';
    }}).join(' ');
  }} catch (_) {{ anomsEl.textContent = '—'; }}
}}
async function openSse(path, handlers) {{
  const headers = authHeaders();
  streamEl.textContent = 'stream: connecting…';
  try {{
    const res = await fetch(path, {{ headers }});
    if (!res.ok) {{ streamEl.textContent = 'stream: ' + res.status; return; }}
    streamEl.textContent = 'stream: live';
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    let evName = 'message';
    let dataLines = [];
    while (true) {{
      const {{ value, done }} = await reader.read();
      if (done) break;
      buf += dec.decode(value, {{ stream: true }});
      const parts = buf.split('\\n');
      buf = parts.pop() || '';
      for (const line of parts) {{
        if (line.startsWith('event:')) {{ evName = line.slice(6).trim(); }}
        else if (line.startsWith('data:')) {{ dataLines.push(line.slice(5).trimStart()); }}
        else if (line === '') {{
          if (dataLines.length) {{
            const data = dataLines.join('\\n');
            const h = handlers[evName] || handlers.message;
            if (h) try {{ h(data); }} catch(_){{}}
          }}
          evName = 'message'; dataLines = [];
        }}
      }}
    }}
  }} catch (e) {{
    streamEl.textContent = 'stream: reconnecting…';
    setTimeout(() => openSse(path, handlers), 1500);
  }}
}}
openSse(`/api/runs/${{encodeURIComponent(runId)}}/events/stream`, {{
  event: (data) => {{ try {{ add(JSON.parse(data)); }} catch (_) {{}} }},
  status: (data) => {{
    try {{
      const s = JSON.parse(data);
      statusEl.textContent = s.status || statusEl.textContent;
      if (s.exit_code != null) statusEl.textContent += ' exit=' + s.exit_code;
      refreshAnoms();
    }} catch (_) {{}}
  }},
}});
refreshAnoms();
document.getElementById('clear').onclick = () => {{ tl.textContent=''; n=0; countEl.textContent='0'; }};
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
    Ok(
        axum::response::Redirect::temporary(&format!("/runs/{}/live", urlencoding(&run.id)))
            .into_response(),
    )
}

fn discovery_from_store(store: &SqliteStore) -> crate::config::ProjectDiscovery {
    use crate::config::{BlackboxConfig, BlackboxPaths, ProjectDiscovery};
    let paths = BlackboxPaths::from_db_path(store.db_path().to_path_buf());
    let project_root = paths
        .root
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| paths.root.clone());
    let config = BlackboxConfig::load_from_path(&paths.root.join("config.toml"))
        .ok()
        .flatten();
    ProjectDiscovery {
        project_root,
        paths,
        config,
    }
}

async fn build_serve_status(
    state: &AppState,
    include_resume: bool,
    force_resume: bool,
) -> anyhow::Result<crate::status::StatusView> {
    use crate::status::{build_status, StatusOptions};
    use crate::storage::TraceStore;
    let discovery = discovery_from_store(&state.store);
    let store: &dyn TraceStore = state.store.as_ref();
    build_status(
        &discovery,
        Some(store),
        StatusOptions {
            include_resume,
            max_tokens: 4000,
            force_resume,
            include_project_memory: include_resume,
        },
    )
    .await
}

async fn api_status(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let view = build_serve_status(&state, false, false).await?;
    Ok(Json(serde_json::to_value(view)?))
}

async fn api_handoff(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let view = build_serve_status(&state, true, false).await?;
    Ok(Json(serde_json::to_value(view)?))
}

async fn status_page(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let view = build_serve_status(&state, false, false).await?;
    let text = crate::status::format_status_text(&view);
    let json = serde_json::to_string_pretty(&view).unwrap_or_default();
    Ok(Html(shell(
        "Status",
        &format!(
            r#"<div class="bar">
  <a class="btn" href="/handoff">Handoff</a>
  <a class="btn secondary" href="/api/status">JSON</a>
  <a class="btn secondary" href="/">Runs</a>
</div>
<pre class="mono status-pre">{}</pre>
<details><summary>JSON</summary><pre class="mono">{}</pre></details>"#,
            html_escape(&text),
            html_escape(&json)
        ),
    )))
}

async fn handoff_page(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let view = build_serve_status(&state, true, false).await?;
    let text = crate::status::format_status_text(&view);
    let json = serde_json::to_string_pretty(&view).unwrap_or_default();
    let attn = if view.attention.needed {
        format!(
            r#"<p class="badge" style="background:#7f1d1d">ATTENTION: {}</p>"#,
            html_escape(
                view.attention
                    .reason
                    .as_deref()
                    .unwrap_or("check last failure")
            )
        )
    } else {
        r#"<p class="muted">No attention needed.</p>"#.to_string()
    };
    Ok(Html(shell(
        "Handoff",
        &format!(
            r#"<div class="bar">
  <a class="btn" href="/status">Status</a>
  <a class="btn secondary" href="/api/handoff">JSON</a>
  <a class="btn secondary" href="/">Runs</a>
</div>
{attn}
<pre class="mono status-pre">{}</pre>
<details open><summary>JSON (resume pack when attention)</summary><pre class="mono">{}</pre></details>"#,
            html_escape(&text),
            html_escape(&json)
        ),
    )))
}

async fn run_export_html(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    let Some(run) = state.store.get_run(&run_id).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let events = state.store.get_events_limited(&run_id, 8_000).await?.0;
    let html = export_html_secure(&run, &events, true)?;
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

#[derive(Debug, Deserialize)]
struct RunsPageQuery {
    /// Opaque cursor from previous page (`next_cursor`).
    cursor: Option<String>,
    /// Page size (default 100, max 500).
    limit: Option<usize>,
    status: Option<String>,
    tag: Option<String>,
}

async fn api_runs(
    State(state): State<AppState>,
    Query(q): Query<RunsPageQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let filters = crate::storage::RunFilters {
        status: q.status,
        tag: q.tag,
    };
    let page = state
        .store
        .list_runs_page(q.cursor.as_deref(), limit, &filters)
        .await?;
    Ok(Json(serde_json::json!({
        "runs": page.runs,
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
        "limit": limit,
    })))
}

#[derive(Debug, Deserialize)]
struct EventsPageQuery {
    after: Option<u64>,
    before: Option<u64>,
    limit: Option<usize>,
    cursor: Option<String>,
    /// Comma-separated kinds for kind-filtered paging.
    kinds: Option<String>,
}

async fn api_events_page(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    Query(q): Query<EventsPageQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = q.limit.unwrap_or(500).clamp(1, 5_000);
    let run_id = resolve_prefix(state.store.as_ref(), &run_id).await?;
    let page = if let Some(ref kinds) = q.kinds {
        let kinds: Vec<&str> = kinds
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        state
            .store
            .get_events_by_kind_page(&run_id, &kinds, q.cursor.as_deref(), limit)
            .await?
    } else {
        let after = q
            .after
            .or_else(|| {
                q.cursor
                    .as_deref()
                    .and_then(crate::storage::decode_event_cursor)
                    .map(|c| c.sequence)
            })
            .unwrap_or(0);
        let before = q.before.unwrap_or(u64::MAX);
        state
            .store
            .get_events_range(&run_id, after, before, limit)
            .await?
    };
    Ok(Json(serde_json::json!({
        "events": page.events,
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
        "limit": limit,
    })))
}

/// SSE stream of run snapshots (initial + updates / new runs).
async fn api_runs_stream(
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    let permit = state
        .sse_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| anyhow::anyhow!("SSE connection limit reached"))?;
    let store = state.store.clone();
    let stream = stream::unfold(
        RunsStreamState {
            store,
            known: std::collections::HashMap::new(),
            bootstrapped: false,
            _permit: permit,
        },
        |mut st| async move {
            let runs = match st.store.list_runs().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "SSE: failed to list runs");
                    tokio::time::sleep(Duration::from_millis(800)).await;
                    return Some((
                        Ok(Event::default()
                            .event("error")
                            .data(format!("list_runs failed: {e}"))),
                        st,
                    ));
                }
            };

            for run in runs.iter().take(100) {
                let fingerprint = format!(
                    "{:?}|{:?}|{}|{}",
                    run.status,
                    run.exit_code,
                    run.tags.join(","),
                    run.name.as_deref().unwrap_or(""),
                );
                let changed = st
                    .known
                    .get(&run.id)
                    .map(|f| f != &fingerprint)
                    .unwrap_or(true);
                if changed {
                    st.known.insert(run.id.clone(), fingerprint);
                    match serde_json::to_string(run) {
                        Ok(data) => {
                            // One SSE frame per tick; remaining changes flush next poll.
                            return Some((Ok(Event::default().event("run").data(data)), st));
                        }
                        Err(e) => {
                            tracing::error!(error = %e, run_id = %run.id, "SSE: failed to serialize run");
                            st.known.remove(&run.id);
                            let err_data = serde_json::json!({"error": "serialization failed", "run_id": run.id});
                            return Some((
                                Ok(Event::default().event("error").data(err_data.to_string())),
                                st,
                            ));
                        }
                    }
                }
            }

            st.bootstrapped = true;
            tokio::time::sleep(Duration::from_millis(750)).await;
            Some((Ok(Event::default().event("ping").data("ok")), st))
        },
    );
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

struct RunsStreamState {
    store: Arc<SqliteStore>,
    known: std::collections::HashMap<String, String>,
    #[allow(dead_code)]
    bootstrapped: bool,
    /// Held for the lifetime of the stream so the concurrency limit is real.
    _permit: OwnedSemaphorePermit,
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
    Query(q): Query<EventsQuery>,
) -> Result<Response, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    // Cap protects dashboard RAM; limit=0 no longer means unlimited.
    let limit = q.limit.unwrap_or(5_000).clamp(1, API_EVENTS_HARD_CAP);
    let events = state.store.get_events_limited(&run_id, limit).await?.0;
    Ok(Json(serde_json::to_value(events)?).into_response())
}

/// Anomaly markers for a run (tool loops, destructive ops, storms, spikes, …).
async fn api_anomalies(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    if state.store.get_run(&run_id).await?.is_none() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    // Cap event load for dashboard RAM; anomaly detectors only need recent/all capped history.
    let events = state.store.get_events_limited(&run_id, 8_000).await?.0;
    let anomalies = crate::analysis::detect_anomalies(&events);
    Ok(Json(serde_json::json!({
        "run_id": run_id,
        "count": anomalies.len(),
        "anomalies": anomalies,
    }))
    .into_response())
}

async fn api_run_boundary(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    if state.store.get_run(&run_id).await?.is_none() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let boundary = state.store.get_run_boundary(&run_id).await?;
    let findings = state.store.list_boundary_findings(&run_id).await?;
    let containment = state.store.list_containment_receipts(&run_id).await?;
    let provenance = state.store.list_provenance_records(&run_id).await?;
    let external = state.store.list_external_evidence_for_run(&run_id).await?;
    let trust = crate::boundary::build_boundary_trust(
        boundary.as_ref(),
        &findings,
        &containment,
        &provenance,
        &external,
        &[],
    );
    Ok(Json(serde_json::json!({
        "run_id": run_id,
        "boundary": boundary,
        "trust": trust,
        "containment_receipts": containment,
        "provenance_records": provenance,
    }))
    .into_response())
}

async fn api_run_findings(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    if state.store.get_run(&run_id).await?.is_none() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let findings = state.store.list_boundary_findings(&run_id).await?;
    Ok(Json(serde_json::json!({
        "run_id": run_id,
        "count": findings.len(),
        "findings": findings,
    }))
    .into_response())
}

async fn api_run_evidence(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    if state.store.get_run(&run_id).await?.is_none() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let events = state.store.list_external_evidence_for_run(&run_id).await?;
    Ok(Json(serde_json::json!({
        "run_id": run_id,
        "count": events.len(),
        "events": events,
    }))
    .into_response())
}

#[derive(Deserialize)]
struct IncidentListQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}

async fn api_incidents(
    State(state): State<AppState>,
    Query(q): Query<IncidentListQuery>,
) -> Result<Response, AppError> {
    let limit = q.limit.unwrap_or(50);
    let cur = match q.cursor.as_deref() {
        Some(c) => Some(
            crate::incident::decode_incident_cursor(c)
                .ok_or_else(|| anyhow::anyhow!("invalid incident cursor"))?,
        ),
        None => None,
    };
    let page = state.store.list_incidents_page(cur.as_ref(), limit).await?;
    Ok(Json(page).into_response())
}

async fn api_incident(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    match state.store.get_incident(&id).await? {
        Some(inc) => Ok(Json(inc).into_response()),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
}

/// Server-Sent Events stream of run events (historical first, then live tail).
// NOTE: This SSE endpoint polls SQLite on every tick (400ms). When many
// clients connect simultaneously (thundering-herd), each poll contends on
// the Mutex<Connection>, serializing all readers. A future improvement
// would be to use a tokio::sync::watch or broadcast channel so the
// write-path notifies all active streams, eliminating polling entirely.
async fn api_event_stream(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    let permit = state
        .sse_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| anyhow::anyhow!("SSE connection limit reached"))?;
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    let store = state.store.clone();

    let stream = stream::unfold(
        StreamState {
            store,
            run_id,
            last_seq: 0,
            queue: VecDeque::new(),
            ticks_idle: 0,
            finished: false,
            _permit: permit,
        },
        |mut st| async move {
            // Drain queued events first
            if let Some(ev) = st.queue.pop_front() {
                return Some((Ok(ev), st));
            }

            // Incremental fetch by sequence — O(delta) not O(entire run) each tick.
            const BATCH: usize = 500;
            if let Ok(events) = st
                .store
                .get_events_since(&st.run_id, st.last_seq, BATCH)
                .await
            {
                for e in events {
                    if e.sequence > st.last_seq {
                        st.last_seq = e.sequence;
                    }
                    if let Ok(data) = serde_json::to_string(&e) {
                        st.queue
                            .push_back(Event::default().event("event").data(data));
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
                    st.queue
                        .push_back(Event::default().event("status").data(data.to_string()));
                } else if st.ticks_idle % 5 == 0 {
                    st.queue
                        .push_back(Event::default().event("status").data(data.to_string()));
                }
                if !finished {
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
            st.ticks_idle = st.ticks_idle.saturating_add(1);
            // heartbeat comment via empty data event name "ping"
            Some((Ok(Event::default().event("ping").data("ok")), st))
        },
    );

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

struct StreamState {
    store: Arc<SqliteStore>,
    run_id: String,
    /// Highest sequence delivered; next poll uses get_events_since.
    last_seq: u64,
    queue: VecDeque<Event>,
    ticks_idle: u32,
    finished: bool,
    /// Held for the lifetime of the stream so the concurrency limit is real.
    _permit: OwnedSemaphorePermit,
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

// ── Remote sync API ───────────────────────────────────────────────

async fn api_sync_manifest(
    State(state): State<AppState>,
) -> Result<Json<crate::sync::SyncManifest>, AppError> {
    let man = manifest_from_store(state.store.as_ref()).await?;
    Ok(Json(man))
}

async fn api_sync_get_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let run_id = resolve_prefix(state.store.as_ref(), &id).await?;
    let Some(run) = state.store.get_run(&run_id).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let events = state.store.get_events(&run_id).await?;
    // Full portable with blobs + H-08 blob body re-scan (same as CLI export)
    let json = export_portable_secure(state.store.as_ref(), &run, &events, true).await?;
    Ok(([(header::CONTENT_TYPE, "application/json")], json).into_response())
}

async fn api_sync_put_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: String,
) -> Result<Json<serde_json::Value>, AppError> {
    const MAX_SYNC_BODY: usize = 10 * 1024 * 1024; // 10 MB
    if body.len() > MAX_SYNC_BODY {
        return Err(AppError::payload_too_large(anyhow::anyhow!(
            "payload too large: exceeds 10 MB limit"
        )));
    }
    if state.token.is_none() {
        return Err(AppError::forbidden(anyhow::anyhow!(
            "sync PUT requires authentication: configure --token to enable"
        )));
    }
    // Prefer keep original ids so multi-machine ids stay stable
    let result = match import_portable(state.store.as_ref(), &body, false).await {
        Ok(r) => r,
        Err(_) => import_portable(state.store.as_ref(), &body, true).await?,
    };
    Ok(Json(serde_json::json!({
        "ok": true,
        "run_id": result.run_id,
        "events": result.events,
        "blobs": result.blobs,
        "requested_id": id,
        "remapped": result.remapped,
    })))
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

async fn resolve_prefix(store: &dyn TraceStore, spec: &str) -> Result<String, AppError> {
    if spec == "latest" {
        return store
            .list_runs()
            .await?
            .first()
            .map(|r| r.id.clone())
            .ok_or_else(|| AppError::not_found(anyhow::anyhow!("no runs")));
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
        0 => Err(AppError::not_found(anyhow::anyhow!(
            "run not found: {spec}"
        ))),
        _ => Err(AppError::bad_request(anyhow::anyhow!(
            "ambiguous run id: {spec}"
        ))),
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
.badge-anom {{ margin-left:0.2rem; font-weight:600; }}
.badge-high {{ background:#7f1d1d; color:#fecaca; }}
.badge-warn {{ background:#78350f; color:#fde68a; }}
.badge-info {{ background:color-mix(in srgb,var(--accent) 22%,transparent); }}
.anom-slot {{ display:inline; }}
.anom-bar {{ margin-top:0.25rem; }}
.trust-panel.trust-ok {{ border-color:color-mix(in srgb,#22c55e 40%,var(--border)); }}
.trust-panel.trust-bad {{ border-color:color-mix(in srgb,#ef4444 50%,var(--border)); }}
.signal-banner {{ margin:0.75rem 0; }}
.graph-wrap {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:0.75rem; overflow-x:auto; }}
.incident-graph {{ width:100%; max-width:960px; height:auto; display:block; }}
.g-run {{ fill:color-mix(in srgb,var(--accent) 35%,var(--card)); stroke:var(--accent); stroke-width:2; }}
.g-label {{ fill:var(--fg); font-size:11px; font-family:ui-monospace,Menlo,monospace; pointer-events:none; }}
.g-edge {{ fill:none; stroke:color-mix(in srgb,var(--accent) 55%,var(--muted)); stroke-width:1.5; opacity:0.85; }}
.g-signal {{ stroke:#ef4444; stroke-width:2.5; }}
.g-signal-label {{ fill:#ef4444; font-size:10px; font-weight:600; }}
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
        .replace('\'', "&#x27;")
}

fn urlencoding(s: &str) -> String {
    // Percent-encode characters that are unsafe in URLs
    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b' ' => result.push_str("%20"),
            b'/' => result.push_str("%2F"),
            b'?' => result.push_str("%3F"),
            b'#' => result.push_str("%23"),
            b'%' => result.push_str("%25"),
            b'&' => result.push_str("%26"),
            b'=' => result.push_str("%3D"),
            b'+' => result.push_str("%2B"),
            b'"' => result.push_str("%22"),
            b'<' => result.push_str("%3C"),
            b'>' => result.push_str("%3E"),
            b'\'' => result.push_str("%27"),
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

#[derive(Debug)]
enum AppErrorKind {
    NotFound(anyhow::Error),
    BadRequest(anyhow::Error),
    Forbidden(anyhow::Error),
    PayloadTooLarge(anyhow::Error),
    Internal(anyhow::Error),
}

struct AppError(AppErrorKind);

impl AppError {
    fn not_found(e: anyhow::Error) -> Self {
        Self(AppErrorKind::NotFound(e))
    }
    fn bad_request(e: anyhow::Error) -> Self {
        Self(AppErrorKind::BadRequest(e))
    }
    fn forbidden(e: anyhow::Error) -> Self {
        Self(AppErrorKind::Forbidden(e))
    }
    fn payload_too_large(e: anyhow::Error) -> Self {
        Self(AppErrorKind::PayloadTooLarge(e))
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        Self(AppErrorKind::Internal(e))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        Self(AppErrorKind::Internal(e.into()))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, err) = match self.0 {
            AppErrorKind::NotFound(e) => (StatusCode::NOT_FOUND, e),
            AppErrorKind::BadRequest(e) => (StatusCode::BAD_REQUEST, e),
            AppErrorKind::Forbidden(e) => (StatusCode::FORBIDDEN, e),
            AppErrorKind::PayloadTooLarge(e) => (StatusCode::PAYLOAD_TOO_LARGE, e),
            AppErrorKind::Internal(e) => {
                tracing::debug!(error = %e, "returning 500 Internal Server Error");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
                    .into_response();
            }
        };
        (status, format!("error: {}", err)).into_response()
    }
}

#[cfg(test)]
mod testing {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    impl AppState {
        /// Build a test [`AppState`] with no auth token.
        ///
        /// # Examples
        ///
        /// ```ignore
        /// // `cfg(test)` helper used by dashboard unit tests:
        /// // let state = AppState::new(Arc::new(SqliteStore::open_memory()?));
        /// ```
        pub fn new(store: Arc<SqliteStore>) -> Self {
            Self {
                store,
                token: None,
                sse_semaphore: Arc::new(Semaphore::new(100)),
                sessions: Arc::new(Mutex::new(HashMap::new())),
                login_failures: Arc::new(Mutex::new(Vec::new())),
                secure_cookies: false,
            }
        }
    }

    /// Minimal dashboard router for unit tests (subset of production routes).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // `cfg(test)` helper:
    /// // let router = build_router(AppState::new(store));
    /// ```
    pub fn build_router(state: AppState) -> Router {
        Router::new()
            .route("/api/runs", get(api_runs))
            .route("/api/runs/{id}", get(api_run))
            .route("/api/runs/{id}/events", get(api_events))
            .route("/api/runs/{id}/anomalies", get(api_anomalies))
            .route("/api/runs/{id}/boundary", get(api_run_boundary))
            .route("/api/runs/{id}/findings", get(api_run_findings))
            .route("/api/incidents", get(api_incidents))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_serve_endpoints() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());

        // Insert test data: two runs, each with events
        let run1 = crate::core::run::Run::new(vec!["echo".into(), "hello".into()], "/tmp".into());
        let mut run2 = crate::core::run::Run::new(vec!["ls".into(), "-la".into()], "/tmp".into());
        run2.name = Some("list-files".into());
        run2.tags = vec!["test".into()];
        store.insert_run(&run1).await.unwrap();
        store.insert_run(&run2).await.unwrap();

        let mut ev1 = crate::core::event::TraceEvent::new(
            &run1.id,
            crate::core::event::EventSource::Terminal,
            "terminal.output",
        );
        ev1.status = crate::core::event::EventStatus::Success;
        ev1.sequence = 0;
        store.insert_event(&ev1).await.unwrap();

        let mut ev2 = crate::core::event::TraceEvent::new(
            &run1.id,
            crate::core::event::EventSource::Tool,
            "tool.call",
        );
        ev2.status = crate::core::event::EventStatus::Running;
        ev2.sequence = 1;
        ev2.metadata
            .insert("tool_name".into(), serde_json::json!("Bash"));
        store.insert_event(&ev2).await.unwrap();

        let state = AppState::new(store.clone());
        let app = build_router(state);

        // ── Test GET /api/runs ────────────────────────────────
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/runs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        // Cursor-paginated envelope (1.5 P1): { runs, next_cursor, has_more, limit }
        let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let runs = page
            .get("runs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(runs.len(), 2, "should list both runs: {page}");

        // ── Test GET /api/runs/{id} ──────────────────────────
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/runs/{}", run1.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let run_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(run_json["id"].as_str().unwrap(), run1.id);
        assert_eq!(run_json["command"].as_array().unwrap().len(), 2);

        // ── Test GET /api/runs/{id}/events ────────────────────
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/runs/{}/events", run1.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(events.len(), 2, "should return both events for run1");
        assert_eq!(events[0]["sequence"].as_u64().unwrap(), 0);
        assert_eq!(events[1]["sequence"].as_u64().unwrap(), 1);

        // ── Test GET /api/runs/{id}/anomalies ─────────────────
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/runs/{}/anomalies", run1.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let anom_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(anom_json["run_id"].as_str().unwrap(), run1.id);
        assert!(anom_json["anomalies"].is_array());
        assert!(anom_json["count"].as_u64().is_some());

        // ── Test 404 for non-existent run ────────────────────
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/runs/nonexistent-id-12345")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "should return 404 for missing run"
        );
    }
    #[test]
    fn test_auth_token_comparison() {
        assert!(constant_time_eq(b"secret-token-123", b"secret-token-123"));
        assert!(!constant_time_eq(b"token-a", b"token-b"));
        assert!(!constant_time_eq(b"short", b"much-longer-token"));
        assert!(!constant_time_eq(b"", b"something"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"AAAA", b"BAAC"));
        assert!(!constant_time_eq(b"AAAA", b"AAB"));
    }

    fn state_with_token(token: Option<&str>) -> AppState {
        AppState {
            store: Arc::new(SqliteStore::open_memory().unwrap()),
            token: token.map(|s| s.to_string()),
            sse_semaphore: Arc::new(Semaphore::new(100)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            login_failures: Arc::new(Mutex::new(Vec::new())),
            secure_cookies: false,
        }
    }

    #[tokio::test]
    async fn test_auth_middleware_rejects_without_token() {
        let state = state_with_token(Some("test-secret"));
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(from_fn_with_state(state.clone(), auth_middleware))
            .with_state(state);
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // Browser HTML Accept → redirect to login; bare request → 401.
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_middleware_accepts_valid_token() {
        let state = state_with_token(Some("test-secret"));
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(from_fn_with_state(state.clone(), auth_middleware))
            .with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::AUTHORIZATION, "Bearer test-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_middleware_accepts_session_cookie() {
        let state = state_with_token(Some("test-secret"));
        let sid = "session-abc".to_string();
        state
            .sessions
            .lock()
            .insert(sid.clone(), Instant::now() + Duration::from_secs(60));
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(from_fn_with_state(state.clone(), auth_middleware))
            .with_state(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::COOKIE, format!("{SESSION_COOKIE}={sid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_middleware_passthrough_when_no_token() {
        let state = state_with_token(None);
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(from_fn_with_state(state.clone(), auth_middleware))
            .with_state(state);
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_middleware_sets_security_headers() {
        let state = state_with_token(None);
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(from_fn_with_state(state.clone(), auth_middleware))
            .with_state(state);
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let headers = resp.headers();
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
        assert!(headers
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("no-store"));
    }

    #[test]
    fn cookie_value_parses() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "foo=1; blackbox_session=abc123; bar=2".parse().unwrap(),
        );
        assert_eq!(
            cookie_value(&headers, SESSION_COOKIE).as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn session_cookie_flags() {
        let c = session_cookie_header("sid", true, 3600);
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Strict"));
        assert!(c.contains("Secure"));
        let c2 = session_cookie_header("sid", false, 3600);
        assert!(!c2.contains("Secure"));
    }

    async fn test_handler() -> (StatusCode, &'static str) {
        (StatusCode::OK, "ok")
    }
}
