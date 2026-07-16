//! Project memory pack (blackbox.memory/v1) — continuity plane for agent handoff.
//!
//! Builds a bounded project-level pack from sticky state + last ≤3 runs + live git porcelain.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::analysis::classifier::SideEffectClassifier;
use crate::context::{ErrorTop, FailedTool};
use crate::core::event::{EventStatus, SideEffect, TraceEvent};
use crate::core::run::{Run, RunStatus};
use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;
use crate::state::{ClaimPointer, IntentState, ProjectState, RunPointer};
use crate::storage::TraceStore;
use crate::summary::{build_summary, SummaryOptions, SummaryView};
use crate::util::{short_id, truncate};

pub const MEMORY_SCHEMA: &str = "blackbox.memory/v1";
pub const MAX_RUNS_SCANNED: usize = 3;
pub const MAX_EVENTS_PER_RUN: usize = 2000;
const PORCELAIN_TIMEOUT_MS: u64 = 500;
const HARD_DEGRADE_MS: u64 = 2000;

#[derive(Debug, Clone, Serialize)]
pub struct ProjectMemoryPack {
    pub schema: String,
    pub purpose: String,
    pub degraded: bool,
    pub project_root: String,
    pub store_db: String,
    pub generated_at: DateTime<Utc>,
    pub continuity_mode: String,
    pub headline: String,
    pub next_action: String,
    pub attention_reason: String,
    pub attention_level: String,
    pub intent: IntentView,
    pub claims: ClaimsSummaryView,
    pub last_run: Option<RunPointer>,
    pub predecessor_run: Option<RunPointer>,
    pub focus_run_id: Option<String>,
    pub files_touched: Vec<String>,
    pub destructive_paths: Vec<String>,
    pub side_effects_top: Vec<SideEffectSample>,
    pub secret_redaction_events: u32,
    pub git: GitMemoryView,
    pub failed_tools: Vec<FailedTool>,
    pub errors_top: Vec<ErrorTop>,
    pub summary: Option<SummaryView>,
    pub last_tools: Vec<String>,
    pub transcript_tail: Option<String>,
    pub resume_command: Option<Vec<String>>,
    pub approx_tokens: usize,
    pub truncated: bool,
    pub build_ms: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct IntentView {
    pub goal: Option<String>,
    pub plan_summary: Option<String>,
    pub open_items: Vec<String>,
    pub do_not_retry: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl From<&IntentState> for IntentView {
    fn from(i: &IntentState) -> Self {
        Self {
            goal: i.goal.clone(),
            plan_summary: i.plan_summary.clone(),
            open_items: i.open_items.clone(),
            do_not_retry: i.do_not_retry.clone(),
            notes: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ClaimsSummaryView {
    /// Whole-project exclusive claim.
    pub active: Option<ClaimPointer>,
    /// Non-overlapping path-scoped claims.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_claims: Vec<ClaimPointer>,
    pub conflicts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct GitMemoryView {
    pub dirty: bool,
    pub branch: Option<String>,
    pub head: Option<String>,
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub porcelain_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SideEffectSample {
    pub rank: u8,
    pub side_effect: String,
    pub kind: String,
    pub detail: String,
    pub sequence: u64,
    pub run_id: String,
}

#[derive(Debug, Clone)]
pub struct MemoryBuildOptions {
    pub max_tokens: usize,
    pub purpose: String,
    pub continuity_mode: String,
    pub project_root: PathBuf,
    pub store_db: PathBuf,
    /// Skip porcelain when attention is none (micro-opt for tiny ok packs).
    pub skip_porcelain_if_none: bool,
}

impl Default for MemoryBuildOptions {
    fn default() -> Self {
        Self {
            max_tokens: 4000,
            purpose: "project-memory".into(),
            continuity_mode: "always".into(),
            project_root: PathBuf::from("."),
            store_db: PathBuf::from(".blackbox/blackbox.db"),
            skip_porcelain_if_none: false,
        }
    }
}

fn approx_tokens(s: &str) -> usize {
    s.len().div_ceil(4)
}

fn side_effect_rank(se: &SideEffect) -> u8 {
    match se {
        SideEffect::Destructive => 4,
        SideEffect::ExternalWrite => 3,
        SideEffect::LocalWrite => 2,
        SideEffect::Read => 1,
        SideEffect::None | SideEffect::Unknown => 0,
    }
}

fn side_effect_str(se: &SideEffect) -> String {
    match se {
        SideEffect::None => "none".into(),
        SideEffect::Read => "read".into(),
        SideEffect::LocalWrite => "local-write".into(),
        SideEffect::ExternalWrite => "external-write".into(),
        SideEffect::Destructive => "destructive".into(),
        SideEffect::Unknown => "unknown".into(),
    }
}

/// True when a porcelain line only refers to blackbox store paths (not real WIP).
fn porcelain_line_is_blackbox_only(line: &str) -> bool {
    // Formats: "?? .blackbox/", " M path", "MM path", "R  old -> new", etc.
    let path_part = line.get(3..).unwrap_or(line).trim();
    let path = if let Some((_, dst)) = path_part.split_once(" -> ") {
        dst.trim()
    } else {
        path_part
    };
    let path = path.trim_matches('"');
    path == ".blackbox"
        || path.starts_with(".blackbox/")
        || path.ends_with("/.blackbox")
        || path.contains("/.blackbox/")
}

/// Live git status --porcelain with timeout (500ms). dirty=false on fail.
pub fn live_git_status(project_root: &Path) -> GitMemoryView {
    let mut view = GitMemoryView::default();
    let start = Instant::now();

    // porcelain
    let porcelain = run_git_timeout(
        project_root,
        &["status", "--porcelain"],
        PORCELAIN_TIMEOUT_MS,
    );
    if start.elapsed() > Duration::from_millis(PORCELAIN_TIMEOUT_MS + 50) {
        return view;
    }
    if let Some(out) = porcelain {
        // Ignore blackbox's own store so ambient capture never sticks attention=wip forever
        // on an otherwise clean tree (`.blackbox/` is usually gitignored but not always).
        let meaningful: Vec<&str> = out
            .lines()
            .filter(|line| !line.trim().is_empty() && !porcelain_line_is_blackbox_only(line))
            .collect();
        view.dirty = !meaningful.is_empty();
        if view.dirty {
            let mut modified = 0usize;
            let mut untracked = 0usize;
            for line in &meaningful {
                if line.starts_with("??") {
                    untracked += 1;
                } else {
                    modified += 1;
                }
            }
            view.summary = Some(format!("{modified} modified, {untracked} untracked"));
            // short hash for cache debug only
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(meaningful.join("\n").as_bytes());
            let dig = hasher.finalize();
            view.porcelain_hash = Some(hex::encode(&dig[..4]));
        } else {
            view.summary = Some("clean".into());
        }
    }

    if let Some(branch) = run_git_timeout(project_root, &["rev-parse", "--abbrev-ref", "HEAD"], 200)
    {
        let b = branch.trim().to_string();
        if !b.is_empty() && b != "HEAD" {
            view.branch = Some(b);
        }
    }
    if let Some(head) = run_git_timeout(project_root, &["rev-parse", "--short", "HEAD"], 200) {
        let h = head.trim().to_string();
        if !h.is_empty() {
            view.head = Some(h);
        }
    }
    view
}

fn run_git_timeout(cwd: &Path, args: &[&str], timeout_ms: u64) -> Option<String> {
    let mut child = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                let mut out = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    use std::io::Read;
                    let _ = stdout.read_to_string(&mut out);
                }
                return Some(out);
            }
            Ok(Some(_)) => return None,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return None,
        }
    }
}

fn tool_failure_detail(ev: &TraceEvent) -> String {
    for key in ["error", "output", "result", "message"] {
        if let Some(v) = ev.metadata.get(key) {
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let t = s.trim();
            if !t.is_empty() && t != "null" {
                return truncate(t, 240);
            }
        }
    }
    if let Some(v) = ev.metadata.get("input") {
        return truncate(&v.to_string(), 200);
    }
    if let Some(p) = ev.metadata.get("preview").and_then(|v| v.as_str()) {
        return truncate(p, 200);
    }
    String::new()
}

/// Build project memory pack from sticky + store (or degraded sticky-only).
pub async fn build_project_memory(
    store: Option<&dyn TraceStore>,
    sticky: &ProjectState,
    opts: MemoryBuildOptions,
) -> anyhow::Result<ProjectMemoryPack> {
    let t0 = Instant::now();
    let scanner = SecretScanner::new(RedactionConfig::default());
    let classifier = SideEffectClassifier::new();

    let attention_level = sticky.attention_level;
    let attention_reason = sticky
        .attention_reason
        .clone()
        .unwrap_or_else(|| attention_level.as_str().into());

    // Focus / predecessor selection
    let focus_id = sticky
        .unresolved_failure_id
        .clone()
        .or_else(|| sticky.last_run.as_ref().map(|r| r.id.clone()));

    let mut degraded = store.is_none();
    let mut focus_run: Option<Run> = None;
    let mut runs_to_scan: Vec<Run> = Vec::new();

    if let Some(store) = store {
        if let Ok(all) = store.list_runs().await {
            runs_to_scan = all.into_iter().take(MAX_RUNS_SCANNED).collect();
            if let Some(ref fid) = focus_id {
                focus_run = if let Some(r) = runs_to_scan.iter().find(|r| &r.id == fid) {
                    Some(r.clone())
                } else {
                    store.get_run(fid).await.ok().flatten()
                };
            }
            if focus_run.is_none() {
                focus_run = runs_to_scan.first().cloned();
            }
        } else {
            degraded = true;
        }
    }

    // Git porcelain
    let git = if opts.skip_porcelain_if_none && attention_level.is_none() {
        GitMemoryView {
            dirty: false,
            summary: Some("skipped".into()),
            ..Default::default()
        }
    } else {
        live_git_status(&opts.project_root)
    };

    // Aggregate from last ≤3 runs
    let mut files_touched: Vec<String> = Vec::new();
    let mut destructive_paths: Vec<String> = Vec::new();
    let mut side_effects_top: Vec<SideEffectSample> = Vec::new();
    let mut secret_redaction_events: u32 = 0;
    let mut failed_tools: Vec<FailedTool> = Vec::new();
    let mut errors_top: Vec<ErrorTop> = Vec::new();
    let mut last_tools: Vec<String> = Vec::new();
    let mut summary: Option<SummaryView> = None;
    let mut resume_command: Option<Vec<String>> = None;
    let mut transcript_tail: Option<String> = None;

    if let Some(store) = store {
        for run in &runs_to_scan {
            let (events, _) = store
                .get_events_limited(&run.id, MAX_EVENTS_PER_RUN)
                .await
                .unwrap_or((Vec::new(), false));

            for ev in &events {
                // redaction counts
                if let Some(n) = ev
                    .metadata
                    .get("redactions")
                    .and_then(|v| v.as_u64())
                    .or_else(|| ev.metadata.get("total_redactions").and_then(|v| v.as_u64()))
                {
                    secret_redaction_events = secret_redaction_events.saturating_add(n as u32);
                }

                // filesystem
                if ev.kind.starts_with("filesystem.")
                    && !ev.kind.contains("observer")
                    && !ev.kind.contains("snapshot")
                {
                    if let Some(p) = ev.metadata.get("path").and_then(|v| v.as_str()) {
                        let entry = format!("{}:{}", ev.kind, p);
                        if !files_touched.contains(&entry) {
                            files_touched.push(entry);
                        }
                        if ev.kind.contains("delete") || ev.kind.contains("remove") {
                            let d = p.to_string();
                            if !destructive_paths.contains(&d) {
                                destructive_paths.push(d);
                            }
                        }
                    }
                }

                // tools
                if ev.kind == "tool.call" || ev.kind == "tool.result" {
                    if let Some(name) = ev.metadata.get("tool_name").and_then(|v| v.as_str()) {
                        if ev.kind == "tool.call" {
                            last_tools.push(name.to_string());
                        }
                        if matches!(ev.status, EventStatus::Error)
                            && focus_run.as_ref().map(|r| r.id.as_str()) == Some(run.id.as_str())
                        {
                            failed_tools.push(FailedTool {
                                sequence: ev.sequence,
                                name: name.to_string(),
                                detail: scanner.redact(&tool_failure_detail(ev)),
                            });
                        }
                    }
                }

                // errors on focus run
                if focus_run.as_ref().map(|r| r.id.as_str()) == Some(run.id.as_str())
                    && matches!(ev.status, EventStatus::Error)
                    && errors_top.len() < 12
                {
                    if let Some(msg) = ev
                        .metadata
                        .get("error")
                        .and_then(|v| v.as_str())
                        .or_else(|| ev.metadata.get("message").and_then(|v| v.as_str()))
                        .or_else(|| ev.metadata.get("preview").and_then(|v| v.as_str()))
                    {
                        let msg = msg.trim();
                        if !msg.is_empty() {
                            errors_top.push(ErrorTop {
                                sequence: ev.sequence,
                                error_type: ev.kind.clone(),
                                message: scanner.redact(&truncate(msg, 200)),
                            });
                        }
                    }
                }

                // side effects
                let se = classifier.classify_event(ev);
                let rank = side_effect_rank(&se);
                if rank >= 2 {
                    let detail = scanner.redact(&event_detail_short(ev));
                    if se == SideEffect::Destructive {
                        if let Some(p) = ev.metadata.get("path").and_then(|v| v.as_str()) {
                            let d = p.to_string();
                            if !destructive_paths.contains(&d) {
                                destructive_paths.push(d);
                            }
                        }
                        // also from command paths
                        if let Some(cmd) = command_from_event(ev) {
                            for tok in cmd.split_whitespace().skip(1) {
                                if tok.starts_with('-') {
                                    continue;
                                }
                                if tok.contains('/') || tok.ends_with(".rs") {
                                    let d = tok.to_string();
                                    if !destructive_paths.contains(&d) {
                                        destructive_paths.push(d);
                                    }
                                }
                            }
                        }
                    }
                    side_effects_top.push(SideEffectSample {
                        rank,
                        side_effect: side_effect_str(&se),
                        kind: ev.kind.clone(),
                        detail,
                        sequence: ev.sequence,
                        run_id: run.id.clone(),
                    });
                }
            }
        }

        // Focus summary + transcript
        if let Some(ref run) = focus_run {
            if let Ok(sum) = build_summary(
                store,
                run,
                SummaryOptions {
                    short: true,
                    full: false,
                },
            )
            .await
            {
                resume_command = sum.resume.command.clone();
                if errors_top.is_empty() {
                    for e in sum.errors.iter().take(12) {
                        errors_top.push(ErrorTop {
                            sequence: e.sequence,
                            error_type: e.error_type.clone(),
                            message: scanner.redact(&truncate(&e.message, 200)),
                        });
                    }
                }
                summary = Some(sum);
            }

            // Skip transcript entirely when attention none
            if !attention_level.is_none() {
                if let Ok((events, _)) = store.get_events_limited(&run.id, MAX_EVENTS_PER_RUN).await
                {
                    if let Ok(full) =
                        crate::transcript::rebuild_terminal_transcript(store, &events).await
                    {
                        let tail_chars = opts.max_tokens.saturating_mul(2).min(8_000);
                        if full.len() > tail_chars {
                            let start = full
                                .char_indices()
                                .rev()
                                .nth(tail_chars)
                                .map(|(i, _)| i)
                                .unwrap_or(0);
                            transcript_tail = Some(scanner.redact(&full[start..]));
                        } else if !full.is_empty() {
                            transcript_tail = Some(scanner.redact(&full));
                        }
                    }
                }
            }
        }
    }

    // Cap lists
    files_touched.truncate(40);
    destructive_paths.truncate(15);
    // Rank side effects: Destructive > ExternalWrite > LocalWrite
    side_effects_top.sort_by(|a, b| b.rank.cmp(&a.rank).then(b.sequence.cmp(&a.sequence)));
    side_effects_top.truncate(12);
    failed_tools.truncate(20);
    errors_top.truncate(12);
    if last_tools.len() > 30 {
        last_tools = last_tools.split_off(last_tools.len() - 30);
    }

    // Claims (project + path-scoped)
    let now = Utc::now();
    let mut claims = ClaimsSummaryView::default();
    if let Some(ref c) = sticky.active_claim {
        if c.is_active(now) {
            claims.active = Some(c.clone());
        } else if c.status == "active" {
            claims.conflicts.push(format!(
                "expired claim was held by {} until {}",
                c.holder,
                c.expires_at.to_rfc3339()
            ));
        }
    }
    for c in &sticky.path_claims {
        if c.is_active(now) {
            claims.path_claims.push(c.clone());
        }
    }

    // Headline / next_action (never success-noop when WIP)
    let (headline, next_action) = build_headline_next(
        sticky,
        focus_run.as_ref(),
        &files_touched,
        &git,
        &failed_tools,
        &claims,
    );

    let mut pack = ProjectMemoryPack {
        schema: MEMORY_SCHEMA.into(),
        purpose: opts.purpose,
        degraded,
        project_root: opts.project_root.display().to_string(),
        store_db: opts.store_db.display().to_string(),
        generated_at: Utc::now(),
        continuity_mode: opts.continuity_mode,
        headline: scanner.redact(&headline),
        next_action: scanner.redact(&next_action),
        attention_reason: scanner.redact(&attention_reason),
        attention_level: attention_level.as_str().into(),
        intent: IntentView::from(&sticky.intent),
        claims,
        last_run: sticky.last_run.clone(),
        predecessor_run: sticky
            .last_run
            .clone()
            .filter(|_| focus_id.is_some())
            .or_else(|| sticky.last_failure.clone()),
        focus_run_id: focus_id.clone(),
        files_touched,
        destructive_paths,
        side_effects_top,
        secret_redaction_events,
        git,
        failed_tools,
        errors_top,
        summary,
        last_tools,
        transcript_tail,
        resume_command,
        approx_tokens: 0,
        truncated: false,
        build_ms: 0,
    };

    // Prefer focus pointer as predecessor when we have focus
    if let Some(ref fr) = focus_run {
        pack.predecessor_run = Some(RunPointer::from_run(fr));
        pack.focus_run_id = Some(fr.id.clone());
    }

    // Redact intent strings
    pack.intent.goal = pack.intent.goal.map(|g| scanner.redact(&g));
    pack.intent.plan_summary = pack.intent.plan_summary.map(|p| scanner.redact(&p));
    pack.intent.open_items = pack
        .intent
        .open_items
        .into_iter()
        .map(|s| scanner.redact(&s))
        .collect();
    pack.intent.do_not_retry = pack
        .intent
        .do_not_retry
        .into_iter()
        .map(|s| scanner.redact(&s))
        .collect();

    // Hard degrade if too slow
    if t0.elapsed() > Duration::from_millis(HARD_DEGRADE_MS) {
        pack.degraded = true;
    }

    // Tiny ok packs (attention none): drop bulk fields for M2a ≤400 token target
    if attention_level.is_none() {
        pack.transcript_tail = None;
        pack.last_tools.clear();
        pack.side_effects_top.clear();
        pack.summary = None;
        pack.failed_tools.clear();
        pack.errors_top.clear();
        pack.files_touched.clear();
        pack.destructive_paths.clear();
        pack.predecessor_run = None;
        // Keep headline/next/intent/claims/git light
        shrink_pack(&mut pack, opts.max_tokens.min(400));
    } else {
        shrink_pack(&mut pack, opts.max_tokens);
    }
    pack.build_ms = t0.elapsed().as_millis() as u64;
    Ok(pack)
}

fn build_headline_next(
    sticky: &ProjectState,
    focus: Option<&Run>,
    files: &[String],
    git: &GitMemoryView,
    failed_tools: &[FailedTool],
    claims: &ClaimsSummaryView,
) -> (String, String) {
    let short = focus
        .map(|r| short_id(&r.id).to_string())
        .or_else(|| sticky.last_run.as_ref().map(|r| r.short_id.clone()))
        .unwrap_or_else(|| "none".into());

    if sticky.unresolved_failure_id.is_some()
        || focus.map(|r| matches!(r.status, RunStatus::Failed | RunStatus::Cancelled)) == Some(true)
    {
        let tool_hint = failed_tools
            .first()
            .map(|t| format!("; last failed tool: {}", t.name))
            .unwrap_or_default();
        let headline = format!("Run {short} needs attention{tool_hint}");
        let next = if let Some(t) = failed_tools.first() {
            format!(
                "Inspect failed tool '{}' (seq {}), fix root cause, then retry; blackbox postmortem {short} --json",
                t.name, t.sequence
            )
        } else {
            format!(
                "Read errors_top and project memory, fix root cause; blackbox postmortem {short} --json"
            )
        };
        return (headline, next);
    }

    let wip = !sticky.intent.open_items.is_empty()
        || git.dirty
        || !files.is_empty()
        || claims.active.is_some();

    if wip {
        let mut bits = Vec::new();
        if git.dirty {
            bits.push("dirty tree".into());
        }
        if !files.is_empty() {
            bits.push(format!("{} files touched", files.len()));
        }
        if !sticky.intent.open_items.is_empty() {
            bits.push(format!("{} open items", sticky.intent.open_items.len()));
        }
        if claims.active.is_some() {
            bits.push("active claim".into());
        }
        let headline = format!("WIP after {short}: {}", bits.join(", "));
        let mut next =
            String::from("Continue from open items / dirty tree; do not redo completed work. ");
        if let Some(ref g) = sticky.intent.goal {
            next.push_str(&format!("Goal: {g}. "));
        }
        if let Some(ref c) = claims.active {
            next.push_str(&format!("Honor claim held by {}. ", c.holder));
        }
        next.push_str("blackbox handoff --json");
        return (headline, next);
    }

    let headline = if let Some(ref g) = sticky.intent.goal {
        format!("Project memory ok after {short}; goal: {g}")
    } else {
        format!("Project memory ok after {short}")
    };
    // Must NOT be the 1.1 success noop string
    let next = "Review project_memory; continue with user task or blackbox runs --json".into();
    (headline, next)
}

fn event_detail_short(ev: &TraceEvent) -> String {
    if let Some(name) = ev.metadata.get("tool_name").and_then(|v| v.as_str()) {
        return truncate(name, 80);
    }
    if let Some(p) = ev.metadata.get("path").and_then(|v| v.as_str()) {
        return truncate(p, 120);
    }
    if let Some(cmd) = command_from_event(ev) {
        return truncate(&cmd, 120);
    }
    truncate(&ev.kind, 80)
}

fn command_from_event(ev: &TraceEvent) -> Option<String> {
    if let Some(cmd) = ev.metadata.get("command").and_then(|v| {
        v.as_str().map(String::from).or_else(|| {
            v.as_array().map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
        })
    }) {
        return Some(cmd);
    }
    ev.metadata
        .get("input")
        .and_then(|i| i.get("command").or_else(|| i.get("cmd")))
        .and_then(|c| c.as_str())
        .map(String::from)
}

/// Budget shrink order per design (transcript first → … → never drop headline/intent core).
pub fn shrink_pack(pack: &mut ProjectMemoryPack, max_tokens: usize) {
    loop {
        let json = serde_json::to_string(pack).unwrap_or_default();
        pack.approx_tokens = approx_tokens(&json);
        if pack.approx_tokens <= max_tokens {
            break;
        }
        // 9. transcript_tail
        if let Some(ref mut t) = pack.transcript_tail {
            if t.len() > 200 {
                let new_len = t.len() / 2;
                let start = t.floor_char_boundary(t.len() - new_len);
                *t = t[start..].to_string();
                pack.truncated = true;
                continue;
            } else {
                pack.transcript_tail = None;
                pack.truncated = true;
                continue;
            }
        }
        // 8. last_tools
        if pack.last_tools.len() > 10 {
            pack.last_tools = pack
                .last_tools
                .split_off(pack.last_tools.len().saturating_sub(10));
            pack.truncated = true;
            continue;
        }
        if !pack.last_tools.is_empty() {
            pack.last_tools.clear();
            pack.truncated = true;
            continue;
        }
        // 7. predecessor (keep id via focus)
        if pack.summary.is_some() {
            pack.summary = None;
            pack.truncated = true;
            continue;
        }
        // 6. side effects / redaction stays as count
        if pack.side_effects_top.len() > 3 {
            pack.side_effects_top.truncate(3);
            pack.truncated = true;
            continue;
        }
        if !pack.side_effects_top.is_empty() {
            pack.side_effects_top.clear();
            pack.truncated = true;
            continue;
        }
        // 5. files / destructive
        if pack.files_touched.len() > 5 {
            pack.files_touched.truncate(5);
            pack.truncated = true;
            continue;
        }
        if !pack.files_touched.is_empty() {
            pack.files_touched.clear();
            pack.truncated = true;
            continue;
        }
        if !pack.destructive_paths.is_empty() {
            pack.destructive_paths.clear();
            pack.truncated = true;
            continue;
        }
        // 4. failed_tools / errors detail shrink
        if pack.failed_tools.len() > 3 {
            pack.failed_tools.truncate(3);
            pack.truncated = true;
            continue;
        }
        let mut shrunk = false;
        for t in &mut pack.failed_tools {
            if t.detail.len() > 40 {
                t.detail = truncate(&t.detail, 40);
                shrunk = true;
            }
        }
        if shrunk {
            pack.truncated = true;
            continue;
        }
        if pack.errors_top.len() > 3 {
            pack.errors_top.truncate(3);
            pack.truncated = true;
            continue;
        }
        // intent open_items shrink last among middle tier
        if pack.intent.open_items.len() > 3 {
            pack.intent.open_items.truncate(3);
            pack.truncated = true;
            continue;
        }
        pack.truncated = true;
        break;
    }
}

/// Format MEMORY.md human text from pack.
pub fn format_memory_markdown(pack: &ProjectMemoryPack) -> String {
    let mut out = String::new();
    out.push_str("# blackbox project memory\n\n");
    out.push_str(&format!(
        "schema: {} · continuity: {} · attention: {}{}\n\n",
        pack.schema,
        pack.continuity_mode,
        pack.attention_level,
        if pack.degraded { " · degraded" } else { "" }
    ));
    out.push_str(&format!("**{}**\n\n", pack.headline));
    out.push_str(&format!("## Next action\n{}\n\n", pack.next_action));
    if !pack.attention_reason.is_empty() {
        out.push_str(&format!("Attention reason: {}\n\n", pack.attention_reason));
    }
    if pack.intent.goal.is_some()
        || !pack.intent.open_items.is_empty()
        || !pack.intent.do_not_retry.is_empty()
    {
        out.push_str("## Intent\n");
        if let Some(ref g) = pack.intent.goal {
            out.push_str(&format!("- goal: {g}\n"));
        }
        if let Some(ref p) = pack.intent.plan_summary {
            out.push_str(&format!("- plan: {p}\n"));
        }
        for item in &pack.intent.open_items {
            out.push_str(&format!("- open: {item}\n"));
        }
        for d in &pack.intent.do_not_retry {
            out.push_str(&format!("- do_not_retry: {d}\n"));
        }
        out.push('\n');
    }
    if let Some(ref c) = pack.claims.active {
        out.push_str(&format!(
            "## Active claim\n- {} ({}) until {}\n\n",
            c.holder,
            c.holder_kind,
            c.expires_at.to_rfc3339()
        ));
    }
    for conf in &pack.claims.conflicts {
        out.push_str(&format!("- conflict: {conf}\n"));
    }
    if pack.git.dirty || pack.git.branch.is_some() {
        out.push_str(&format!(
            "## Git\n- dirty: {} · branch: {} · head: {} · {}\n\n",
            pack.git.dirty,
            pack.git.branch.as_deref().unwrap_or("?"),
            pack.git.head.as_deref().unwrap_or("?"),
            pack.git.summary.as_deref().unwrap_or("")
        ));
    }
    if !pack.failed_tools.is_empty() {
        out.push_str("## Failed tools\n");
        for t in &pack.failed_tools {
            out.push_str(&format!("- seq={} {} {}\n", t.sequence, t.name, t.detail));
        }
        out.push('\n');
    }
    if !pack.errors_top.is_empty() {
        out.push_str("## Top errors\n");
        for e in pack.errors_top.iter().take(8) {
            out.push_str(&format!(
                "- seq={} [{}] {}\n",
                e.sequence, e.error_type, e.message
            ));
        }
        out.push('\n');
    }
    if !pack.files_touched.is_empty() {
        out.push_str("## Files touched\n");
        for f in pack.files_touched.iter().take(20) {
            out.push_str(&format!("- {f}\n"));
        }
        out.push('\n');
    }
    if !pack.destructive_paths.is_empty() {
        out.push_str("## Destructive paths\n");
        for p in &pack.destructive_paths {
            out.push_str(&format!("- {p}\n"));
        }
        out.push('\n');
    }
    if pack.secret_redaction_events > 0 {
        out.push_str(&format!(
            "Secret redaction events observed: {}\n\n",
            pack.secret_redaction_events
        ));
    }
    if let Some(ref tail) = pack.transcript_tail {
        out.push_str("## Transcript tail\n```\n");
        out.push_str(tail);
        if !tail.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("```\n\n");
    }
    out.push_str(&format!(
        "tokens≈{}{} · build_ms={}\n",
        pack.approx_tokens,
        if pack.truncated { " (truncated)" } else { "" },
        pack.build_ms
    ));
    out
}

/// Write MEMORY.md + MEMORY.json (+ optional RESUME identical copies).
pub fn write_memory_files(
    blackbox_root: &Path,
    pack: &ProjectMemoryPack,
    also_resume_copies: bool,
) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(blackbox_root)?;
    crate::privacy::restrict_dir(blackbox_root);
    let md = format_memory_markdown(pack);
    let md_path = blackbox_root.join("MEMORY.md");
    let json_path = blackbox_root.join("MEMORY.json");
    let json = serde_json::to_string_pretty(pack)?;
    // Seal when store.key is present (encrypt_blobs). Agents that need plain
    // MEMORY.md for prompt inject still get plaintext markdown by design —
    // only JSON sidecars are sealed (structured pack is the high-value dump).
    let crypto = crate::crypto::sticky_crypto(blackbox_root);
    // Markdown stays readable for handoff/preamble; JSON pack may be sealed.
    std::fs::write(&md_path, &md)?;
    crate::privacy::restrict_file(&md_path);
    crate::crypto::write_maybe_sealed(&json_path, json.as_bytes(), crypto.as_ref())?;
    if also_resume_copies {
        let resume_md = blackbox_root.join("RESUME.md");
        let resume_json = blackbox_root.join("RESUME.json");
        std::fs::write(&resume_md, &md)?;
        crate::privacy::restrict_file(&resume_md);
        crate::crypto::write_maybe_sealed(&resume_json, json.as_bytes(), crypto.as_ref())?;
    }
    Ok(md_path)
}

/// Compact preamble for argv injection (untrusted delimiters).
pub fn compact_memory_preamble(pack: &ProjectMemoryPack, memory_file: &Path) -> String {
    let claim = pack
        .claims
        .active
        .as_ref()
        .map(|c| format!("{} until {}", c.holder, c.expires_at.to_rfc3339()))
        .unwrap_or_else(|| "none".into());
    let mut s = format!(
        "<<<BLACKBOX_UNTRUSTED_MEMORY>>>\n\
         [blackbox memory] {}\n\
         next: {}\n\
         claim: {}\n\
         full: {}\n\
         <<<END_BLACKBOX_UNTRUSTED_MEMORY>>>",
        pack.headline,
        pack.next_action,
        claim,
        memory_file.display()
    );
    if s.len() > 1500 {
        s.truncate(s.floor_char_boundary(1500));
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus, TraceEvent};
    use crate::core::run::{Run, RunStatus};
    use crate::state::AttentionLevel;
    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn pack_failed_run_has_tools() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let mut run = Run::new(
            vec!["claude".into(), "-p".into(), "x".into()],
            "/tmp".into(),
        );
        run.status = RunStatus::Failed;
        run.exit_code = Some(1);
        store.insert_run(&run).await.unwrap();

        let mut call = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
        call.metadata
            .insert("tool_name".into(), serde_json::json!("Bash"));
        call.status = EventStatus::Success;
        store.insert_event(&call).await.unwrap();

        let mut res = TraceEvent::new(&run.id, EventSource::Tool, "tool.result");
        res.metadata
            .insert("tool_name".into(), serde_json::json!("Bash"));
        res.metadata
            .insert("error".into(), serde_json::json!("permission denied"));
        res.status = EventStatus::Error;
        store.insert_event(&res).await.unwrap();

        let mut sticky = ProjectState::default();
        sticky.record_run(&run);

        let pack = build_project_memory(
            Some(store.as_ref() as &dyn TraceStore),
            &sticky,
            MemoryBuildOptions {
                max_tokens: 4000,
                project_root: PathBuf::from("/tmp"),
                store_db: PathBuf::from("/tmp/db"),
                continuity_mode: "always".into(),
                purpose: "project-memory".into(),
                skip_porcelain_if_none: true,
            },
        )
        .await
        .unwrap();

        assert!(!pack.headline.is_empty());
        assert!(!pack.next_action.is_empty());
        assert_eq!(pack.attention_level, "continue");
        assert!(!pack.failed_tools.is_empty());
        assert!(pack.approx_tokens <= 4000);
    }

    #[tokio::test]
    async fn shrink_drops_transcript_before_headline() {
        let mut pack = ProjectMemoryPack {
            schema: MEMORY_SCHEMA.into(),
            purpose: "test".into(),
            degraded: false,
            project_root: "/tmp".into(),
            store_db: "/tmp/db".into(),
            generated_at: Utc::now(),
            continuity_mode: "always".into(),
            headline: "KEEP_HEADLINE".into(),
            next_action: "KEEP_NEXT".into(),
            attention_reason: "failed".into(),
            attention_level: "continue".into(),
            intent: IntentView {
                goal: Some("goal".into()),
                open_items: vec!["a".into()],
                ..Default::default()
            },
            claims: ClaimsSummaryView::default(),
            last_run: None,
            predecessor_run: None,
            focus_run_id: None,
            files_touched: vec![],
            destructive_paths: vec![],
            side_effects_top: vec![],
            secret_redaction_events: 0,
            git: GitMemoryView::default(),
            failed_tools: vec![FailedTool {
                sequence: 1,
                name: "Bash".into(),
                detail: "err".into(),
            }],
            errors_top: vec![],
            summary: None,
            last_tools: vec!["a".into(); 20],
            transcript_tail: Some("x".repeat(5000)),
            resume_command: None,
            approx_tokens: 0,
            truncated: false,
            build_ms: 0,
        };
        shrink_pack(&mut pack, 200);
        assert_eq!(pack.headline, "KEEP_HEADLINE");
        assert_eq!(pack.next_action, "KEEP_NEXT");
        assert!(!pack.failed_tools.is_empty());
        assert!(
            pack.transcript_tail.is_none() || pack.transcript_tail.as_ref().unwrap().len() < 200
        );
        assert!(pack.truncated);
    }

    #[tokio::test]
    async fn success_wip_next_action_not_noop() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let mut run = Run::new(vec!["true".into()], "/tmp".into());
        run.status = RunStatus::Succeeded;
        run.exit_code = Some(0);
        store.insert_run(&run).await.unwrap();

        let mut fs = TraceEvent::new(&run.id, EventSource::Filesystem, "filesystem.write");
        fs.metadata
            .insert("path".into(), serde_json::json!("src/lib.rs"));
        store.insert_event(&fs).await.unwrap();

        let mut sticky = ProjectState::default();
        apply_run_outcome_wip(&mut sticky, &run);

        let pack = build_project_memory(
            Some(store.as_ref() as &dyn TraceStore),
            &sticky,
            MemoryBuildOptions {
                max_tokens: 4000,
                project_root: PathBuf::from("/tmp"),
                store_db: PathBuf::from("/tmp/db"),
                skip_porcelain_if_none: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert!(!pack.next_action.contains("No failure attention required"));
        assert!(pack.attention_level != "none" || !pack.files_touched.is_empty() || pack.git.dirty);
    }

    fn apply_run_outcome_wip(state: &mut ProjectState, run: &Run) {
        use crate::state::{apply_run_outcome, OutcomeExtras};
        apply_run_outcome(
            state,
            run,
            OutcomeExtras {
                files_touched_nonempty: true,
                ..Default::default()
            },
        );
    }

    #[test]
    fn ignores_blackbox_store_in_porcelain() {
        assert!(porcelain_line_is_blackbox_only("?? .blackbox/"));
        assert!(porcelain_line_is_blackbox_only("?? .blackbox/state.json"));
        assert!(porcelain_line_is_blackbox_only(" M .blackbox/config.toml"));
        assert!(!porcelain_line_is_blackbox_only(" M src/main.rs"));
        assert!(!porcelain_line_is_blackbox_only("?? README.md"));
    }

    #[tokio::test]
    async fn attention_none_skips_transcript() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let mut run = Run::new(vec!["true".into()], "/tmp".into());
        run.status = RunStatus::Succeeded;
        run.exit_code = Some(0);
        store.insert_run(&run).await.unwrap();
        let mut term = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        term.metadata
            .insert("preview".into(), serde_json::json!("hello world output"));
        store.insert_event(&term).await.unwrap();

        let mut sticky = ProjectState::default();
        sticky.record_run(&run);
        assert_eq!(sticky.attention_level, AttentionLevel::None);

        let pack = build_project_memory(
            Some(store.as_ref() as &dyn TraceStore),
            &sticky,
            MemoryBuildOptions {
                skip_porcelain_if_none: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(pack.transcript_tail.is_none());
        assert!(!pack.headline.is_empty());
    }
}
