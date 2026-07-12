use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::config::{discover_project, CapturePolicy};
use crate::output::{self, OutputMode};
use crate::storage::sqlite::SqliteStore;
use crate::storage::TraceStore;
use crate::views;

/// Default bind address for `blackbox serve`.
#[allow(dead_code)] // documented constant — clap requires a string literal for default_value
const DEFAULT_SERVE_PORT: &str = "127.0.0.1:7788";
/// A flight recorder and debugger for AI-agent runs
#[derive(Parser)]
#[command(name = "blackbox")]
#[command(version, about)]
pub struct Cli {
    /// SQLite database path (default: .blackbox/blackbox.db, or BLACKBOX_DB)
    #[arg(long, global = true, env = "BLACKBOX_DB")]
    pub store: Option<PathBuf>,

    /// Machine-readable JSON envelope on stdout (`blackbox.cli/v1`)
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    pub fn output_mode(&self) -> OutputMode {
        OutputMode::from_flag(self.json)
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Run a command under observation
    Run(RunArgs),
    /// List recorded runs
    Runs(RunsArgs),
    /// Show details of a specific run (text summary; use --tui for interactive)
    Show(ShowArgs),
    /// Display the timeline of a run
    Timeline(TimelineArgs),
    /// Inspect a specific event in a run
    Inspect(InspectArgs),
    /// Compare two runs
    Diff(DiffArgs),
    /// Export a run trace (redacted by default)
    Export(ExportArgs),
    /// Import a portable JSON archive into the store
    Import(ImportArgs),
    /// Replay a run (timeline, mock, sandbox, or live)
    Replay(ReplayArgs),
    /// Fork a new run from recorded context
    Fork(ForkArgs),
    /// Run analysis passes (errors, side-effects, correlations)
    Analyze(AnalyzeArgs),
    /// Re-redact secrets in historical traces (at-rest cleanup)
    Scrub(ScrubArgs),
    /// Diagnose store path, schema, and environment
    Doctor(DoctorArgs),
    /// Delete one or more runs
    Rm(RmArgs),
    /// Purge runs by policy (keep N, pending forks, failed, …)
    Purge(PurgeArgs),
    /// Search runs and events
    Search(SearchArgs),
    /// Live-tail events for a run as they appear
    Watch(WatchArgs),
    /// List tags and their run counts
    Tags,
    /// Add or remove tags on a run
    Tag(TagArgs),
    /// Aggregate stats for the store
    Stats(StatsArgs),
    /// Generate shell completions
    Completions(CompletionsArgs),
    /// Local web dashboard for browsing runs
    Serve(ServeArgs),
    /// Sync runs with a shared directory (push/pull portable archives)
    Sync(SyncArgs),
    /// Project-gated ambient capture (used by shell wrappers)
    MaybeRun(MaybeRunArgs),
    /// Enable ambient capture for this project
    Enable(EnableArgs),
    /// Disable ambient capture for this project
    Disable,
    /// One-command postmortem of a run
    Postmortem(SummaryArgs),
    /// Alias for postmortem
    Summary(SummaryArgs),
    /// Policy retention dry-run / apply (alias: purge --policy-from-config)
    Gc(GcArgs),
    /// Bounded resume context pack for agents
    Context(ContextArgs),
    /// Project status: capture, last run, attention (agent-friendly)
    Status(StatusArgs),
    /// Agent handoff: status + resume pack when attention is needed
    Handoff(HandoffArgs),
}

#[derive(Args, Default)]
pub struct StatusArgs {
    /// Attach a resume pack when attention is needed
    #[arg(long)]
    pub resume: bool,

    /// Approximate max tokens for an attached resume pack
    #[arg(long, default_value_t = 4000)]
    pub max_tokens: usize,
}

#[derive(Args, Default)]
pub struct HandoffArgs {
    /// Approximate max tokens for the resume pack
    #[arg(long, default_value_t = 4000)]
    pub max_tokens: usize,

    /// Always attach resume pack for last run (even if succeeded)
    #[arg(long)]
    pub always: bool,
}

#[derive(Args)]
pub struct ContextArgs {
    /// Run ID, prefix, or "latest"
    pub run_id: String,

    /// Emit a pack suitable for pasting into a resume prompt
    #[arg(long)]
    pub for_resume: bool,

    /// Approximate max tokens for the pack (chars/4)
    #[arg(long, default_value_t = 4000)]
    pub max_tokens: usize,

    /// Omit terminal transcript tail
    #[arg(long)]
    pub no_transcript: bool,
}

#[derive(Args)]
pub struct SyncArgs {
    #[command(subcommand)]
    pub action: SyncAction,
}

#[derive(Subcommand)]
pub enum SyncAction {
    /// Export local runs into a sync directory
    Push(SyncDirArgs),
    /// Import missing runs from a sync directory
    Pull(SyncDirArgs),
}

#[derive(Args)]
pub struct SyncDirArgs {
    /// Sync directory (shared via NFS/rsync/cloud drive)
    #[arg(long, default_value = ".blackbox/sync")]
    pub dir: String,

    /// Remote HTTP base URL of another `blackbox serve` (e.g. http://host:7788)
    #[arg(long)]
    pub remote: Option<String>,

    /// S3 URL (s3://bucket/prefix) — uses AWS_* env credentials
    #[arg(long)]
    pub s3: Option<String>,

    /// Auth token for --remote (or BLACKBOX_SERVE_TOKEN)
    #[arg(long, env = "BLACKBOX_SERVE_TOKEN")]
    pub token: Option<String>,

    /// Redact secrets when pushing (default: true)
    #[arg(long, default_value_t = true)]
    pub redact: bool,

    /// Include secrets in push archives (dangerous)
    #[arg(long)]
    pub no_redact: bool,
}

#[derive(Args, Default)]
pub struct DoctorArgs {
    /// Rebuild the FTS5 full-text index
    #[arg(long)]
    pub reindex: bool,
}

#[derive(Args)]
pub struct ServeArgs {
    /// Bind address (default 127.0.0.1:7788)
    #[arg(long, default_value = "127.0.0.1:7788")]
    pub bind: String,

    /// Rebuild FTS index before serving
    #[arg(long)]
    pub reindex: bool,

    /// Require this shared secret (Authorization: Bearer or ?token=)
    #[arg(long, env = "BLACKBOX_SERVE_TOKEN")]
    pub token: Option<String>,
}

#[derive(Args)]
pub struct RunsArgs {
    /// Only show runs with this tag (repeatable; any match)
    #[arg(long)]
    pub tag: Vec<String>,

    /// Filter by status (Succeeded, Failed, Pending, Running, …)
    #[arg(long)]
    pub status: Option<String>,

    /// Max runs to list (default: all)
    #[arg(long)]
    pub limit: Option<usize>,

    /// Show tags column
    #[arg(long)]
    pub show_tags: bool,
}

#[derive(Args)]
pub struct TagArgs {
    /// Run ID, prefix, or "latest"
    pub run_id: String,

    /// Tags to add
    #[arg(long = "add")]
    pub add: Vec<String>,

    /// Tags to remove
    #[arg(long = "rm")]
    pub rm: Vec<String>,
}

#[derive(Args)]
pub struct StatsArgs {
    /// Max recent runs to sample for event totals (default: 50)
    #[arg(long, default_value = "50")]
    pub max_runs: usize,
}

#[derive(Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    pub shell: Shell,
}

#[derive(Args)]
pub struct SearchArgs {
    /// Search query (all terms must match)
    pub query: String,

    /// Max runs to scan (most recent first)
    #[arg(long, default_value = "50")]
    pub max_runs: usize,

    /// Max hits to print
    #[arg(long, default_value = "40")]
    pub limit: usize,
}

#[derive(Args)]
pub struct WatchArgs {
    /// Run ID, prefix, or "latest" (default: latest)
    #[arg(default_value = "latest")]
    pub run_id: String,

    /// Poll interval in milliseconds
    #[arg(long, default_value = "500")]
    pub interval_ms: u64,

    /// Hide bookkeeping noise
    #[arg(long, default_value_t = true)]
    pub semantic: bool,

    /// Exit after this many idle seconds with no new events (0 = never)
    #[arg(long, default_value = "0")]
    pub idle_exit: u64,
}

#[derive(Args)]
pub struct RunArgs {
    /// Label for this run
    #[arg(long)]
    pub name: Option<String>,

    /// Project directory (defaults to cwd)
    #[arg(long)]
    pub project: Option<String>,

    /// Tags for this run (repeatable)
    #[arg(long)]
    pub tag: Vec<String>,

    /// Store raw (unredacted) terminal bytes as blobs. Dangerous.
    #[arg(long)]
    pub insecure_raw: bool,

    /// Disable redaction entirely (even more dangerous than --insecure-raw)
    #[arg(long)]
    pub no_redact: bool,

    /// The command to observe (everything after `--`)
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Args)]
pub struct ShowArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,

    /// Open the interactive TUI instead of a text summary
    #[arg(long)]
    pub tui: bool,

    /// Print reconstructed terminal transcript
    #[arg(long)]
    pub transcript: bool,

    /// Print tool-call summary transcript
    #[arg(long)]
    pub tools: bool,
}

#[derive(Args)]
pub struct TimelineArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,

    /// Hide bookkeeping events (pty/fs observer start/stop, etc.)
    #[arg(long, default_value_t = true)]
    pub semantic: bool,
    /// Only show events whose kind contains this substring (repeatable)
    #[arg(long)]
    pub kind: Vec<String>,

    /// Only show events from this source (e.g. Tool, Terminal, Git)
    #[arg(long)]
    pub source: Option<String>,
}

#[derive(Args)]
pub struct RmArgs {
    /// Run IDs, prefixes, or "latest" (one or more)
    pub run_ids: Vec<String>,

    /// Also garbage-collect unreferenced blobs after delete
    #[arg(long)]
    pub gc: bool,

    /// Skip confirmation prompt when deleting multiple
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct PurgeArgs {
    /// Keep only the N most recent runs (delete older)
    #[arg(long)]
    pub keep: Option<usize>,

    /// Delete Pending runs (e.g. unused forks)
    #[arg(long)]
    pub pending: bool,

    /// Delete Failed runs
    #[arg(long)]
    pub failed: bool,

    /// Also garbage-collect unreferenced blobs
    #[arg(long)]
    pub gc: bool,

    /// Required: confirm destructive purge
    #[arg(long)]
    pub yes: bool,

    /// Apply retention from `.blackbox/config.toml` (dry-run unless --yes)
    #[arg(long)]
    pub policy_from_config: bool,
}

#[derive(Args)]
pub struct MaybeRunArgs {
    /// Optional label
    #[arg(long)]
    pub name: Option<String>,

    /// Command after `--`
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Args, Default)]
pub struct EnableArgs {
    /// Install managed shell wrappers into rc / fish conf.d (idempotent)
    #[arg(long)]
    pub install_shell: bool,

    /// Remove managed shell wrappers from rc / fish conf.d
    #[arg(long)]
    pub uninstall_shell: bool,

    /// Shell for snippets/install: fish, bash, zsh (default: detect)
    #[arg(long)]
    pub shell: Option<String>,
}

#[derive(Args)]
pub struct SummaryArgs {
    /// Run ID, prefix, or "latest"
    pub run_id: String,

    /// Smaller event window (fast path)
    #[arg(long)]
    pub short: bool,

    /// Larger SQL limit for big runs
    #[arg(long)]
    pub full: bool,
}

#[derive(Args)]
pub struct GcArgs {
    /// Apply deletions (requires --yes)
    #[arg(long)]
    pub apply: bool,

    /// Confirm apply
    #[arg(long)]
    pub yes: bool,

    /// Also GC orphan blobs after delete
    #[arg(long)]
    pub gc: bool,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,
    /// Event ID, unique prefix, sequence number, or "latest"
    pub event_id: String,
}

#[derive(Args)]
pub struct DiffArgs {
    /// First run ID, prefix, or "latest"
    pub run_a: String,
    /// Second run ID, prefix, or "latest"
    pub run_b: String,

    /// Ordered tool/event trajectory alignment (greedy LCP)
    #[arg(long)]
    pub trajectory: bool,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ExportFormat {
    /// JSON Lines format
    Jsonl,
    /// Standalone HTML report
    Html,
    /// Portable archive with all blobs
    Portable,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,

    /// Export format
    #[arg(long, default_value = "jsonl")]
    pub format: ExportFormat,

    // TODO(L-20): add --output / -o flag to write to a file instead of stdout
    /// Include secrets (disable redaction). Default is redacted.
    #[arg(long)]
    pub no_redact: bool,
}

#[derive(Args)]
pub struct ImportArgs {
    /// Path to portable JSON file, or "-" for stdin
    pub path: String,

    /// Keep original ids (fails if run already exists). Default: assign new ids.
    #[arg(long)]
    pub keep_ids: bool,
}

#[derive(Args)]
pub struct ReplayArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,

    /// Mock tool calls with recorded outputs (filesystem unchanged)
    #[arg(long)]
    pub mock_tools: bool,

    /// Run in a sandbox (temporary workspace, side effects blocked)
    #[arg(long)]
    pub sandbox: bool,

    /// Run live against the current environment (dangerous)
    #[arg(long)]
    pub live: bool,

    /// Event ID (or prefix) to start replay from
    #[arg(long)]
    pub from: Option<String>,
}

#[derive(Args)]
pub struct ForkArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,

    /// Event ID (or prefix) to fork from
    #[arg(long)]
    pub at: Option<String>,

    /// Label for the new run
    #[arg(long)]
    pub name: Option<String>,

    /// After forking, launch the harness resume command under blackbox
    #[arg(long)]
    pub launch: bool,
}

#[derive(Args)]
pub struct AnalyzeArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,

    /// Persist derived analysis events back into the store
    #[arg(long)]
    pub persist: bool,
}

#[derive(Args)]
pub struct ScrubArgs {
    /// Run ID, prefix, "latest", or "all" (default: all)
    #[arg(default_value = "all")]
    pub run_id: String,

    /// Report what would change without writing
    #[arg(long)]
    pub dry_run: bool,

    /// Delete unreferenced blob files after scrub
    #[arg(long)]
    pub gc: bool,

    /// Skip redaction (dangerous: leaves secrets at rest)
    #[arg(long)]
    pub no_redact: bool,
}

impl Cli {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match &self.command {
            Command::Run(args) => cmd_run(self, args).await,
            Command::Runs(args) => cmd_runs(self, args).await,
            Command::Show(args) => cmd_show(self, args).await,
            Command::Timeline(args) => cmd_timeline(self, args).await,
            Command::Inspect(args) => cmd_inspect(self, args).await,
            Command::Diff(args) => cmd_diff(self, args).await,
            Command::Export(args) => cmd_export(self, args).await,
            Command::Import(args) => cmd_import(self, args).await,
            Command::Replay(args) => cmd_replay(self, args).await,
            Command::Fork(args) => cmd_fork(self, args).await,
            Command::Analyze(args) => cmd_analyze(self, args).await,
            Command::Scrub(args) => cmd_scrub(self, args).await,
            Command::Doctor(args) => cmd_doctor(self, args).await,
            Command::Rm(args) => cmd_rm(self, args).await,
            Command::Purge(args) => cmd_purge(self, args).await,
            Command::Search(args) => cmd_search(self, args).await,
            Command::Watch(args) => cmd_watch(self, args).await,
            Command::Tags => cmd_tags(self).await,
            Command::Tag(args) => cmd_tag(self, args).await,
            Command::Stats(args) => cmd_stats(self, args).await,
            Command::Completions(args) => cmd_completions(args),
            Command::Serve(args) => cmd_serve(self, args).await,
            Command::Sync(args) => cmd_sync(self, args).await,
            Command::MaybeRun(args) => cmd_maybe_run(self, args).await,
            Command::Enable(args) => cmd_enable(self, args).await,
            Command::Disable => cmd_disable(self).await,
            Command::Postmortem(args) | Command::Summary(args) => cmd_summary(self, args).await,
            Command::Gc(args) => cmd_gc(self, args).await,
            Command::Context(args) => cmd_context(self, args).await,
            Command::Status(args) => cmd_status(self, args).await,
            Command::Handoff(args) => cmd_handoff(self, args).await,
        }
    }
}

// ── Shared helpers ────────────────────────────────────────────────

/// Open the project store using ancestor-aware discovery (K21).
fn open_store(cli: &Cli) -> anyhow::Result<SqliteStore> {
    let cwd = std::env::current_dir()?;
    let discovery = discover_project(&cwd, cli.store.as_deref())?;
    discovery.paths.ensure_dirs()?;
    tracing::debug!(
        db = %discovery.paths.db_path.display(),
        blobs = %discovery.paths.blob_dir.display(),
        project = %discovery.project_root.display(),
        "opening store"
    );
    SqliteStore::open_with_blobs(&discovery.paths.db_path, &discovery.paths.blob_dir)
}

/// Discover project without opening the DB (doctor, enable, etc.).
fn discover(cli: &Cli) -> anyhow::Result<crate::config::ProjectDiscovery> {
    let cwd = std::env::current_dir()?;
    discover_project(&cwd, cli.store.as_deref())
}

/// Resolve a run id: `"latest"`, full UUID, or unique prefix.
async fn resolve_run_id(store: &dyn TraceStore, spec: &str) -> anyhow::Result<String> {
    if spec == "latest" {
        let runs = store.list_runs().await?;
        return runs
            .first()
            .map(|r| r.id.clone())
            .ok_or_else(|| anyhow::anyhow!("no runs recorded"));
    }

    if let Some(run) = store.get_run(spec).await? {
        return Ok(run.id);
    }

    let runs = store.list_runs().await?;
    let matches: Vec<_> = runs
        .iter()
        .filter(|r| r.id.starts_with(spec))
        .map(|r| r.id.clone())
        .collect();

    match matches.len() {
        0 => anyhow::bail!("run not found: {}", spec),
        1 => Ok(matches[0].clone()),
        n => anyhow::bail!(
            "ambiguous run id prefix '{}': {} matches (use a longer prefix)",
            spec,
            n
        ),
    }
}

/// Resolve an event id: full UUID, prefix, sequence number, or "latest".
async fn resolve_event_id(
    store: &dyn TraceStore,
    event_spec: &str,
    run_id: Option<&str>,
) -> anyhow::Result<crate::core::event::TraceEvent> {
    if let Some(ev) = store.get_event(event_spec).await? {
        return Ok(ev);
    }

    let candidates: Vec<crate::core::event::TraceEvent> = if let Some(rid) = run_id {
        let events = store.get_events(rid).await?;
        if event_spec == "latest" {
            return events
                .into_iter()
                .next_back()
                .ok_or_else(|| anyhow::anyhow!("no events in run"));
        }
        if let Ok(seq) = event_spec.parse::<u64>() {
            if let Some(ev) = events.iter().find(|e| e.sequence == seq) {
                return Ok(ev.clone());
            }
        }
        events
            .into_iter()
            .filter(|e| e.id.starts_with(event_spec))
            .collect()
    } else {
        let mut found = Vec::new();
        for run in store.list_runs().await?.into_iter().take(50) {
            for ev in store.get_events(&run.id).await? {
                if ev.id.starts_with(event_spec) {
                    found.push(ev);
                }
            }
        }
        found
    };

    match candidates.len() {
        0 => anyhow::bail!("event not found: {}", event_spec),
        1 => Ok(candidates.into_iter().next().unwrap()),
        n => anyhow::bail!("ambiguous event id prefix '{}': {} matches", event_spec, n),
    }
}

fn short_id(id: &str) -> &str {
    &id[..8.min(id.len())]
}

/// Bookkeeping noise that drowns semantic signal.
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

// ── Commands ──────────────────────────────────────────────────────

async fn cmd_run(cli: &Cli, args: &RunArgs) -> anyhow::Result<()> {
    use crate::run::RunSupervisor;

    if args.insecure_raw {
        eprintln!("warning: --insecure-raw stores unredacted terminal bytes");
    }
    if args.no_redact {
        eprintln!("warning: --no-redact disables all secret redaction");
    }

    tracing::info!(
        command = ?args.command,
        name = ?args.name,
        project = ?args.project,
        tags = ?args.tag,
        insecure_raw = args.insecure_raw,
        "run command"
    );

    let discovery = discover(cli).ok();
    let store = open_store(cli)?;
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let policy = CapturePolicy {
        insecure_raw: args.insecure_raw,
        redact: !args.no_redact,
    };
    let supervisor = RunSupervisor::new(Arc::clone(&store)).with_policy(policy);
    let run = supervisor.execute(args).await?;

    // Sticky project state for agent handoff (best-effort).
    if let Some(ref disc) = discovery {
        let mut state = crate::state::ProjectState::load(&disc.paths.root)
            .ok()
            .flatten()
            .unwrap_or_default();
        state.record_run(&run);
        if let Err(e) = state.save(&disc.paths.root) {
            tracing::warn!(error = %e, "failed to write .blackbox/state.json");
        }
        // Opportunistic retention when configured.
        if let Some(ref cfg) = disc.config {
            if cfg.retention.auto_apply {
                if let Err(e) =
                    apply_retention_quiet(store.as_ref(), &cfg.retention, &disc.paths.blob_dir)
                        .await
                {
                    tracing::warn!(error = %e, "auto retention failed");
                }
            }
        }
    }

    if cli.json {
        #[derive(serde::Serialize)]
        struct RunDone {
            run_id: String,
            short_id: String,
            exit_code: Option<i32>,
            status: String,
            attention_needed: bool,
            handoff_hint: String,
        }
        let attention = matches!(
            run.status,
            crate::core::run::RunStatus::Failed | crate::core::run::RunStatus::Cancelled
        );
        return output::emit_ok(
            "run",
            &RunDone {
                run_id: run.id.clone(),
                short_id: short_id(&run.id).to_string(),
                exit_code: run.exit_code,
                status: format!("{:?}", run.status).to_lowercase(),
                attention_needed: attention,
                handoff_hint: if attention {
                    format!(
                        "blackbox handoff --json  # or: blackbox context {} --for-resume --json",
                        short_id(&run.id)
                    )
                } else {
                    "blackbox status --json".into()
                },
            },
        );
    }

    println!(
        "Run {} completed with exit code {:?}",
        short_id(&run.id),
        run.exit_code
    );
    if let Some(ref notes) = run.notes {
        if notes.contains("session:") {
            println!("  {}", notes);
        }
    }
    if matches!(
        run.status,
        crate::core::run::RunStatus::Failed | crate::core::run::RunStatus::Cancelled
    ) {
        println!(
            "  handoff: blackbox handoff --json  (or: blackbox context {} --for-resume --json)",
            short_id(&run.id)
        );
    }
    Ok(())
}

/// Best-effort retention apply used after runs (no stdout noise).
async fn apply_retention_quiet(
    store: &dyn TraceStore,
    cfg: &crate::config::RetentionConfig,
    blob_dir: &std::path::Path,
) -> anyhow::Result<()> {
    use crate::retention::plan_deletions;
    use crate::scrub::gc_unreferenced_blobs;

    let runs = store.list_runs().await?;
    let candidates = plan_deletions(&runs, cfg);
    for c in &candidates {
        let _ = store.delete_run(&c.id).await?;
    }
    if cfg.auto_gc_blobs && !candidates.is_empty() {
        let _ = gc_unreferenced_blobs(store, blob_dir, false).await?;
    }
    Ok(())
}

async fn cmd_runs(cli: &Cli, args: &RunsArgs) -> anyhow::Result<()> {
    let store = open_store(cli)?;
    let mut runs = store.list_runs().await?;

    if !args.tag.is_empty() {
        runs.retain(|r| args.tag.iter().any(|t| r.tags.iter().any(|rt| rt == t)));
    }
    if let Some(status) = &args.status {
        // Validate against known status values with a helpful error
        let valid_statuses = [
            "pending",
            "running",
            "succeeded",
            "failed",
            "cancelled",
            "unknown",
        ];
        let s = status.to_lowercase();
        if !valid_statuses
            .iter()
            .any(|v| v.contains(&s) || s.contains(v))
        {
            if cli.json {
                return output::emit_err(
                    "runs",
                    output::CliErrorCode::InvalidArgs,
                    format!(
                        "unknown status {:?}; valid values: Pending, Running, Succeeded, Failed, Cancelled, Unknown",
                        status
                    ),
                );
            }
            anyhow::bail!(
                "unknown status {:?}; valid values: Pending, Running, Succeeded, Failed, Cancelled, Unknown",
                status
            );
        }
        runs.retain(|r| format!("{:?}", r.status).to_lowercase().contains(&s));
    }
    if let Some(limit) = args.limit {
        runs.truncate(limit);
    }

    if cli.json {
        let view = views::RunsView {
            runs: runs.iter().map(views::RunSummaryView::from_run).collect(),
        };
        return output::emit_ok("runs", &view);
    }

    println!("Store: {}", store.db_path().display());
    if runs.is_empty() {
        println!("No runs matched.");
        println!("  Try: blackbox run --tag demo -- echo hello");
    } else {
        if args.show_tags {
            println!(
                "{:<2} {:<10} {:<12} {:<6} {:<20} LABEL",
                "", "ID", "STATUS", "EXIT", "TAGS"
            );
        } else {
            println!(
                "{:<2} {:<10} {:<12} {:<6} LABEL",
                "", "ID", "STATUS", "EXIT"
            );
        }
        for run in &runs {
            let status = match &run.status {
                crate::core::run::RunStatus::Succeeded => "✓",
                crate::core::run::RunStatus::Failed => "✗",
                crate::core::run::RunStatus::Running => "●",
                crate::core::run::RunStatus::Cancelled => "⊘",
                crate::core::run::RunStatus::Pending => "○",
                _ => "?",
            };
            let cmd = run.command.join(" ");
            let label = run.name.as_deref().unwrap_or(&cmd);
            let label = if label.len() > 50 {
                let end = label.floor_char_boundary(47);
                format!("{}…", &label[..end])
            } else {
                label.to_string()
            };
            let exit = run
                .exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".into());
            if args.show_tags {
                let tags = if run.tags.is_empty() {
                    "-".to_string()
                } else {
                    run.tags.join(",")
                };
                let tags = if tags.len() > 18 {
                    let end = tags.floor_char_boundary(17);
                    format!("{}…", &tags[..end])
                } else {
                    tags
                };
                println!(
                    "{}  {}  {:<12} {:<6} {:<20} {}",
                    status,
                    short_id(&run.id),
                    format!("{:?}", run.status),
                    exit,
                    tags,
                    label
                );
            } else {
                println!(
                    "{}  {}  {:<12} {:<6} {}",
                    status,
                    short_id(&run.id),
                    format!("{:?}", run.status),
                    exit,
                    label
                );
            }
        }
        println!("({} run(s))", runs.len());
    }
    Ok(())
}

async fn cmd_tags(cli: &Cli) -> anyhow::Result<()> {
    use std::collections::BTreeMap;

    let store = open_store(cli)?;
    let runs = store.list_runs().await?;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for run in &runs {
        for t in &run.tags {
            *counts.entry(t.clone()).or_insert(0) += 1;
        }
    }
    if counts.is_empty() {
        println!("No tags yet. Add with: blackbox run --tag demo -- …");
        println!("  or: blackbox tag latest --add demo");
        return Ok(());
    }
    println!("{:<24} COUNT", "TAG");
    println!("{}", "-".repeat(32));
    for (tag, n) in counts {
        println!("{:<24} {}", tag, n);
    }
    Ok(())
}

async fn cmd_tag(cli: &Cli, args: &TagArgs) -> anyhow::Result<()> {
    if args.add.is_empty() && args.rm.is_empty() {
        anyhow::bail!("pass --add TAG and/or --rm TAG");
    }
    // Reject tags that appear in both --add and --rm
    let overlap: Vec<_> = args.add.iter().filter(|t| args.rm.contains(t)).collect();
    if !overlap.is_empty() {
        let names: Vec<&str> = overlap.iter().map(|s| s.as_str()).collect();
        anyhow::bail!(
            "tags appear in both --add and --rm: {}; remove the conflict and retry",
            names.join(", ")
        );
    }
    let store = open_store(cli)?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;
    let mut run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found"))?;

    for t in &args.rm {
        run.tags.retain(|x| x != t);
    }
    for t in &args.add {
        if !run.tags.iter().any(|x| x == t) {
            run.tags.push(t.clone());
        }
    }
    store.update_run(&run).await?;
    println!(
        "Run {} tags: {}",
        short_id(&run.id),
        if run.tags.is_empty() {
            "(none)".into()
        } else {
            run.tags.join(", ")
        }
    );
    Ok(())
}

async fn cmd_stats(cli: &Cli, args: &StatsArgs) -> anyhow::Result<()> {
    use std::collections::HashMap;

    let store = open_store(cli)?;
    let runs = store.list_runs().await?;

    let mut by_status: HashMap<String, usize> = HashMap::new();
    let mut by_adapter: HashMap<String, usize> = HashMap::new();
    let mut tagged = 0usize;
    for run in &runs {
        *by_status.entry(format!("{:?}", run.status)).or_insert(0) += 1;
        if !run.tags.is_empty() {
            tagged += 1;
        }
        let adapter = run
            .notes
            .as_deref()
            .and_then(|n| n.split(';').find_map(|p| p.trim().strip_prefix("adapter:")))
            .unwrap_or("unknown");
        *by_adapter.entry(adapter.to_string()).or_insert(0) += 1;
    }

    let sample: Vec<_> = runs.iter().take(args.max_runs).cloned().collect();
    let mut total_events = 0usize;
    let mut total_tools = 0usize;
    let mut total_errors = 0usize;
    let mut kind_counts: HashMap<String, usize> = HashMap::new();
    for run in &sample {
        let events = store.get_events(&run.id).await?;
        total_events += events.len();
        for ev in &events {
            *kind_counts.entry(ev.kind.clone()).or_insert(0) += 1;
            if ev.kind == "tool.call" {
                total_tools += 1;
            }
            if matches!(ev.status, crate::core::event::EventStatus::Error) {
                total_errors += 1;
            }
        }
    }

    let mut kinds: Vec<_> = kind_counts.into_iter().collect();
    kinds.sort_by_key(|b| std::cmp::Reverse(b.1));
    let top_kinds: Vec<_> = kinds.into_iter().take(12).collect();

    let blob_files = std::fs::read_dir(store.blob_dir())
        .map(|rd| rd.filter_map(|e| e.ok()).count())
        .unwrap_or(0);
    let blob_bytes: u64 = std::fs::read_dir(store.blob_dir())
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0);

    if cli.json {
        let view = views::StatsView {
            db_path: store.db_path().display().to_string(),
            blob_dir: store.blob_dir().display().to_string(),
            run_count: runs.len(),
            tagged_run_count: tagged,
            by_status: by_status.clone(),
            by_adapter: by_adapter.clone(),
            sample_run_count: sample.len(),
            total_events,
            total_tool_calls: total_tools,
            total_errors,
            top_kinds: top_kinds.clone(),
            blob_files,
            blob_bytes,
        };
        return output::emit_ok("stats", &view);
    }

    println!("Store: {}", store.db_path().display());
    println!("Blobs: {}", store.blob_dir().display());
    println!();
    println!("Runs: {} ({} tagged)", runs.len(), tagged);
    println!("  by status:");
    let mut statuses: Vec<_> = by_status.into_iter().collect();
    statuses.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (s, n) in statuses {
        println!("    {:<12} {}", s, n);
    }
    println!("  by adapter:");
    let mut adapters: Vec<_> = by_adapter.into_iter().collect();
    adapters.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (a, n) in adapters {
        println!("    {:<12} {}", a, n);
    }

    println!();
    println!(
        "Events (last {} runs): {} total, {} tool.call, {} errors",
        sample.len(),
        total_events,
        total_tools,
        total_errors
    );
    println!("  top kinds:");
    for (k, n) in top_kinds {
        println!("    {:<28} {}", k, n);
    }

    println!();
    println!(
        "Blobs: {} files, {:.1} MiB",
        blob_files,
        blob_bytes as f64 / (1024.0 * 1024.0)
    );
    Ok(())
}

fn cmd_completions(args: &CompletionsArgs) -> anyhow::Result<()> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    clap_complete::generate(args.shell, &mut cmd, name, &mut std::io::stdout());
    Ok(())
}

async fn cmd_show(cli: &Cli, args: &ShowArgs) -> anyhow::Result<()> {
    if args.tui {
        let store = open_store(cli)?;
        let run_id = resolve_run_id(&store, &args.run_id).await?;
        return crate::ui::tui::run_tui_with_store(store, Some(&run_id)).await;
    }

    let store = open_store(cli)?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;
    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found"))?;
    let events = store.get_events(&run_id).await?;
    let checkpoints = store.get_checkpoints(&run_id).await?;

    let tools: Vec<_> = events.iter().filter(|e| e.kind == "tool.call").collect();
    let errors: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.status, crate::core::event::EventStatus::Error))
        .collect();
    let fs_live: Vec<_> = events
        .iter()
        .filter(|e| e.kind.starts_with("filesystem.") && e.kind != "filesystem.snapshot")
        .filter(|e| !e.kind.contains("observer"))
        .collect();

    // Quick analysis summary
    let detector = crate::analysis::error_detector::ErrorDetector::new();
    let mut structured = 0usize;
    for ev in &events {
        structured += detector.extract_errors(ev).len();
    }

    let resume_cmd = crate::resume::resume_command(&run, &events, &checkpoints);
    let tool_tx = if args.tools || cli.json {
        Some(crate::transcript::rebuild_tool_transcript(&events))
    } else {
        None
    };
    let terminal_tx = if args.transcript {
        match crate::transcript::rebuild_terminal_transcript(&store, &events).await {
            Ok(text) => Some(text),
            Err(e) => {
                if !cli.json {
                    eprintln!("failed to rebuild transcript: {e}");
                }
                None
            }
        }
    } else {
        None
    };

    if cli.json {
        let tool_calls: Vec<_> = tools
            .iter()
            .map(|t| views::ToolCallSummary {
                sequence: t.sequence,
                tool_name: t
                    .metadata
                    .get("tool_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
            })
            .collect();
        let mut hints = vec![
            format!("blackbox timeline {} --semantic", short_id(&run.id)),
            format!("blackbox show {} --transcript", short_id(&run.id)),
        ];
        if matches!(
            run.status,
            crate::core::run::RunStatus::Failed | crate::core::run::RunStatus::Cancelled
        ) {
            hints.push(format!("blackbox postmortem {}", short_id(&run.id)));
        }
        let view = views::ShowView {
            run: run.clone(),
            event_count: events.len(),
            checkpoint_count: checkpoints.len(),
            tool_calls,
            error_event_count: errors.len(),
            structured_error_count: structured,
            filesystem_event_count: fs_live.len(),
            resume: views::ResumeView {
                available: resume_cmd.is_some(),
                command: resume_cmd.clone(),
            },
            hints,
            tool_transcript: if args.tools { tool_tx.clone() } else { None },
            terminal_transcript: terminal_tx.clone(),
        };
        return output::emit_ok("show", &view);
    }

    println!("Run {}", run.id);
    println!("  Status:   {:?}", run.status);
    println!("  Exit:     {:?}", run.exit_code);
    println!("  Command:  {}", run.command.join(" "));
    println!("  Cwd:      {}", run.cwd);
    println!("  Started:  {}", run.started_at);
    if let Some(end) = run.ended_at {
        println!("  Ended:    {}", end);
    }
    if let Some(ref notes) = run.notes {
        println!("  Notes:    {}", notes);
    }
    println!("  Events:   {}", events.len());
    println!("  Checkpts: {}", checkpoints.len());

    if !tools.is_empty() {
        println!();
        println!("Tool calls ({}):", tools.len());
        for t in tools.iter().take(20) {
            let name = t
                .metadata
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            println!("  seq={:<4} {}", t.sequence, name);
        }
        if tools.len() > 20 {
            println!("  … and {} more", tools.len() - 20);
        }
    }

    if !errors.is_empty() {
        println!();
        println!("Errors ({}):", errors.len());
        for e in errors.iter().take(10) {
            println!("  seq={:<4} {}", e.sequence, e.kind);
        }
    }

    if !fs_live.is_empty() {
        println!();
        println!("Filesystem events: {}", fs_live.len());
    }

    if structured > 0 {
        println!();
        println!(
            "Structured errors detected: {} (run `blackbox analyze {}` for detail)",
            structured,
            short_id(&run.id)
        );
    }

    if let Some(ref cmd) = resume_cmd {
        println!();
        println!("Resume: {}", crate::resume::format_command(cmd));
        println!(
            "  blackbox fork {} --launch   # fork + relaunch under observation",
            short_id(&run.id)
        );
    }

    if args.tools {
        println!();
        println!("── tool transcript ──");
        let tools_tx = tool_tx.unwrap_or_default();
        if tools_tx.is_empty() {
            println!("(no tool.call events)");
        } else {
            println!("{}", tools_tx);
        }
    }

    if args.transcript {
        println!();
        println!("── terminal transcript ──");
        match terminal_tx {
            Some(text) if text.trim().is_empty() => println!("(empty)"),
            Some(text) => {
                if text.len() > 50_000 {
                    let end = text.floor_char_boundary(50_000);
                    print!("{}", &text[..end]);
                    println!("\n… (truncated; {} bytes total)", text.len());
                } else {
                    print!("{}", text);
                    if !text.ends_with('\n') {
                        println!();
                    }
                }
            }
            None => {}
        }
    }

    println!();
    println!("  blackbox timeline {} --semantic", short_id(&run.id));
    println!("  blackbox show {} --transcript", short_id(&run.id));
    println!("  blackbox show {} --tui", short_id(&run.id));
    Ok(())
}

async fn cmd_timeline(cli: &Cli, args: &TimelineArgs) -> anyhow::Result<()> {
    let store = open_store(cli)?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;

    let events = store.get_events(&run_id).await?;
    let events: Vec<_> = events
        .into_iter()
        .filter(|e| {
            if args.semantic && is_bookkeeping(&e.kind) {
                return false;
            }
            if !args.kind.is_empty()
                && !args
                    .kind
                    .iter()
                    .any(|k| e.kind.to_lowercase().contains(&k.to_lowercase()))
            {
                return false;
            }
            if let Some(ref src) = args.source {
                let s = format!("{:?}", e.source);
                if !s.to_lowercase().contains(&src.to_lowercase()) {
                    return false;
                }
            }
            true
        })
        .collect();

    if cli.json {
        let view = views::TimelineView {
            run_id: run_id.clone(),
            semantic: args.semantic,
            total_matched: events.len(),
            truncated: false,
            events: events
                .iter()
                .map(|ev| views::TimelineEventView::from_event(ev, event_detail_line(ev)))
                .collect(),
        };
        return output::emit_ok("timeline", &view);
    }

    if events.is_empty() {
        println!("No events recorded for run {}.", short_id(&run_id));
    } else {
        let mut filters = Vec::new();
        if args.semantic {
            filters.push("semantic");
        }
        if !args.kind.is_empty() {
            filters.push("kind");
        }
        if args.source.is_some() {
            filters.push("source");
        }
        let filter_note = if filters.is_empty() {
            String::new()
        } else {
            format!(", {}", filters.join("+"))
        };
        println!(
            "Timeline for run {} ({} events{}):",
            short_id(&run_id),
            events.len(),
            filter_note
        );
        println!(
            "{:<6} {:<12} {:<28} {:<8} DETAIL",
            "SEQ", "SRC", "KIND", "STATUS"
        );
        println!("{}", "-".repeat(90));
        for ev in &events {
            let status = match &ev.status {
                crate::core::event::EventStatus::Success => "✓",
                crate::core::event::EventStatus::Error => "✗",
                crate::core::event::EventStatus::Running => "●",
                _ => "○",
            };
            let detail = event_detail_line(ev);
            println!(
                "{:<6} {:<12} {:<28} {:<8} {}",
                ev.sequence,
                format!("{:?}", ev.source),
                ev.kind,
                status,
                detail,
            );
        }
    }
    Ok(())
}

fn event_detail_line(ev: &crate::core::event::TraceEvent) -> String {
    if let Some(preview) = ev.metadata.get("preview").and_then(|v| v.as_str()) {
        let p = preview.replace('\n', "⏎");
        if p.len() > 50 {
            let end = p.floor_char_boundary(50);
            return format!("{}…", &p[..end]);
        }
        return p;
    }
    if let Some(name) = ev.metadata.get("tool_name").and_then(|v| v.as_str()) {
        return name.to_string();
    }
    if let Some(path) = ev.metadata.get("path").and_then(|v| v.as_str()) {
        return path.to_string();
    }
    if let Some(commit) = ev.metadata.get("commit").and_then(|v| v.as_str()) {
        return commit.chars().take(8).collect();
    }
    if let Some(code) = ev.metadata.get("exit_code") {
        return format!("exit={}", code);
    }
    String::new()
}

async fn cmd_inspect(cli: &Cli, args: &InspectArgs) -> anyhow::Result<()> {
    let store = open_store(cli)?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;
    let event = resolve_event_id(&store, &args.event_id, Some(&run_id)).await?;

    if event.run_id != run_id && !cli.json {
        eprintln!(
            "warning: event belongs to run {}, not {}",
            short_id(&event.run_id),
            short_id(&run_id)
        );
    }

    let mut blob_text = None;
    if let Some(ref b) = event.output_blob {
        if let Some(bref) = crate::core::blob::BlobReference::try_new(b.clone(), 0) {
            if let Ok(data) = store.load_blob(&bref).await {
                let text = String::from_utf8_lossy(&data);
                blob_text = Some(if text.len() > 2000 {
                    let end = text.floor_char_boundary(2000);
                    format!("{}…\n  ({} bytes total)", &text[..end], data.len())
                } else {
                    text.to_string()
                });
            }
        }
    }

    if cli.json {
        let view = views::InspectView {
            run_id: run_id.clone(),
            event: event.clone(),
            blob_text,
        };
        return output::emit_ok("inspect", &view);
    }

    println!("Event: {}", event.id);
    println!("  Run:       {}", short_id(&event.run_id));
    println!("  Sequence:  {}", event.sequence);
    println!("  Source:    {:?}", event.source);
    println!("  Kind:      {}", event.kind);
    println!("  Status:    {:?}", event.status);
    println!("  Started:   {}", event.started_at);
    if let Some(ended) = event.ended_at {
        println!("  Ended:     {}", ended);
    }
    if let Some(duration) = event.duration_ms {
        println!("  Duration:  {}ms", duration);
    }
    println!("  Side Eff:  {:?}", event.side_effect);
    if let Some(ref b) = event.output_blob {
        println!("  Out blob:  {}", b);
        if let Some(ref show) = blob_text {
            println!("  ── blob content ──");
            println!("{}", show);
        }
    }
    if let Some(ref b) = event.input_blob {
        println!("  In blob:   {} (raw; may contain secrets)", b);
    }
    if !event.metadata.is_empty() {
        println!("  Metadata:");
        for (k, v) in &event.metadata {
            let val_str = if let Some(s) = v.as_str() {
                if s.len() > 200 {
                    let end = s.floor_char_boundary(200);
                    format!("{}...", &s[..end])
                } else {
                    s.to_string()
                }
            } else {
                v.to_string()
            };
            println!("    {}: {}", k, val_str);
        }
    }
    Ok(())
}

async fn cmd_diff(cli: &Cli, args: &DiffArgs) -> anyhow::Result<()> {
    use std::collections::{HashMap, HashSet};

    let store = open_store(cli)?;
    let id_a = resolve_run_id(&store, &args.run_a).await?;
    let id_b = resolve_run_id(&store, &args.run_b).await?;
    if id_a == id_b {
        eprintln!(
            "warning: diffing a run against itself (L-19: self-diff produces no useful output)"
        );
    }

    let run_a = store
        .get_run(&id_a)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", id_a))?;
    let run_b = store
        .get_run(&id_b)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", id_b))?;

    let events_a = store.get_events(&id_a).await?;
    let events_b = store.get_events(&id_b).await?;

    if args.trajectory || cli.json {
        let traj = crate::trajectory::diff_trajectories(&id_a, &events_a, &id_b, &events_b);
        if cli.json {
            return output::emit_ok("diff", &traj);
        }
        if args.trajectory {
            println!(
                "Trajectory diff {} vs {}  common_prefix={}",
                short_id(&id_a),
                short_id(&id_b),
                traj.common_prefix_len
            );
            if let Some(div) = &traj.first_divergence {
                println!("  first divergence at index {}", div.index);
                if let Some(a) = &div.a {
                    println!("    A: seq={} {}", a.sequence, a.label);
                }
                if let Some(b) = &div.b {
                    println!("    B: seq={} {}", b.sequence, b.label);
                }
            } else {
                println!("  trajectories identical (semantic)");
            }
            if !traj.only_a.is_empty() {
                println!("  only in A ({}):", traj.only_a.len());
                for s in traj.only_a.iter().take(15) {
                    println!("    seq={} {}", s.sequence, s.label);
                }
            }
            if !traj.only_b.is_empty() {
                println!("  only in B ({}):", traj.only_b.len());
                for s in traj.only_b.iter().take(15) {
                    println!("    seq={} {}", s.sequence, s.label);
                }
            }
            return Ok(());
        }
    }

    println!("Comparing runs:");
    println!(
        "  A: {} — {} ({} events)",
        short_id(&run_a.id),
        run_a.command.join(" "),
        events_a.len()
    );
    println!(
        "  B: {} — {} ({} events)",
        short_id(&run_b.id),
        run_b.command.join(" "),
        events_b.len()
    );
    println!();

    if run_a.status == run_b.status {
        println!("  Status:     both {:?}", run_a.status);
    } else {
        println!("  Status:     A={:?}  B={:?}", run_a.status, run_b.status);
    }

    match (run_a.exit_code, run_b.exit_code) {
        (Some(a), Some(b)) if a == b => println!("  Exit code:  both {}", a),
        (Some(a), Some(b)) => println!("  Exit code:  A={}  B={}", a, b),
        (None, None) => println!("  Exit code:  both unknown"),
        (a, b) => println!("  Exit code:  A={:?}  B={:?}", a, b),
    }

    // Tool call set comparison
    let tools_a: HashSet<String> = events_a
        .iter()
        .filter(|e| e.kind == "tool.call")
        .filter_map(|e| {
            e.metadata
                .get("tool_name")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect();
    let tools_b: HashSet<String> = events_b
        .iter()
        .filter(|e| e.kind == "tool.call")
        .filter_map(|e| {
            e.metadata
                .get("tool_name")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect();
    if !tools_a.is_empty() || !tools_b.is_empty() {
        println!();
        println!(
            "  Tools only in A: {:?}",
            tools_a.difference(&tools_b).collect::<Vec<_>>()
        );
        println!(
            "  Tools only in B: {:?}",
            tools_b.difference(&tools_a).collect::<Vec<_>>()
        );
        println!(
            "  Tools in both:   {:?}",
            tools_a.intersection(&tools_b).collect::<Vec<_>>()
        );
    }

    let mut kinds_a: HashMap<String, usize> = HashMap::new();
    let mut kinds_b: HashMap<String, usize> = HashMap::new();
    for ev in &events_a {
        *kinds_a.entry(ev.kind.clone()).or_insert(0) += 1;
    }
    for ev in &events_b {
        *kinds_b.entry(ev.kind.clone()).or_insert(0) += 1;
    }
    let only_a: Vec<_> = kinds_a
        .keys()
        .filter(|k| !kinds_b.contains_key(*k))
        .cloned()
        .collect();
    let only_b: Vec<_> = kinds_b
        .keys()
        .filter(|k| !kinds_a.contains_key(*k))
        .cloned()
        .collect();
    if !only_a.is_empty() || !only_b.is_empty() {
        println!();
        println!("  Event kinds only in A: {:?}", only_a);
        println!("  Event kinds only in B: {:?}", only_b);
    }

    Ok(())
}

async fn cmd_export(cli: &Cli, args: &ExportArgs) -> anyhow::Result<()> {
    use crate::export::export_run;

    let redact = !args.no_redact;
    tracing::info!(run_id = %args.run_id, format = ?args.format, redact = %redact, "export run");

    let store = open_store(cli)?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;

    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", run_id))?;

    let events = store.get_events(&run_id).await?;

    let format_str = match args.format {
        ExportFormat::Jsonl => "jsonl",
        ExportFormat::Html => "html",
        ExportFormat::Portable => "portable",
    };

    let output = export_run(&store, &run, &events, format_str, redact).await?;
    print!("{}", output);

    Ok(())
}

async fn cmd_import(cli: &Cli, args: &ImportArgs) -> anyhow::Result<()> {
    use crate::export::portable::import_portable;

    let json = if args.path == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(&args.path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", args.path))?
    };

    let store = open_store(cli)?;
    let new_ids = !args.keep_ids;
    if args.keep_ids {
        // Validate that the input is a JSON object with an "id" field before
        // attempting import, so we fail early with a clear message.
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| anyhow::anyhow!("--keep-ids requires valid JSON: {e}"))?;
        if parsed.get("id").is_none() {
            anyhow::bail!("--keep-ids: imported JSON must contain a top-level \"id\" field");
        }
    }
    let result = import_portable(&store, &json, new_ids).await?;
    println!(
        "Imported run {} ({} events, {} blobs{})",
        short_id(&result.run_id),
        result.events,
        result.blobs,
        if result.remapped {
            ", new ids"
        } else {
            ", original ids"
        }
    );
    println!("  blackbox show {}", short_id(&result.run_id));
    println!("  blackbox show {} --transcript", short_id(&result.run_id));
    Ok(())
}

async fn cmd_sync(cli: &Cli, args: &SyncArgs) -> anyhow::Result<()> {
    use crate::sync::{
        parse_s3_url, resolve_sync_dir, sync_pull, sync_pull_http, sync_pull_s3, sync_push,
        sync_push_http, sync_push_s3, SyncReport,
    };

    let store = open_store(cli)?;
    let print_report = |label: &str, report: SyncReport| {
        println!(
            "{label}: pushed={} pulled={} skipped={} errors={}",
            report.pushed,
            report.pulled,
            report.skipped,
            report.errors.len()
        );
        for e in report.errors {
            eprintln!("  ! {e}");
        }
    };

    match &args.action {
        SyncAction::Push(d) => {
            let redact = d.redact && !d.no_redact;
            if d.no_redact {
                eprintln!(
                    "warning: --no-redact includes unredacted secrets in sync archives (L-29)"
                );
            }
            if let Some(ref remote) = d.remote {
                println!("Sync push → {remote}");
                let report = sync_push_http(&store, remote, d.token.as_deref(), redact).await?;
                print_report("http", report);
            } else if let Some(ref s3) = d.s3 {
                let (bucket, prefix) = parse_s3_url(s3)?;
                println!("Sync push → s3://{bucket}/{prefix}");
                let report = sync_push_s3(&store, &bucket, &prefix, redact).await?;
                print_report("s3", report);
            } else {
                let dir = resolve_sync_dir(&d.dir);
                println!("Sync push → {}", dir.display());
                let report = sync_push(&store, &dir, redact).await?;
                print_report("dir", report);
            }
        }
        SyncAction::Pull(d) => {
            if let Some(ref remote) = d.remote {
                println!("Sync pull ← {remote}");
                let report = sync_pull_http(&store, remote, d.token.as_deref()).await?;
                print_report("http", report);
            } else if let Some(ref s3) = d.s3 {
                let (bucket, prefix) = parse_s3_url(s3)?;
                println!("Sync pull ← s3://{bucket}/{prefix}");
                let report = sync_pull_s3(&store, &bucket, &prefix).await?;
                print_report("s3", report);
            } else {
                let dir = resolve_sync_dir(&d.dir);
                println!("Sync pull ← {}", dir.display());
                let report = sync_pull(&store, &dir).await?;
                print_report("dir", report);
            }
        }
    }
    Ok(())
}

async fn cmd_replay(cli: &Cli, args: &ReplayArgs) -> anyhow::Result<()> {
    // Validate mutually exclusive replay mode flags.
    let mode_count = args.mock_tools as u8 + args.sandbox as u8 + args.live as u8;
    if mode_count > 1 {
        anyhow::bail!(
            "conflicting replay flags: --mock-tools, --sandbox, and --live are mutually exclusive"
        );
    }

    use crate::replay::mock::MockReplay;
    use crate::replay::sandbox::SandboxReplay;
    use crate::replay::timeline::TimelineReplay;
    use crate::replay::ReplayEngine;

    let store = open_store(cli)?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;

    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", run_id))?;
    let events = store.get_events(&run_id).await?;

    let from_id = if let Some(ref from) = args.from {
        Some(resolve_event_id(&store, from, Some(&run_id)).await?.id)
    } else {
        None
    };

    let mut engine: Box<dyn ReplayEngine> = if args.mock_tools {
        Box::new(MockReplay)
    } else if args.sandbox || args.live {
        let policy = if args.live {
            crate::replay::ReplayPolicy::Live
        } else {
            crate::replay::ReplayPolicy::Sandbox
        };
        Box::new(SandboxReplay::new().with_policy(policy))
    } else {
        Box::new(TimelineReplay)
    };

    tracing::info!(engine = engine.name(), "starting replay");
    let outcome = engine.start(&run, &events, from_id.as_deref()).await?;
    println!("Replay finished: {}", outcome);
    if !outcome.success() {
        std::process::exit(1);
    }
    Ok(())
}

async fn cmd_fork(cli: &Cli, args: &ForkArgs) -> anyhow::Result<()> {
    use crate::replay::fork::ForkManager;
    use crate::replay::ReplayEngine;
    use crate::replay::ReplayOutcome;

    let store = Arc::new(open_store(cli)?);
    let run_id = resolve_run_id(store.as_ref(), &args.run_id).await?;

    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", run_id))?;
    let events = store.get_events(&run_id).await?;
    let checkpoints = store.get_checkpoints(&run_id).await?;

    let from_event = if let Some(ref at) = args.at {
        Some(
            resolve_event_id(store.as_ref(), at, Some(&run_id))
                .await?
                .id,
        )
    } else {
        None
    };

    let mut fork = ForkManager::new()
        .with_store(store.clone())
        .with_name(args.name.clone());
    tracing::info!(from = ?from_event, name = ?args.name, "forking run");
    let outcome = fork.start(&run, &events, from_event.as_deref()).await?;
    println!("Fork finished: {}", outcome);

    let resume = crate::resume::resume_command(&run, &events, &checkpoints);
    if let Some(ref cmd) = resume {
        println!("Resume command: {}", crate::resume::format_command(cmd));
    } else {
        println!("No harness session found — resume command unavailable.");
        println!("  Tip: record with `claude -p …` so session ids are captured.");
    }

    if args.launch {
        let cmd = resume.ok_or_else(|| {
            anyhow::anyhow!("--launch requires a known harness session (none found)")
        })?;
        println!();
        println!(
            "Launching under blackbox: {}",
            crate::resume::format_command(&cmd)
        );
        // Drop store before nested run reopens it
        drop(store);
        let run_args = RunArgs {
            name: args
                .name
                .clone()
                .or_else(|| Some(format!("resume-{}", short_id(&run_id)))),
            project: Some(run.cwd.clone()),
            tag: vec!["resume".into(), "fork".into()],
            insecure_raw: false,
            no_redact: false,
            command: cmd,
        };
        return cmd_run(cli, &run_args).await;
    }

    if let ReplayOutcome::Forked { new_run_id, .. } = &outcome {
        println!("  blackbox show {}", short_id(new_run_id));
    }
    Ok(())
}

async fn cmd_analyze(cli: &Cli, args: &AnalyzeArgs) -> anyhow::Result<()> {
    use crate::analysis::classifier::SideEffectClassifier;
    use crate::analysis::correlator::EventCorrelator;
    use crate::analysis::error_detector::ErrorDetector;
    use crate::analysis::AnalysisPass;

    let store = Arc::new(open_store(cli)?);
    let run_id = resolve_run_id(store.as_ref(), &args.run_id).await?;
    let events = store.get_events(&run_id).await?;

    if events.is_empty() {
        if cli.json {
            let view = views::AnalyzeView {
                run_id: run_id.clone(),
                derived_count: 0,
                structured_errors: vec![],
                by_kind: Default::default(),
                samples: vec![],
                persisted: false,
            };
            return output::emit_ok("analyze", &view);
        }
        println!("No events to analyze for run {}.", short_id(&run_id));
        return Ok(());
    }

    if !cli.json {
        println!(
            "Analyzing run {} ({} events)…",
            short_id(&run_id),
            events.len()
        );
    }

    let detector = ErrorDetector::new();
    let classifier = SideEffectClassifier::new();
    let correlator = EventCorrelator::new();

    let mut derived = Vec::new();
    derived.extend(detector.analyze(&events).await?);
    derived.extend(classifier.analyze(&events).await?);
    derived.extend(correlator.analyze(&events).await?);

    // Structured errors + optional text print
    let mut structured_errors = Vec::new();
    let mut error_count = 0usize;
    for ev in &events {
        for err in detector.extract_errors(ev) {
            error_count += 1;
            structured_errors.push(views::StructuredErrorView {
                sequence: ev.sequence,
                error_type: err.error_type.clone(),
                message: err.message.clone(),
                file: err.file.clone(),
                line: err.line,
            });
            if !cli.json {
                println!(
                    "  error  seq={} type={} {}{}{}",
                    ev.sequence,
                    err.error_type,
                    err.message.chars().take(80).collect::<String>(),
                    err.file
                        .as_ref()
                        .map(|f| format!(" @{}", f))
                        .unwrap_or_default(),
                    err.line.map(|l| format!(":{}", l)).unwrap_or_default(),
                );
            }
        }
    }

    // Quiet summary: counts by kind, sample of high-signal events
    use std::collections::HashMap;
    let mut by_kind: HashMap<String, usize> = HashMap::new();
    for d in &derived {
        *by_kind.entry(d.kind.clone()).or_insert(0) += 1;
    }

    if cli.json {
        let samples: Vec<_> = derived
            .iter()
            .filter(|d| d.kind == "analysis.side_effect" || d.kind.starts_with("analysis.error"))
            .take(15)
            .map(|d| views::DerivedSampleView {
                kind: d.kind.clone(),
                sequence: d.sequence,
                side_effect: d.side_effect.clone(),
                detail: event_detail_line(d),
            })
            .collect();
        let mut persisted = false;
        if args.persist && !derived.is_empty() {
            let max_seq = events.iter().map(|e| e.sequence).max().unwrap_or(0);
            let n = derived.len();
            for (i, d) in derived.iter_mut().enumerate() {
                d.sequence = max_seq + 1 + i as u64;
            }
            store.insert_events_batch(&derived).await?;
            if let Ok(Some(mut run)) = store.get_run(&run_id).await {
                run.next_sequence = max_seq + 1 + n as u64;
                let _ = store.update_run(&run).await;
            }
            persisted = true;
        }
        let view = views::AnalyzeView {
            run_id: run_id.clone(),
            derived_count: derived.len(),
            structured_errors,
            by_kind,
            samples,
            persisted,
        };
        return output::emit_ok("analyze", &view);
    }

    println!();
    println!(
        "Derived events: {}  (structured errors: {})",
        derived.len(),
        error_count
    );
    if !by_kind.is_empty() {
        let mut kinds: Vec<_> = by_kind.into_iter().collect();
        kinds.sort_by_key(|b| std::cmp::Reverse(b.1));
        for (k, n) in kinds {
            println!("  {:<28} {}", k, n);
        }
    }
    // Sample interesting derived (prefer side_effect over correlation)
    let samples: Vec<_> = derived
        .iter()
        .filter(|d| d.kind == "analysis.side_effect" || d.kind.starts_with("analysis.error"))
        .take(15)
        .collect();
    if !samples.is_empty() {
        println!();
        println!("High-signal samples:");
        for d in samples {
            println!(
                "  + {}  effect={:?}  {}",
                d.kind,
                d.side_effect,
                event_detail_line(d)
            );
        }
    }

    if args.persist && !derived.is_empty() {
        let max_seq = events.iter().map(|e| e.sequence).max().unwrap_or(0);
        let n = derived.len();
        // Assign sequence numbers before batch insert
        for (i, d) in derived.iter_mut().enumerate() {
            d.sequence = max_seq + 1 + i as u64;
        }
        // Persist all derived events atomically in a single transaction
        store.insert_events_batch(&derived).await?;
        // Keep run.next_sequence coherent
        if let Ok(Some(mut run)) = store.get_run(&run_id).await {
            run.next_sequence = max_seq + 1 + n as u64;
            if let Err(e) = store.update_run(&run).await {
                eprintln!("warning: failed to update run sequence: {e}");
            }
        }
        println!("Persisted {} analysis events.", n);
    } else if !derived.is_empty() {
        println!();
        println!("  Tip: re-run with --persist to write derived events into the store");
    }

    Ok(())
}

async fn cmd_scrub(cli: &Cli, args: &ScrubArgs) -> anyhow::Result<()> {
    use crate::scrub::{format_report, gc_unreferenced_blobs, scrub_store};

    let store = open_store(cli)?;
    let blob_dir = store.blob_dir().to_path_buf();
    let store: Arc<dyn TraceStore> = Arc::new(store);

    let filter_owned: Option<String> = if args.run_id == "all" {
        Some("all".into())
    } else if args.run_id == "latest" {
        let id = resolve_run_id(store.as_ref(), "latest").await?;
        println!("Scrubbing run {}…", short_id(&id));
        Some(id)
    } else {
        // Validate run-id exists before scrubbing
        let id = resolve_run_id(store.as_ref(), &args.run_id).await?;
        println!("Scrubbing run {}…", short_id(&id));
        Some(id)
    };
    let filter = filter_owned.as_deref();

    if args.dry_run {
        println!("Dry-run scrub (no writes)…");
    } else {
        println!("Scrubbing store for secrets at rest…");
    }

    let report = scrub_store(
        store.clone(),
        args.dry_run,
        filter,
        Some(crate::redaction::RedactionConfig {
            enabled: !args.no_redact,
            ..Default::default()
        }),
    )
    .await?;
    println!("{}", format_report(&report));

    if args.gc {
        let (files, meta) = gc_unreferenced_blobs(store.as_ref(), &blob_dir, args.dry_run).await?;
        println!(
            "{}orphan blobs: {} file(s), {} metadata row(s) ({})",
            if args.dry_run { "[dry-run] " } else { "" },
            files,
            meta,
            blob_dir.display()
        );
    }

    if report.runs_updated + report.events_updated + report.blobs_rewritten == 0 && !args.gc {
        println!("No secrets found (or already clean).");
    } else if args.dry_run {
        println!("Re-run without --dry-run to apply.");
    } else if !args.gc {
        println!("Done. Use `blackbox scrub --gc` to delete unreferenced blobs.");
    } else {
        println!("Done.");
    }
    Ok(())
}

async fn cmd_search(cli: &Cli, args: &SearchArgs) -> anyhow::Result<()> {
    use crate::search::search_store;

    let store = open_store(cli)?;
    let hits = search_store(&store, &args.query, args.max_runs, args.limit).await?;
    let backend = hits.first().map(|h| h.backend).unwrap_or("scan");

    if cli.json {
        let view = views::SearchView {
            query: args.query.clone(),
            truncated: hits.len() as u32 >= args.limit as u32,
            backend: backend.to_string(),
            max_runs_scanned: args.max_runs,
            hits: hits
                .iter()
                .map(|h| views::SearchHitView {
                    run_id: h.run_id.clone(),
                    short_run_id: short_id(&h.run_id).to_string(),
                    event_id: h.event_id.clone(),
                    score: h.score as f64,
                    kind: h.kind.clone(),
                    sequence: h.sequence,
                    snippet: h.snippet.clone(),
                })
                .collect(),
        };
        return output::emit_ok("search", &view);
    }

    if hits.is_empty() {
        println!("No hits for {:?}.", args.query);
        return Ok(());
    }
    println!(
        "Search {:?} — {} hit(s) (scanned up to {} runs)",
        args.query,
        hits.len(),
        args.max_runs
    );
    println!(
        "{:<10} {:<8} {:<22} {:<6} SNIPPET  [{}]",
        "RUN", "SCORE", "KIND", "SEQ", backend
    );
    println!("{}", "-".repeat(90));
    for h in hits {
        let seq = h
            .sequence
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".into());
        println!(
            "{:<10} {:<8} {:<22} {:<6} {}",
            short_id(&h.run_id),
            h.score,
            h.kind,
            seq,
            h.snippet
        );
        if let Some(ref eid) = h.event_id {
            println!(
                "           inspect: blackbox inspect {} {}",
                short_id(&h.run_id),
                short_id(eid)
            );
        } else {
            println!("           show:    blackbox show {}", short_id(&h.run_id));
        }
    }
    Ok(())
}

async fn cmd_watch(cli: &Cli, args: &WatchArgs) -> anyhow::Result<()> {
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    let store = open_store(cli)?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;
    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found"))?;

    println!(
        "Watching run {} ({}) — Ctrl+C to stop",
        short_id(&run_id),
        run.name.as_deref().unwrap_or(&run.command.join(" "))
    );
    println!("{:<6} {:<12} {:<28} DETAIL", "SEQ", "SRC", "KIND");
    println!("{}", "-".repeat(72));

    let mut seen: HashSet<String> = HashSet::new();
    // TODO(L-22): cap output buffer size to prevent OOM on extremely long runs
    // Seed with existing so we only print new if already completed; for live
    // runs print everything once then tail.
    let initial = store.get_events(&run_id).await?;
    for ev in &initial {
        if args.semantic && is_bookkeeping(&ev.kind) {
            seen.insert(ev.id.clone());
            continue;
        }
        if seen.insert(ev.id.clone()) {
            println!(
                "{:<6} {:<12} {:<28} {}",
                ev.sequence,
                format!("{:?}", ev.source),
                ev.kind,
                event_detail_line(ev)
            );
        }
    }

    let mut last_new = Instant::now();
    let interval = Duration::from_millis(args.interval_ms.max(100));
    if args.interval_ms < 100 {
        eprintln!(
            "warning: --interval-ms {} is below the recommended minimum of 100ms; \
             polling too frequently may cause high CPU usage",
            args.interval_ms
        );
    }
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nStopped.");
                break;
            }
            _ = tokio::time::sleep(interval) => {
                let events = store.get_events(&run_id).await?;
                let mut any = false;
                for ev in events {
                    if args.semantic && is_bookkeeping(&ev.kind) {
                        continue;
                    }
                    if seen.insert(ev.id.clone()) {
                        println!(
                            "{:<6} {:<12} {:<28} {}",
                            ev.sequence,
                            format!("{:?}", ev.source),
                            ev.kind,
                            event_detail_line(&ev)
                        );
                        any = true;
                    }
                }
                if any {
                    last_new = Instant::now();
                } else if args.idle_exit > 0
                    && last_new.elapsed() > Duration::from_secs(args.idle_exit)
                {
                    // Also stop if run finished and idle
                    if let Ok(Some(r)) = store.get_run(&run_id).await {
                        if !matches!(r.status, crate::core::run::RunStatus::Running | crate::core::run::RunStatus::Pending) {
                            println!("Run finished ({:?}); idle exit.", r.status);
                            break;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

async fn cmd_rm(cli: &Cli, args: &RmArgs) -> anyhow::Result<()> {
    use crate::scrub::gc_unreferenced_blobs;

    if args.run_ids.is_empty() {
        anyhow::bail!("pass at least one run id (or latest)");
    }

    let store = open_store(cli)?;
    let blob_dir = store.blob_dir().to_path_buf();
    let store: Arc<dyn TraceStore> = Arc::new(store);

    let mut ids = Vec::new();
    for spec in &args.run_ids {
        ids.push(resolve_run_id(store.as_ref(), spec).await?);
    }
    ids.sort();
    ids.dedup();

    if ids.len() > 1 && !args.yes {
        anyhow::bail!(
            "refusing to delete {} runs without --yes (ids: {})",
            ids.len(),
            ids.iter()
                .map(|id| short_id(id).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let mut deleted = 0usize;
    for id in &ids {
        if store.delete_run(id).await? {
            println!("deleted {}", short_id(id));
            deleted += 1;
        } else {
            println!("not found {}", short_id(id));
        }
    }
    println!("Removed {deleted} run(s).");

    if args.gc {
        let (files, meta) = gc_unreferenced_blobs(store.as_ref(), &blob_dir, false).await?;
        println!("gc: removed {files} orphan blob file(s), {meta} metadata row(s)");
    } else {
        println!("Tip: blackbox scrub --gc  to reclaim unreferenced blobs");
    }
    Ok(())
}

async fn cmd_purge(cli: &Cli, args: &PurgeArgs) -> anyhow::Result<()> {
    use crate::scrub::gc_unreferenced_blobs;

    if args.policy_from_config {
        return cmd_retention_policy(cli, args.yes, args.gc, false).await;
    }

    if !args.yes {
        anyhow::bail!("purge is destructive; pass --yes to confirm");
    }
    if args.keep == Some(0) {
        anyhow::bail!("--keep 0 would delete ALL runs; refusing (use --keep N with N >= 1)");
    }
    if args.keep.is_none() && !args.pending && !args.failed {
        anyhow::bail!(
            "specify at least one of --keep N, --pending, --failed, or --policy-from-config"
        );
    }

    let store = open_store(cli)?;
    let blob_dir = store.blob_dir().to_path_buf();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let runs = store.list_runs().await?;

    let mut to_delete: Vec<String> = Vec::new();

    if let Some(keep) = args.keep {
        for run in runs.iter().skip(keep) {
            to_delete.push(run.id.clone());
        }
    }
    for run in &runs {
        use crate::core::run::RunStatus;
        if args.pending && run.status == RunStatus::Pending {
            to_delete.push(run.id.clone());
        }
        if args.failed && run.status == RunStatus::Failed {
            to_delete.push(run.id.clone());
        }
    }
    to_delete.sort();
    to_delete.dedup();

    if to_delete.is_empty() {
        println!("Nothing to purge.");
        return Ok(());
    }

    println!("Purging {} run(s)…", to_delete.len());
    let mut deleted = 0usize;
    for id in &to_delete {
        if store.delete_run(id).await? {
            deleted += 1;
        }
    }
    println!("Deleted {deleted} run(s).");

    if args.gc {
        let (files, meta) = gc_unreferenced_blobs(store.as_ref(), &blob_dir, false).await?;
        println!("gc: removed {files} orphan blob file(s), {meta} metadata row(s)");
    }
    Ok(())
}

async fn cmd_gc(cli: &Cli, args: &GcArgs) -> anyhow::Result<()> {
    let apply = args.apply && args.yes;
    if args.apply && !args.yes {
        anyhow::bail!("gc --apply requires --yes");
    }
    cmd_retention_policy(cli, apply, args.gc, !apply).await
}

/// Retention policy from config (dry-run by default).
async fn cmd_retention_policy(
    cli: &Cli,
    apply: bool,
    do_blob_gc: bool,
    force_dry_run: bool,
) -> anyhow::Result<()> {
    use crate::retention::plan_deletions;
    use crate::scrub::gc_unreferenced_blobs;

    let discovery = discover(cli)?;
    let cfg = discovery
        .config
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!("no .blackbox/config.toml found; run `blackbox enable` first")
        })?
        .retention
        .clone();

    let store = open_store(cli)?;
    let blob_dir = store.blob_dir().to_path_buf();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let runs = store.list_runs().await?;
    let candidates = plan_deletions(&runs, &cfg);

    let dry = force_dry_run || !apply;
    let cand_json: Vec<_> = candidates
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "short_id": short_id(&c.id),
                "reason": c.reason,
            })
        })
        .collect();

    if dry {
        if cli.json {
            #[derive(serde::Serialize)]
            struct RetView {
                dry_run: bool,
                would_delete: usize,
                candidates: Vec<serde_json::Value>,
            }
            return output::emit_ok(
                "gc",
                &RetView {
                    dry_run: true,
                    would_delete: candidates.len(),
                    candidates: cand_json,
                },
            );
        }
        if candidates.is_empty() {
            println!("Retention dry-run: nothing to delete.");
        } else {
            println!(
                "Retention dry-run: would delete {} run(s) (keep={}, max_age_days={:?})",
                candidates.len(),
                cfg.keep_runs,
                cfg.max_age_days
            );
            for c in &candidates {
                println!("  {}  {}", short_id(&c.id), c.reason);
            }
            println!("Re-run with: blackbox gc --apply --yes");
        }
        return Ok(());
    }

    let mut deleted = 0usize;
    for c in &candidates {
        if store.delete_run(&c.id).await? {
            deleted += 1;
        }
    }
    let mut files = 0usize;
    let mut meta = 0usize;
    if do_blob_gc || cfg.auto_gc_blobs {
        let r = gc_unreferenced_blobs(store.as_ref(), &blob_dir, false).await?;
        files = r.0;
        meta = r.1;
    }
    if cli.json {
        #[derive(serde::Serialize)]
        struct RetView {
            dry_run: bool,
            deleted: usize,
            candidates: Vec<serde_json::Value>,
            blob_files_removed: usize,
            blob_meta_removed: usize,
        }
        return output::emit_ok(
            "gc",
            &RetView {
                dry_run: false,
                deleted,
                candidates: cand_json,
                blob_files_removed: files,
                blob_meta_removed: meta,
            },
        );
    }
    println!("Deleted {deleted} run(s) by retention policy.");
    if do_blob_gc || cfg.auto_gc_blobs {
        println!("gc: removed {files} orphan blob file(s), {meta} metadata row(s)");
    }
    Ok(())
}

async fn cmd_maybe_run(cli: &Cli, args: &MaybeRunArgs) -> anyhow::Result<()> {
    use crate::maybe_run::{
        decide, exec_passthrough, run_args_for_record, ENV_ACTIVE_RUN, ENV_OFF,
    };

    let cwd = std::env::current_dir()?;
    let off = std::env::var_os(ENV_OFF).is_some();
    let active = std::env::var_os(ENV_ACTIVE_RUN).is_some();
    let action = decide(&args.command, &cwd, cli.store.as_deref(), off, active)?;

    match action {
        crate::maybe_run::MaybeRunAction::Passthrough { reason } => {
            tracing::debug!(%reason, "maybe-run passthrough");
            exec_passthrough(&args.command)
        }
        crate::maybe_run::MaybeRunAction::Record { project_root, tags } => {
            let run_args =
                run_args_for_record(args.command.clone(), project_root, tags, args.name.clone());
            cmd_run(cli, &run_args).await
        }
    }
}

async fn cmd_enable(cli: &Cli, args: &EnableArgs) -> anyhow::Result<()> {
    use crate::config::BlackboxConfig;
    use crate::maybe_run::{default_enable_config, shell_snippet_bash, shell_snippet_fish};
    use crate::shell_install::{self, ShellKind};
    use crate::state::write_agent_instructions;

    let cwd = std::env::current_dir()?;
    // Prefer existing project root if any; else cwd
    let discovery = discover_project(&cwd, cli.store.as_deref())?;
    let project_root = if discovery.config.is_some()
        || discovery.paths.db_path.exists()
        || discovery.paths.root.join("config.toml").exists()
    {
        discovery.project_root
    } else {
        cwd.canonicalize().unwrap_or(cwd)
    };

    let bb = project_root.join(".blackbox");
    std::fs::create_dir_all(&bb)?;
    let config_path = bb.join("config.toml");

    let mut cfg = if let Some(existing) = BlackboxConfig::load_from_path(&config_path)? {
        let mut c = existing;
        c.enabled = true;
        c
    } else {
        default_enable_config()
    };
    cfg.enabled = true;
    // Daily-driver defaults for new / re-enabled projects
    if cfg.retention.keep_runs == 0 {
        cfg.retention.keep_runs = 50;
    }
    cfg.write_to_path(&config_path)?;
    // Ensure dirs for store
    discovery.paths.ensure_dirs().ok();
    let paths = crate::config::BlackboxPaths {
        root: bb.clone(),
        db_path: bb.join("blackbox.db"),
        blob_dir: bb.join("blobs"),
    };
    paths.ensure_dirs()?;

    let agent_md = write_agent_instructions(&bb)?;

    let wrap = cfg.capture.wrap.clone();
    let shell_kind = if let Some(ref s) = args.shell {
        ShellKind::parse(s)
            .ok_or_else(|| anyhow::anyhow!("unknown --shell {s:?}; expected fish, bash, or zsh"))?
    } else {
        ShellKind::detect()
    };

    let mut shell_install_result: Option<shell_install::InstallResult> = None;
    let mut shell_uninstall_path: Option<std::path::PathBuf> = None;

    if args.uninstall_shell {
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME not set; cannot uninstall shell wrappers"))?;
        shell_uninstall_path = shell_install::uninstall_shell(shell_kind, &home)?;
    } else if args.install_shell {
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME not set; cannot install shell wrappers"))?;
        shell_install_result = Some(shell_install::install_shell(shell_kind, &wrap, &home)?);
    }

    if cli.json {
        #[derive(serde::Serialize)]
        struct En {
            enabled: bool,
            project_root: String,
            config_path: String,
            wrap: Vec<String>,
            agent_instructions: String,
            shell: String,
            shell_install: Option<String>,
            shell_install_path: Option<String>,
            shell_uninstall_path: Option<String>,
            next: Vec<String>,
        }
        let (shell_install, shell_install_path) = match &shell_install_result {
            Some(r) => (
                Some(r.action.to_string()),
                Some(r.path.display().to_string()),
            ),
            None => (None, None),
        };
        return output::emit_ok(
            "enable",
            &En {
                enabled: true,
                project_root: project_root.display().to_string(),
                config_path: config_path.display().to_string(),
                wrap: wrap.clone(),
                agent_instructions: agent_md.display().to_string(),
                shell: shell_kind.as_str().into(),
                shell_install,
                shell_install_path,
                shell_uninstall_path: shell_uninstall_path
                    .as_ref()
                    .map(|p| p.display().to_string()),
                next: vec![
                    "blackbox status --json".into(),
                    "blackbox handoff --json".into(),
                    if shell_install_result.is_some() {
                        "open a new shell (or source your rc)".into()
                    } else {
                        "blackbox enable --install-shell".into()
                    },
                ],
            },
        );
    }

    println!("Enabled blackbox for {}", project_root.display());
    println!("  config: {}", config_path.display());
    println!("  wrap:   {}", wrap.join(", "));
    println!("  agent:  {}", agent_md.display());
    println!("  tip:    blackbox status --json   ·   blackbox handoff --json");
    println!();

    if args.uninstall_shell {
        match shell_uninstall_path {
            Some(p) => println!("Removed managed shell wrappers from {}", p.display()),
            None => println!("No managed shell wrappers found to remove."),
        }
    } else if let Some(r) = shell_install_result {
        println!(
            "Shell wrappers {} for {} → {}",
            r.action,
            r.shell.as_str(),
            r.path.display()
        );
        println!("  open a new shell (or source that file) so wrappers take effect");
    } else {
        println!("Shell wrappers (paste into rc, or re-run with --install-shell):");
        println!();
        if shell_kind == ShellKind::Fish {
            print!("{}", shell_snippet_fish(&wrap));
        } else {
            print!("{}", shell_snippet_bash(&wrap));
        }
        println!("Install automatically: blackbox enable --install-shell");
    }
    println!("Disable with: blackbox disable");
    println!("Record only when enabled + basename in wrap list.");
    Ok(())
}

async fn cmd_disable(cli: &Cli) -> anyhow::Result<()> {
    use crate::config::BlackboxConfig;

    let discovery = discover(cli)?;
    let config_path = discovery.paths.root.join("config.toml");
    let mut cfg = BlackboxConfig::load_from_path(&config_path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no config at {}; run blackbox enable first",
            config_path.display()
        )
    })?;
    cfg.enabled = false;
    cfg.write_to_path(&config_path)?;

    if cli.json {
        #[derive(serde::Serialize)]
        struct D {
            enabled: bool,
            config_path: String,
        }
        return output::emit_ok(
            "disable",
            &D {
                enabled: false,
                config_path: config_path.display().to_string(),
            },
        );
    }
    println!("Disabled ambient capture ({})", config_path.display());
    println!("Shell functions may remain; maybe-run will passthrough.");
    Ok(())
}

async fn cmd_status(cli: &Cli, args: &StatusArgs) -> anyhow::Result<()> {
    use crate::status::{build_status, format_status_text, StatusOptions};

    let discovery = discover(cli)?;
    // Open store when it exists; status still works without runs.
    let store = if discovery.paths.db_path.exists() {
        Some(open_store(cli)?)
    } else {
        None
    };
    let store_ref = store.as_ref().map(|s| s as &dyn TraceStore);
    let view = build_status(
        &discovery,
        store_ref,
        StatusOptions {
            include_resume: args.resume,
            max_tokens: args.max_tokens,
            force_resume: false,
        },
    )
    .await?;

    if cli.json {
        return output::emit_ok("status", &view);
    }
    print!("{}", format_status_text(&view));
    Ok(())
}

async fn cmd_handoff(cli: &Cli, args: &HandoffArgs) -> anyhow::Result<()> {
    use crate::status::{build_status, format_status_text, StatusOptions};

    let discovery = discover(cli)?;
    let store = if discovery.paths.db_path.exists() {
        Some(open_store(cli)?)
    } else {
        None
    };
    let store_ref = store.as_ref().map(|s| s as &dyn TraceStore);
    let view = build_status(
        &discovery,
        store_ref,
        StatusOptions {
            include_resume: true,
            max_tokens: args.max_tokens,
            force_resume: args.always,
        },
    )
    .await?;

    if cli.json {
        return output::emit_ok("handoff", &view);
    }
    print!("{}", format_status_text(&view));
    if view.resume_pack.is_none() && !view.attention.needed {
        println!("  (no resume pack — nothing needs attention; pass --always to force)");
    }
    Ok(())
}

async fn cmd_context(cli: &Cli, args: &ContextArgs) -> anyhow::Result<()> {
    use crate::context::{build_context_pack, ContextOptions};

    if !args.for_resume {
        anyhow::bail!("specify --for-resume (only mode in 0.3)");
    }
    let store = open_store(cli)?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;
    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found"))?;

    let pack = build_context_pack(
        &store,
        &run,
        ContextOptions {
            max_tokens: args.max_tokens,
            include_transcript: !args.no_transcript,
        },
    )
    .await?;

    if cli.json {
        return output::emit_ok("context", &pack);
    }
    println!(
        "Context pack {} (≈{} tokens{})",
        pack.short_id,
        pack.approx_tokens,
        if pack.truncated { ", truncated" } else { "" }
    );
    println!(
        "  status={:?} exit={:?} tools={} errors={}",
        pack.summary.status,
        pack.summary.exit_code,
        pack.summary.tools.total,
        pack.summary.errors.len()
    );
    if !pack.last_tools.is_empty() {
        println!("  last tools: {}", pack.last_tools.join(", "));
    }
    if !pack.failed_tools.is_empty() {
        println!("  failed tools:");
        for t in &pack.failed_tools {
            println!("    seq={} {} {}", t.sequence, t.name, t.detail);
        }
    }
    if let Some(ref cmd) = pack.resume_command {
        println!("  resume: {}", cmd.join(" "));
    }
    if let Some(ref tail) = pack.transcript_tail {
        println!("  ── transcript tail ──");
        println!("{}", tail);
    }
    println!(
        "  tip: blackbox context {} --for-resume --json",
        pack.short_id
    );
    Ok(())
}

async fn cmd_summary(cli: &Cli, args: &SummaryArgs) -> anyhow::Result<()> {
    use crate::summary::{build_summary, format_summary_text, SummaryOptions};

    let store = open_store(cli)?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;
    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found"))?;

    // Design: default SQL-capped; --short smaller; --full larger still limited
    let opts = if args.full {
        SummaryOptions {
            short: false,
            full: true,
        }
    } else if args.short {
        SummaryOptions {
            short: true,
            full: false,
        }
    } else {
        SummaryOptions::default()
    };

    let view = build_summary(&store, &run, opts).await?;
    if cli.json {
        return output::emit_ok("postmortem", &view);
    }
    print!("{}", format_summary_text(&view));
    Ok(())
}

async fn cmd_doctor(cli: &Cli, args: &DoctorArgs) -> anyhow::Result<()> {
    use crate::redaction::scanner::SecretScanner;
    use crate::redaction::RedactionConfig;
    use crate::storage::sqlite::SCHEMA_VERSION;

    let discovery = discover(cli)?;
    let paths = &discovery.paths;
    let project = std::env::current_dir().ok();
    let on_path = std::process::Command::new("sh")
        .arg("-c")
        .arg("command -v blackbox >/dev/null 2>&1")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let mut run_count = None;
    let mut running_count = None;
    let mut fts5 = "unopened".to_string();
    let mut secrets_clean = None;
    let mut store_size_bytes = None;

    if let Ok(store) = open_store(cli) {
        if args.reindex {
            match store.reindex_fts() {
                Ok(n) => {
                    if !cli.json {
                        println!("fts reindex: {n} events");
                    }
                }
                Err(e) => {
                    if !cli.json {
                        println!("fts reindex: failed ({e})");
                    }
                }
            }
        }

        let runs = store.list_runs().await?;
        let running = runs
            .iter()
            .filter(|r| matches!(r.status, crate::core::run::RunStatus::Running))
            .count();
        run_count = Some(runs.len());
        running_count = Some(running);

        match store.fts_event_ids("tool", 1).await {
            Ok(Some(_)) => fts5 = "available".into(),
            Ok(None) => fts5 = "unavailable".into(),
            Err(e) => fts5 = format!("error ({e})"),
        }

        let scanner = SecretScanner::new(RedactionConfig::default());
        let mut dirty = 0usize;
        for run in runs.iter().take(20) {
            let cmd = run.command.join(" ");
            if !scanner.scan(&cmd, "doctor", None).is_empty() {
                dirty += 1;
            }
        }
        secrets_clean = Some(dirty == 0);

        if let Ok(meta) = std::fs::metadata(store.db_path()) {
            store_size_bytes = Some(meta.len());
        }
    }

    let config_view = match &discovery.config {
        Some(c) => views::DoctorConfigView {
            present: true,
            enabled: Some(c.enabled),
            wrap: Some(c.capture.wrap.clone()),
            retention: Some(views::DoctorRetentionView {
                keep_runs: c.retention.keep_runs,
                max_age_days: c.retention.max_age_days,
            }),
        },
        None => views::DoctorConfigView {
            present: false,
            enabled: None,
            wrap: None,
            retention: None,
        },
    };

    if cli.json {
        let view = views::DoctorView {
            version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: SCHEMA_VERSION as u32,
            db_path: paths.db_path.display().to_string(),
            blob_dir: paths.blob_dir.display().to_string(),
            db_exists: paths.db_path.exists(),
            blob_dir_exists: paths.blob_dir.exists(),
            project_root: discovery.project_root.display().to_string(),
            store_size_bytes,
            run_count,
            running_count,
            fts5,
            secrets_clean,
            config: config_view,
            shell_integration_hint:
                "functions call maybe-run; install via blackbox enable --install-shell (0.2)".into(),
            blackbox_on_path: on_path,
        };
        return output::emit_ok("doctor", &view);
    }

    println!("blackbox doctor");
    println!("{}", "─".repeat(48));
    println!(
        "cwd:        {}",
        project
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "?".into())
    );
    println!("project:    {}", discovery.project_root.display());
    println!("db path:    {}", paths.db_path.display());
    println!("blob dir:   {}", paths.blob_dir.display());
    println!("db exists:  {}", paths.db_path.exists());
    println!("blobs dir:  {}", paths.blob_dir.exists());
    println!(
        "config:     {}",
        if config_view.present { "yes" } else { "no" }
    );
    if let Some(n) = run_count {
        println!(
            "runs:       {} (running/orphan: {})",
            n,
            running_count.unwrap_or(0)
        );
    } else {
        println!("store:      could not open (will be created on first run)");
    }
    println!("fts5:       {}", fts5);
    match secrets_clean {
        Some(true) => println!("secrets:    no secret patterns in recent run argv"),
        Some(false) => {
            println!("warning:    recent run command(s) still match secret patterns");
            println!("            run: blackbox scrub");
        }
        None => {}
    }

    println!();
    println!("env:");
    println!(
        "  BLACKBOX_DB         = {}",
        std::env::var("BLACKBOX_DB").unwrap_or_else(|_| "(unset)".into())
    );
    println!(
        "  BLACKBOX_FORCE_JSON = {}",
        std::env::var("BLACKBOX_FORCE_JSON").unwrap_or_else(|_| "(unset)".into())
    );
    println!(
        "  RUST_LOG            = {}",
        std::env::var("RUST_LOG").unwrap_or_else(|_| "(unset)".into())
    );

    println!();
    println!("ok — blackbox serve  ·  blackbox run -- echo hi");
    Ok(())
}

async fn cmd_serve(cli: &Cli, args: &ServeArgs) -> anyhow::Result<()> {
    let store = open_store(cli)?;
    let addr: std::net::SocketAddr = args
        .bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --bind address: {e}"))?;
    crate::serve::serve(
        Arc::new(store),
        crate::serve::ServeOptions {
            addr,
            token: args.token.clone(),
            reindex: args.reindex,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parse_all_subcommands() {
        // Test that every subcommand is recognized (even if it needs more args).
        // We use --help to verify the subcommand exists without requiring args.
        let all_subs = vec![
            "run",
            "runs",
            "show",
            "timeline",
            "inspect",
            "diff",
            "export",
            "import",
            "replay",
            "fork",
            "analyze",
            "scrub",
            "doctor",
            "rm",
            "purge",
            "search",
            "watch",
            "tags",
            "tag",
            "stats",
            "completions",
            "serve",
            "sync",
            "maybe-run",
            "enable",
            "disable",
            "postmortem",
            "summary",
            "gc",
            "context",
            "status",
            "handoff",
        ];
        for sub in all_subs {
            let result = Cli::command().try_get_matches_from(["blackbox", sub, "--help"]);
            // --help returns DisplayHelp which is an Err variant (same as --version)
            match result {
                Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => {
                    // Subcommand recognized and help displayed — success
                }
                Err(e) if e.kind() == clap::error::ErrorKind::UnknownArgument => {
                    panic!("unknown subcommand '{}': {:?}", sub, e);
                }
                Err(e) => panic!("unexpected error for '{}': {:?}", sub, e),
                Ok(_) => {} // shouldn't happen with --help but fine
            }
        }
    }

    #[test]
    fn test_cli_parse_run_with_command() {
        let result =
            Cli::command().try_get_matches_from(["blackbox", "run", "--", "echo", "hello"]);
        assert!(result.is_ok(), "run subcommand with args should parse");
    }

    #[test]
    fn test_cli_parse_sync_subcommands() {
        assert!(
            Cli::command()
                .try_get_matches_from(["blackbox", "sync", "push"])
                .is_ok(),
            "sync push should parse"
        );
        assert!(
            Cli::command()
                .try_get_matches_from(["blackbox", "sync", "pull"])
                .is_ok(),
            "sync pull should parse"
        );
    }

    #[test]
    fn test_cli_parse_version() {
        let result = Cli::command().try_get_matches_from(["blackbox", "--version"]);
        // --version returns DisplayVersion (exits normally), which clap reports as Err
        match result {
            Err(e) if e.kind() == clap::error::ErrorKind::DisplayVersion => {
                // This is expected — version was displayed successfully
            }
            other => panic!("--version should return DisplayVersion, got: {:?}", other),
        }
    }

    #[test]
    fn test_cli_parse_store_global_flag() {
        assert!(
            Cli::command()
                .try_get_matches_from(["blackbox", "--store", "/tmp/test.db", "runs"])
                .is_ok(),
            "--store global flag should parse"
        );
    }

    #[test]
    fn test_cli_parse_export_with_format() {
        let result = Cli::command()
            .try_get_matches_from(["blackbox", "export", "run-123", "--format", "html"]);
        assert!(
            result.is_ok()
                || matches!(&result, Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp)
        );
    }

    #[test]
    fn test_cli_parse_scrub_flags() {
        let result = Cli::command().try_get_matches_from([
            "blackbox",
            "scrub",
            "--dry-run",
            "--gc",
            "--no-redact",
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_parse_watch_interval() {
        let result = Cli::command().try_get_matches_from([
            "blackbox",
            "watch",
            "run-id",
            "--interval-ms",
            "500",
        ]);
        assert!(
            result.is_ok(),
            "watch with interval should parse: {result:?}"
        );
    }

    #[test]
    fn test_cli_parse_purge_flags() {
        let result =
            Cli::command().try_get_matches_from(["blackbox", "purge", "--keep", "5", "--yes"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_parse_rm_single() {
        let result = Cli::command().try_get_matches_from(["blackbox", "rm", "run-123"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_short_id_truncates() {
        assert_eq!(short_id("abc"), "abc");
        assert_eq!(short_id("abcdefgh"), "abcdefgh");
        assert_eq!(short_id("abcdefghijklmnop"), "abcdefgh");
    }

    #[test]
    fn test_short_id_empty() {
        assert_eq!(short_id(""), "");
    }
}
