use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

use crate::config::{BlackboxPaths, CapturePolicy};
use crate::storage::sqlite::SqliteStore;
use crate::storage::TraceStore;

/// A flight recorder and debugger for AI-agent runs
#[derive(Parser)]
#[command(name = "blackbox")]
#[command(version, about)]
pub struct Cli {
    /// SQLite database path (default: .blackbox/blackbox.db, or BLACKBOX_DB)
    #[arg(long, global = true, env = "BLACKBOX_DB")]
    pub store: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
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
    #[arg(long)]
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

    /// Include secrets (disable redaction). Default is redacted.
    #[arg(long)]
    pub no_redact: bool,
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
        }
    }
}

// ── Shared helpers ────────────────────────────────────────────────

fn open_store(cli: &Cli) -> anyhow::Result<SqliteStore> {
    let project = std::env::current_dir().ok();
    let paths = BlackboxPaths::resolve(project.as_deref(), cli.store.as_deref())?;
    paths.ensure_dirs()?;
    tracing::debug!(db = %paths.db_path.display(), blobs = %paths.blob_dir.display(), "opening store");
    SqliteStore::open_with_blobs(&paths.db_path, &paths.blob_dir)
}

/// Resolve a run id: `"latest"`, full UUID, or unique prefix.
async fn resolve_run_id(
    store: &dyn TraceStore,
    spec: &str,
) -> anyhow::Result<String> {
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
        n => anyhow::bail!(
            "ambiguous event id prefix '{}': {} matches",
            event_spec,
            n
        ),
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

    let store = open_store(cli)?;
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let policy = CapturePolicy {
        insecure_raw: args.insecure_raw,
        redact: !args.no_redact,
    };
    let supervisor = RunSupervisor::new(store).with_policy(policy);
    let run = supervisor.execute(args).await?;

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
    Ok(())
}

async fn cmd_runs(cli: &Cli, args: &RunsArgs) -> anyhow::Result<()> {
    let store = open_store(cli)?;
    let mut runs = store.list_runs().await?;

    if !args.tag.is_empty() {
        runs.retain(|r| args.tag.iter().any(|t| r.tags.iter().any(|rt| rt == t)));
    }
    if let Some(ref status) = args.status {
        let s = status.to_lowercase();
        runs.retain(|r| format!("{:?}", r.status).to_lowercase().contains(&s));
    }
    if let Some(limit) = args.limit {
        runs.truncate(limit);
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
                format!("{}…", &label[..47])
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
                    format!("{}…", &tags[..17])
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
    println!("Store: {}", store.db_path().display());
    println!("Blobs: {}", store.blob_dir().display());
    println!();

    let mut by_status: HashMap<String, usize> = HashMap::new();
    let mut by_adapter: HashMap<String, usize> = HashMap::new();
    let mut tagged = 0usize;
    for run in &runs {
        *by_status
            .entry(format!("{:?}", run.status))
            .or_insert(0) += 1;
        if !run.tags.is_empty() {
            tagged += 1;
        }
        let adapter = run
            .notes
            .as_deref()
            .and_then(|n| {
                n.split(';')
                    .find_map(|p| p.trim().strip_prefix("adapter:"))
            })
            .unwrap_or("unknown");
        *by_adapter.entry(adapter.to_string()).or_insert(0) += 1;
    }

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

    // Sample recent runs for event / tool / error counts
    let sample: Vec<_> = runs.into_iter().take(args.max_runs).collect();
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

    println!();
    println!(
        "Events (last {} runs): {} total, {} tool.call, {} errors",
        sample.len(),
        total_events,
        total_tools,
        total_errors
    );
    let mut kinds: Vec<_> = kind_counts.into_iter().collect();
    kinds.sort_by_key(|b| std::cmp::Reverse(b.1));
    println!("  top kinds:");
    for (k, n) in kinds.into_iter().take(12) {
        println!("    {:<28} {}", k, n);
    }

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

    // Quick analysis summary
    let detector = crate::analysis::error_detector::ErrorDetector::new();
    let mut structured = 0usize;
    for ev in &events {
        structured += detector.extract_errors(ev).len();
    }
    if structured > 0 {
        println!();
        println!(
            "Structured errors detected: {} (run `blackbox analyze {}` for detail)",
            structured,
            short_id(&run.id)
        );
    }

    // Resume hint
    if let Some(cmd) = crate::resume::resume_command(&run, &events, &checkpoints) {
        println!();
        println!("Resume: {}", crate::resume::format_command(&cmd));
        println!(
            "  blackbox fork {} --launch   # fork + relaunch under observation",
            short_id(&run.id)
        );
    }

    if args.tools {
        println!();
        println!("── tool transcript ──");
        let tools_tx = crate::transcript::rebuild_tool_transcript(&events);
        if tools_tx.is_empty() {
            println!("(no tool.call events)");
        } else {
            println!("{}", tools_tx);
        }
    }

    if args.transcript {
        println!();
        println!("── terminal transcript ──");
        match crate::transcript::rebuild_terminal_transcript(&store, &events).await {
            Ok(text) if text.trim().is_empty() => println!("(empty)"),
            Ok(text) => {
                // Cap display for huge traces
                if text.len() > 50_000 {
                    print!("{}", &text[..50_000]);
                    println!("\n… (truncated; {} bytes total)", text.len());
                } else {
                    print!("{}", text);
                    if !text.ends_with('\n') {
                        println!();
                    }
                }
            }
            Err(e) => eprintln!("failed to rebuild transcript: {e}"),
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
            return format!("{}…", &p[..50]);
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

    if event.run_id != run_id {
        eprintln!(
            "warning: event belongs to run {}, not {}",
            short_id(&event.run_id),
            short_id(&run_id)
        );
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
        // Try load and show preview
        let bref = crate::core::blob::BlobReference::new(b.clone(), 0);
        if let Ok(data) = store.load_blob(&bref).await {
            let text = String::from_utf8_lossy(&data);
            let show = if text.len() > 2000 {
                format!("{}…\n  ({} bytes total)", &text[..2000], data.len())
            } else {
                text.to_string()
            };
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
                    format!("{}...", &s[..200])
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
        println!("  Tools only in A: {:?}", tools_a.difference(&tools_b).collect::<Vec<_>>());
        println!("  Tools only in B: {:?}", tools_b.difference(&tools_a).collect::<Vec<_>>());
        println!("  Tools in both:   {:?}", tools_a.intersection(&tools_b).collect::<Vec<_>>());
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

    let output = export_run(&run, &events, format_str, redact).await?;
    print!("{}", output);

    Ok(())
}

async fn cmd_replay(cli: &Cli, args: &ReplayArgs) -> anyhow::Result<()> {
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
        Some(resolve_event_id(store.as_ref(), at, Some(&run_id)).await?.id)
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
    use crate::pipeline::EventWriter;

    let store = Arc::new(open_store(cli)?);
    let run_id = resolve_run_id(store.as_ref(), &args.run_id).await?;
    let events = store.get_events(&run_id).await?;

    if events.is_empty() {
        println!("No events to analyze for run {}.", short_id(&run_id));
        return Ok(());
    }

    println!(
        "Analyzing run {} ({} events)…",
        short_id(&run_id),
        events.len()
    );

    let detector = ErrorDetector::new();
    let classifier = SideEffectClassifier::new();
    let correlator = EventCorrelator::new();

    let mut derived = Vec::new();
    derived.extend(detector.analyze(&events).await?);
    derived.extend(classifier.analyze(&events).await?);
    derived.extend(correlator.analyze(&events).await?);

    // Also print structured errors inline
    let mut error_count = 0usize;
    for ev in &events {
        for err in detector.extract_errors(ev) {
            error_count += 1;
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

    // Quiet summary: counts by kind, sample of high-signal events
    use std::collections::HashMap;
    let mut by_kind: HashMap<&str, usize> = HashMap::new();
    for d in &derived {
        *by_kind.entry(d.kind.as_str()).or_insert(0) += 1;
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
        let writer = EventWriter::with_start(store.clone(), run_id.clone(), max_seq + 1);
        let n = derived.len();
        for d in derived {
            writer.write(d).await?;
        }
        // Keep run.next_sequence coherent
        if let Ok(Some(mut run)) = store.get_run(&run_id).await {
            run.next_sequence = writer.next_sequence();
            let _ = store.update_run(&run).await;
        }
        println!("Persisted {} analysis events.", n);
    } else if !derived.is_empty() {
        println!();
        println!("  Tip: re-run with --persist to write derived events into the store");
    }

    Ok(())
}

async fn cmd_scrub(cli: &Cli, args: &ScrubArgs) -> anyhow::Result<()> {
    use crate::scrub::{
        collect_referenced_blobs, format_report, gc_orphan_blobs, scrub_store,
    };

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
        Some(args.run_id.clone())
    };
    let filter = filter_owned.as_deref();

    if args.dry_run {
        println!("Dry-run scrub (no writes)…");
    } else {
        println!("Scrubbing store for secrets at rest…");
    }

    let report = scrub_store(store.clone(), args.dry_run, filter).await?;
    println!("{}", format_report(&report));

    if args.gc {
        let refs = collect_referenced_blobs(store.as_ref()).await?;
        let n = gc_orphan_blobs(&blob_dir, &refs, args.dry_run)?;
        println!(
            "{}orphan blobs: {} ({})",
            if args.dry_run { "[dry-run] " } else { "" },
            n,
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
    let backend = hits
        .first()
        .map(|h| h.backend)
        .unwrap_or("scan");
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
            println!(
                "           show:    blackbox show {}",
                short_id(&h.run_id)
            );
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
        run.name
            .as_deref()
            .unwrap_or(&run.command.join(" "))
    );
    println!("{:<6} {:<12} {:<28} DETAIL", "SEQ", "SRC", "KIND");
    println!("{}", "-".repeat(72));

    let mut seen: HashSet<String> = HashSet::new();
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
    use crate::scrub::{collect_referenced_blobs, gc_orphan_blobs};

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
        let refs = collect_referenced_blobs(store.as_ref()).await?;
        let n = gc_orphan_blobs(&blob_dir, &refs, false)?;
        println!("gc: removed {n} orphan blob file(s)");
    } else {
        println!("Tip: blackbox scrub --gc  to reclaim unreferenced blobs");
    }
    Ok(())
}

async fn cmd_purge(cli: &Cli, args: &PurgeArgs) -> anyhow::Result<()> {
    use crate::scrub::{collect_referenced_blobs, gc_orphan_blobs};

    if !args.yes {
        anyhow::bail!("purge is destructive; pass --yes to confirm");
    }
    if args.keep.is_none() && !args.pending && !args.failed {
        anyhow::bail!("specify at least one of --keep N, --pending, --failed");
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
        let refs = collect_referenced_blobs(store.as_ref()).await?;
        let n = gc_orphan_blobs(&blob_dir, &refs, false)?;
        println!("gc: removed {n} orphan blob file(s)");
    }
    Ok(())
}

async fn cmd_doctor(cli: &Cli, args: &DoctorArgs) -> anyhow::Result<()> {
    use crate::redaction::scanner::SecretScanner;
    use crate::redaction::RedactionConfig;

    println!("blackbox doctor");
    println!("{}", "─".repeat(48));

    let project = std::env::current_dir().ok();
    let paths = BlackboxPaths::resolve(project.as_deref(), cli.store.as_deref())?;
    println!(
        "cwd:        {}",
        project
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "?".into())
    );
    println!("db path:    {}", paths.db_path.display());
    println!("blob dir:   {}", paths.blob_dir.display());
    println!("db exists:  {}", paths.db_path.exists());
    println!("blobs dir:  {}", paths.blob_dir.exists());

    if let Ok(store) = open_store(cli) {
        if args.reindex {
            match store.reindex_fts() {
                Ok(n) => println!("fts reindex: {n} events"),
                Err(e) => println!("fts reindex: failed ({e})"),
            }
        }

        let runs = store.list_runs().await?;
        let running = runs
            .iter()
            .filter(|r| matches!(r.status, crate::core::run::RunStatus::Running))
            .count();
        println!("runs:       {} (running/orphan: {})", runs.len(), running);
        let blob_count = std::fs::read_dir(store.blob_dir())
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0);
        println!("blob files: {}", blob_count);

        // Probe FTS
        match store.fts_event_ids("tool", 1).await {
            Ok(Some(_)) => println!("fts5:       available"),
            Ok(None) => println!("fts5:       unavailable"),
            Err(e) => println!("fts5:       error ({e})"),
        }

        let scanner = SecretScanner::new(RedactionConfig::default());
        let mut dirty = 0usize;
        for run in runs.iter().take(20) {
            let cmd = run.command.join(" ");
            if !scanner.scan(&cmd, "doctor", None).is_empty() {
                dirty += 1;
            }
        }
        if dirty > 0 {
            println!(
                "warning:    {dirty} recent run command(s) still match secret patterns"
            );
            println!("            run: blackbox scrub");
        } else {
            println!("secrets:    no secret patterns in recent run argv");
        }
    } else {
        println!("store:      could not open (will be created on first run)");
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
