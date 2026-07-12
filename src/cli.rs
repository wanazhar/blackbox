use clap::{Args, Parser, Subcommand, ValueEnum};

/// A flight recorder and debugger for AI-agent runs
#[derive(Parser)]
#[command(name = "blackbox")]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run a command under observation
    Run(RunArgs),
    /// List recorded runs
    Runs,
    /// Show details of a specific run
    Show(ShowArgs),
    /// Display the timeline of a run
    Timeline(TimelineArgs),
    /// Inspect a specific event in a run
    Inspect(InspectArgs),
    /// Compare two runs
    Diff(DiffArgs),
    /// Export a run trace
    Export(ExportArgs),
    /// Replay a run (timeline, mock, sandbox, or live)
    Replay(ReplayArgs),
    /// Fork a new run from recorded context
    Fork(ForkArgs),
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

    /// The command to observe (everything after `--`)
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Args)]
pub struct ShowArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,
}

#[derive(Args)]
pub struct TimelineArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,
    /// Event ID or unique prefix
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

    /// Redact sensitive information before export
    #[arg(long)]
    pub redact: bool,
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
}

impl Cli {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match &self.command {
            Command::Run(args) => cmd_run(args).await,
            Command::Runs => cmd_runs().await,
            Command::Show(args) => cmd_show(args).await,
            Command::Timeline(args) => cmd_timeline(args).await,
            Command::Inspect(args) => cmd_inspect(args).await,
            Command::Diff(args) => cmd_diff(args).await,
            Command::Export(args) => cmd_export(args).await,
            Command::Replay(args) => cmd_replay(args).await,
            Command::Fork(args) => cmd_fork(args).await,
        }
    }
}

// ── Shared helpers ────────────────────────────────────────────────

/// Resolve a run id: `"latest"`, full UUID, or unique prefix.
async fn resolve_run_id(
    store: &dyn crate::storage::TraceStore,
    spec: &str,
) -> anyhow::Result<String> {
    if spec == "latest" {
        let runs = store.list_runs().await?;
        return runs
            .first()
            .map(|r| r.id.clone())
            .ok_or_else(|| anyhow::anyhow!("no runs recorded"));
    }

    // Exact match first
    if let Some(run) = store.get_run(spec).await? {
        return Ok(run.id);
    }

    // Prefix match
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

/// Resolve an event id: full UUID or unique prefix (optionally scoped to a run).
async fn resolve_event_id(
    store: &dyn crate::storage::TraceStore,
    event_spec: &str,
    run_id: Option<&str>,
) -> anyhow::Result<crate::core::event::TraceEvent> {
    if let Some(ev) = store.get_event(event_spec).await? {
        return Ok(ev);
    }

    let candidates: Vec<crate::core::event::TraceEvent> = if let Some(rid) = run_id {
        store
            .get_events(rid)
            .await?
            .into_iter()
            .filter(|e| e.id.starts_with(event_spec))
            .collect()
    } else {
        // Search recent runs
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

// ── Commands ──────────────────────────────────────────────────────

async fn cmd_run(args: &RunArgs) -> anyhow::Result<()> {
    use std::sync::Arc;

    use crate::run::RunSupervisor;
    use crate::storage::sqlite::SqliteStore;

    tracing::info!(
        command = ?args.command,
        name = ?args.name,
        project = ?args.project,
        tags = ?args.tag,
        "run command"
    );

    let store = SqliteStore::open("blackbox.db")?;
    let store: Arc<dyn crate::storage::TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store);
    let run = supervisor.execute(args).await?;

    println!(
        "Run {} completed with exit code {:?}",
        run.id, run.exit_code
    );
    Ok(())
}

async fn cmd_runs() -> anyhow::Result<()> {
    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;

    let store = SqliteStore::open("blackbox.db")?;
    let runs = store.list_runs().await?;

    if runs.is_empty() {
        println!("No runs recorded yet.");
    } else {
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
            // Truncate long labels for readability
            let label = if label.len() > 60 {
                format!("{}…", &label[..57])
            } else {
                label.to_string()
            };
            println!(
                "{} {}  {}  {:?}",
                status,
                short_id(&run.id),
                label,
                run.exit_code
            );
        }
    }
    Ok(())
}

async fn cmd_show(args: &ShowArgs) -> anyhow::Result<()> {
    use crate::storage::sqlite::SqliteStore;

    let store = SqliteStore::open("blackbox.db")?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;
    tracing::info!(run_id = %run_id, "show run");
    crate::ui::tui::run_tui(Some(&run_id)).await
}

async fn cmd_timeline(args: &TimelineArgs) -> anyhow::Result<()> {
    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;

    let store = SqliteStore::open("blackbox.db")?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;

    let events = store.get_events(&run_id).await?;
    if events.is_empty() {
        println!("No events recorded for run {}.", short_id(&run_id));
    } else {
        println!(
            "Timeline for run {} ({} events):",
            short_id(&run_id),
            events.len()
        );
        println!(
            "{:<8} {:<12} {:<24} {:<8} {}",
            "SEQ", "SRC", "KIND", "STATUS", "TIMESTAMP"
        );
        println!("{}", "-".repeat(80));
        for ev in &events {
            let status = match &ev.status {
                crate::core::event::EventStatus::Success => "✓",
                crate::core::event::EventStatus::Error => "✗",
                crate::core::event::EventStatus::Running => "●",
                _ => "○",
            };
            println!(
                "{:<8} {:<12} {:<24} {:<8} {}",
                ev.sequence,
                format!("{:?}", ev.source),
                ev.kind,
                status,
                ev.started_at.format("%H:%M:%S%.3f"),
            );
        }
    }
    Ok(())
}

async fn cmd_inspect(args: &InspectArgs) -> anyhow::Result<()> {
    use crate::storage::sqlite::SqliteStore;

    let store = SqliteStore::open("blackbox.db")?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;
    let event = resolve_event_id(&store, &args.event_id, Some(&run_id)).await?;

    // Soft check: warn if event belongs to a different run
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
    if !event.metadata.is_empty() {
        println!("  Metadata:");
        for (k, v) in &event.metadata {
            let val_str = if let Some(s) = v.as_str() {
                if s.len() > 100 {
                    format!("{}...", &s[..100])
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

async fn cmd_diff(args: &DiffArgs) -> anyhow::Result<()> {
    use std::collections::HashMap;

    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;

    let store = SqliteStore::open("blackbox.db")?;
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
        "  A: {} — {:?} ({} events)",
        short_id(&run_a.id),
        run_a.command,
        events_a.len()
    );
    println!(
        "  B: {} — {:?} ({} events)",
        short_id(&run_b.id),
        run_b.command,
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

    let mut sources_a: HashMap<String, usize> = HashMap::new();
    let mut sources_b: HashMap<String, usize> = HashMap::new();
    for ev in &events_a {
        *sources_a.entry(format!("{:?}", ev.source)).or_insert(0) += 1;
    }
    for ev in &events_b {
        *sources_b.entry(format!("{:?}", ev.source)).or_insert(0) += 1;
    }
    let mut all_sources: Vec<String> = sources_a
        .keys()
        .chain(sources_b.keys())
        .cloned()
        .collect();
    all_sources.sort();
    all_sources.dedup();

    if !all_sources.is_empty() {
        println!();
        println!("  Event sources:");
        for src in &all_sources {
            let count_a = sources_a.get(src).copied().unwrap_or(0);
            let count_b = sources_b.get(src).copied().unwrap_or(0);
            if count_a == count_b {
                println!("    {:<12} both {}", src, count_a);
            } else {
                println!("    {:<12} A={}  B={}", src, count_a, count_b);
            }
        }
    }

    // Kind-level diff: kinds only in A or only in B
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

async fn cmd_export(args: &ExportArgs) -> anyhow::Result<()> {
    use crate::export::export_run;
    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;

    tracing::info!(run_id = %args.run_id, format = ?args.format, redact = %args.redact, "export run");

    let store = SqliteStore::open("blackbox.db")?;
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

    let output = export_run(&run, &events, format_str, args.redact).await?;
    print!("{}", output);

    Ok(())
}

async fn cmd_replay(args: &ReplayArgs) -> anyhow::Result<()> {
    use crate::replay::mock::MockReplay;
    use crate::replay::sandbox::SandboxReplay;
    use crate::replay::timeline::TimelineReplay;
    use crate::replay::ReplayEngine;
    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;

    let store = SqliteStore::open("blackbox.db")?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;

    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", run_id))?;
    let events = store.get_events(&run_id).await?;

    // Resolve --from prefix if provided
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

async fn cmd_fork(args: &ForkArgs) -> anyhow::Result<()> {
    use std::sync::Arc;

    use crate::replay::fork::ForkManager;
    use crate::replay::ReplayEngine;
    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;

    let store = Arc::new(SqliteStore::open("blackbox.db")?);
    let run_id = resolve_run_id(store.as_ref(), &args.run_id).await?;

    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", run_id))?;
    let events = store.get_events(&run_id).await?;

    let from_event = if let Some(ref at) = args.at {
        Some(resolve_event_id(store.as_ref(), at, Some(&run_id)).await?.id)
    } else {
        None
    };

    let mut fork = ForkManager::new()
        .with_store(store.clone())
        .with_name(args.name.clone());
    tracing::info!(from = ?from_event, name = ?args.name, "forking run");
    let outcome = fork
        .start(&run, &events, from_event.as_deref())
        .await?;
    println!("Fork finished: {}", outcome);
    Ok(())
}
