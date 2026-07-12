use clap::{Parser, Subcommand, Args, ValueEnum};

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
    /// Run ID or "latest"
    pub run_id: String,
}

#[derive(Args)]
pub struct TimelineArgs {
    /// Run ID or "latest"
    pub run_id: String,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Run ID or "latest"
    pub run_id: String,
    /// Event ID
    pub event_id: String,
}

#[derive(Args)]
pub struct DiffArgs {
    /// First run ID
    pub run_a: String,
    /// Second run ID
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
    /// Run ID or "latest"
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
    /// Run ID or "latest"
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

    /// Event ID to start replay from
    #[arg(long)]
    pub from: Option<String>,
}

#[derive(Args)]
pub struct ForkArgs {
    /// Run ID or "latest"
    pub run_id: String,

    /// Event ID to fork from
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

async fn cmd_run(args: &RunArgs) -> anyhow::Result<()> {
    use std::sync::Arc;
    use crate::storage::sqlite::SqliteStore;
    use crate::run::RunSupervisor;

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

    println!("Run {} completed with exit code {:?}", run.id, run.exit_code);
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
                _ => "○",
            };
            let cmd = run.command.join(" ");
            let label = run.name.as_deref().unwrap_or(&cmd);
            println!("{} {}  {}  {:?}", status, &run.id[..8], label, run.exit_code);
        }
    }
    Ok(())
}

async fn cmd_show(args: &ShowArgs) -> anyhow::Result<()> {
    tracing::info!(run_id = %args.run_id, "show run");
    crate::ui::tui::run_tui(Some(&args.run_id)).await
}

async fn cmd_timeline(args: &TimelineArgs) -> anyhow::Result<()> {
    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;

    let store = SqliteStore::open("blackbox.db")?;
    let run_id = if args.run_id == "latest" {
        let runs = store.list_runs().await?;
        runs.first()
            .map(|r| r.id.clone())
            .ok_or_else(|| anyhow::anyhow!("no runs recorded"))?
    } else {
        args.run_id.clone()
    };

    let events = store.get_events(&run_id).await?;
    if events.is_empty() {
        println!("No events recorded for run {}.", &run_id[..8]);
    } else {
        println!("Timeline for run {} ({} events):", &run_id[..8], events.len());
        println!("{:<8} {:<6} {:<20} {:<15} {}", "SEQ", "SRC", "KIND", "STATUS", "TIMESTAMP");
        println!("{}", "-".repeat(80));
        for ev in &events {
            let status = match &ev.status {
                crate::core::event::EventStatus::Success => "✓",
                crate::core::event::EventStatus::Error => "✗",
                crate::core::event::EventStatus::Running => "●",
                _ => "○",
            };
            println!(
                "{:<8} {:<6} {:<20} {:<15} {}",
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
    use crate::storage::TraceStore;

    let store = SqliteStore::open("blackbox.db")?;



    let event = store
        .get_event(&args.event_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("event not found: {}", args.event_id))?;

    println!("Event: {}", event.id);
    println!("  Run:       {}", &event.run_id[..8]);
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
    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;

    let store = SqliteStore::open("blackbox.db")?;

    let run_a = store
        .get_run(&args.run_a)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", args.run_a))?;
    let run_b = store
        .get_run(&args.run_b)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", args.run_b))?;

    let events_a = store.get_events(&args.run_a).await?;
    let events_b = store.get_events(&args.run_b).await?;

    println!("Comparing runs:");
    println!("  A: {} — {:?} ({} events)", &run_a.id[..8], run_a.command, events_a.len());
    println!("  B: {} — {:?} ({} events)", &run_b.id[..8], run_b.command, events_b.len());
    println!();

    // Compare status
    if run_a.status == run_b.status {
        println!("  Status:     both {:?}", run_a.status);
    } else {
        println!("  Status:     A={:?}  B={:?}", run_a.status, run_b.status);
    }

    // Compare exit codes
    match (run_a.exit_code, run_b.exit_code) {
        (Some(a), Some(b)) if a == b => println!("  Exit code:  both {}", a),
        (Some(a), Some(b)) => println!("  Exit code:  A={}  B={}", a, b),
        (None, None) => println!("  Exit code:  both unknown"),
        (a, b) => println!("  Exit code:  A={:?}  B={:?}", a, b),
    }

    // Compare event counts by source
    use std::collections::HashMap;
    let mut sources_a: HashMap<String, usize> = HashMap::new();
    let mut sources_b: HashMap<String, usize> = HashMap::new();
    for ev in &events_a {
        *sources_a.entry(format!("{:?}", ev.source)).or_insert(0) += 1;
    }
    for ev in &events_b {
        *sources_b.entry(format!("{:?}", ev.source)).or_insert(0) += 1;
    }
    let mut all_sources: Vec<String> = sources_a.keys().chain(sources_b.keys()).cloned().collect();
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

    Ok(())
}

async fn cmd_export(args: &ExportArgs) -> anyhow::Result<()> {
    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;
    use crate::export::export_run;

    tracing::info!(run_id = %args.run_id, format = ?args.format, redact = %args.redact, "export run");

    let store = SqliteStore::open("blackbox.db")?;

    // Resolve "latest" to the most recent run
    let run_id = if args.run_id == "latest" {
        let runs = store.list_runs().await?;
        runs.first()
            .map(|r| r.id.clone())
            .ok_or_else(|| anyhow::anyhow!("no runs recorded"))?
    } else {
        args.run_id.clone()
    };

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
    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;
    use crate::replay::ReplayEngine;
    use crate::replay::mock::MockReplay;
    use crate::replay::sandbox::SandboxReplay;
    use crate::replay::timeline::TimelineReplay;

    let store = SqliteStore::open("blackbox.db")?;

    let run_id = if args.run_id == "latest" {
        let runs = store.list_runs().await?;
        runs.first()
            .map(|r| r.id.clone())
            .ok_or_else(|| anyhow::anyhow!("no runs recorded"))?
    } else {
        args.run_id.clone()
    };

    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", run_id))?;
    let events = store.get_events(&run_id).await?;

    // --live means unrestricted sandbox policy
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
    let outcome = engine.start(&run, &events, args.from.as_deref()).await?;
    println!("Replay finished: {}", outcome);
    Ok(())
}

async fn cmd_fork(args: &ForkArgs) -> anyhow::Result<()> {
    use std::sync::Arc;
    use crate::storage::sqlite::SqliteStore;
    use crate::storage::TraceStore;
    use crate::replay::ReplayEngine;
    use crate::replay::fork::ForkManager;

    let store = Arc::new(SqliteStore::open("blackbox.db")?);

    let run_id = if args.run_id == "latest" {
        let runs = store.list_runs().await?;
        runs.first()
            .map(|r| r.id.clone())
            .ok_or_else(|| anyhow::anyhow!("no runs recorded"))?
    } else {
        args.run_id.clone()
    };

    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", run_id))?;
    let events = store.get_events(&run_id).await?;

    let mut fork = ForkManager::new()
        .with_store(store.clone())
        .with_name(args.name.clone());
    let from_event = args.at.as_deref();
    tracing::info!(from = ?from_event, name = ?args.name, "forking run");
    let outcome = fork.start(&run, &events, from_event).await?;
    println!("Fork finished: {}", outcome);
    Ok(())
}
