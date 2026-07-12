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
    tracing::info!(run_id = %args.run_id, "timeline");
    anyhow::bail!("timeline view not yet implemented")
}

async fn cmd_inspect(args: &InspectArgs) -> anyhow::Result<()> {
    tracing::info!(run_id = %args.run_id, event_id = %args.event_id, "inspect event");
    anyhow::bail!("event inspection not yet implemented")
}

async fn cmd_diff(args: &DiffArgs) -> anyhow::Result<()> {
    tracing::info!(run_a = %args.run_a, run_b = %args.run_b, "diff runs");
    anyhow::bail!("run comparison not yet implemented")
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
        ExportFormat::Html => anyhow::bail!("HTML export not yet implemented"),
        ExportFormat::Portable => anyhow::bail!("portable export not yet implemented"),
    };

    let output = export_run(&run, &events, format_str, args.redact).await?;
    print!("{}", output);

    Ok(())
}

async fn cmd_replay(args: &ReplayArgs) -> anyhow::Result<()> {
    tracing::info!(
        run_id = %args.run_id,
        mock_tools = %args.mock_tools,
        sandbox = %args.sandbox,
        live = %args.live,
        from = ?args.from,
        "replay run"
    );
    anyhow::bail!("replay not yet implemented")
}

async fn cmd_fork(args: &ForkArgs) -> anyhow::Result<()> {
    tracing::info!(
        run_id = %args.run_id,
        at = ?args.at,
        name = ?args.name,
        "fork run"
    );
    anyhow::bail!("fork not yet implemented")
}
