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
    /// Command argv.
    pub command: Command,
}

impl Cli {
    /// Output mode.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `output_mode` — see module docs for full workflow.
    /// ```
    pub fn output_mode(&self) -> OutputMode {
        OutputMode::from_flag(self.json)
    }
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // RunArgs carries optional resume injection
/// `Command` classification.
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
    /// One-shot project setup (enable + optional shell/memory/harden + sample run)
    Setup(SetupArgs),
    /// One-shot failure debugger (postmortem + anomalies + next steps)
    Fail(FailArgs),
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
    /// Project memory pack (1.2 memory bus)
    Memory(MemoryArgs),
    /// Clear unresolved failure attention
    Resolve(ResolveArgs),
    /// Project claim acquire / release / status
    Claim(ClaimArgs),
    /// Acknowledge memory handoff (satisfies gate_mode=require_ack once)
    Ack,
    /// MCP stdio server (tools for status/handoff/postmortem/search/…)
    Mcp,
    /// Sealed offline backup of store sticky files (+ optional DB/blobs)
    Backup(BackupArgs),
    /// Restore a sealed store backup
    Restore(RestoreArgs),
    /// Store integrity check (1.6)
    Fsck(crate::cli_ext::FsckArgs),
    /// Verify a run with an immutable receipt (1.6)
    Verify(crate::cli_ext::VerifyArgs),
    /// Structured experiments (1.6)
    Experiment(crate::cli_ext::ExperimentArgs),
    /// Multi-run experiment report (1.6)
    Report(crate::cli_ext::ReportArgs),
    /// CI regression gate (1.6)
    Gate(crate::cli_ext::GateArgs),
    /// Reproducibility capsule (1.6)
    Capsule(crate::cli_ext::CapsuleArgs),
    /// MCP cassette tools (experimental, 1.6)
    Cassette(crate::cli_ext::CassetteArgs),
    /// Show execution budget capabilities (1.6)
    Budget(crate::cli_ext::BudgetArgs),
    /// External adapter protocol (1.6)
    Adapter(crate::cli_ext::AdapterArgs),
    /// Multi-project metadata index (1.6)
    Projects(crate::cli_ext::ProjectsArgs),
    /// Boundary contracts, containment receipts, evidence gates (1.7)
    Boundary(crate::cli_ext::BoundaryArgs),
    /// External evidence import (1.7)
    Evidence(crate::cli_ext::EvidenceArgs),
    /// Multi-run incident reconstruction (1.7)
    Incident(crate::cli_ext::IncidentArgs),
    /// Local forensic analysis packs (1.7)
    Forensic(crate::cli_ext::ForensicArgs),
}

#[derive(Args, Clone)]
/// `BackupArgs` value.
pub struct BackupArgs {
    /// Output path for sealed backup (`-` = stdout)
    #[arg(short = 'o', long, default_value = "blackbox-backup.bbx.json")]
    pub output: String,
    /// Passphrase for the sealed archive (preferred; also BLACKBOX_EXPORT_PASSPHRASE)
    #[arg(long, env = "BLACKBOX_EXPORT_PASSPHRASE")]
    pub passphrase: Option<String>,
    /// Seal with project store key instead of passphrase
    #[arg(long)]
    pub store_key: bool,
    /// Include SQLite database file
    #[arg(long, default_value_t = true)]
    pub include_db: bool,
    /// Include content-addressed blobs (can be large)
    #[arg(long, default_value_t = false)]
    pub include_blobs: bool,
    /// Max blob bytes to embed when --include-blobs (default 64MiB)
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    pub max_blob_bytes: u64,
}

#[derive(Args, Clone)]
/// `RestoreArgs` value.
pub struct RestoreArgs {
    /// Path to sealed backup (`-` = stdin)
    pub path: String,
    /// Passphrase (or BLACKBOX_EXPORT_PASSPHRASE)
    #[arg(long, env = "BLACKBOX_EXPORT_PASSPHRASE")]
    pub passphrase: Option<String>,
}

#[derive(Args, Default)]
/// `MemoryArgs` value.
pub struct MemoryArgs {
    #[command(subcommand)]
    /// Action.
    pub action: Option<MemoryAction>,

    /// Approximate max tokens for the pack
    #[arg(long, default_value_t = 4000)]
    pub max_tokens: usize,
}

#[derive(Subcommand, Clone)]
/// `MemoryAction` classification.
pub enum MemoryAction {
    /// Show project memory pack
    Show(MemoryShowArgs),
    /// Set intentional memory fields (redacted)
    Set(MemorySetArgs),
}

impl Default for MemoryAction {
    fn default() -> Self {
        Self::Show(MemoryShowArgs::default())
    }
}

#[derive(Args, Default, Clone)]
/// `MemoryShowArgs` value.
pub struct MemoryShowArgs {
    #[arg(long, default_value_t = 4000)]
    /// Max tokens.
    pub max_tokens: usize,
}

#[derive(Args, Clone, Default)]
/// `MemorySetArgs` value.
pub struct MemorySetArgs {
    /// Set project goal (empty string clears when used with --clear-goal)
    #[arg(long)]
    pub goal: Option<String>,
    /// Replace open items list (repeatable; omit all with --clear-open)
    #[arg(long = "open")]
    pub open: Vec<String>,
    /// Clear open_items
    #[arg(long)]
    pub clear_open: bool,
    /// Clear goal
    #[arg(long)]
    pub clear_goal: bool,
    /// Set plan summary
    #[arg(long)]
    pub plan: Option<String>,
}

#[derive(Args, Default)]
/// `ResolveArgs` value.
pub struct ResolveArgs {
    /// Run id to mark resolved (default: sticky unresolved_failure_id)
    pub run_id: Option<String>,
    /// Also clear open_items WIP
    #[arg(long)]
    pub clear_wip: bool,
    /// Also clear goal
    #[arg(long)]
    pub clear_goal: bool,
}

#[derive(Args)]
/// `ClaimArgs` value.
pub struct ClaimArgs {
    #[command(subcommand)]
    /// Action.
    pub action: ClaimAction,
}

#[derive(Subcommand, Clone)]
/// `ClaimAction` classification.
pub enum ClaimAction {
    /// `Acquire` variant.
    Acquire(ClaimAcquireArgs),
    /// `Release` variant.
    Release(ClaimReleaseArgs),
    /// `Status` variant.
    Status,
    /// `Heartbeat` variant.
    Heartbeat(ClaimHeartbeatArgs),
}

#[derive(Args, Clone, Default)]
/// `ClaimAcquireArgs` value.
pub struct ClaimAcquireArgs {
    #[arg(long)]
    /// Goal.
    pub goal: Option<String>,
    #[arg(long)]
    /// Ttl secs.
    pub ttl_secs: Option<u64>,
    #[arg(long)]
    /// Holder.
    pub holder: Option<String>,
    /// Path scope relative to project root (e.g. `src/auth`). Omit for whole-project claim.
    #[arg(long)]
    pub path: Option<String>,
}

#[derive(Args, Clone, Default)]
/// `ClaimReleaseArgs` value.
pub struct ClaimReleaseArgs {
    #[arg(long)]
    /// Holder.
    pub holder: Option<String>,
}

#[derive(Args, Clone, Default)]
/// `ClaimHeartbeatArgs` value.
pub struct ClaimHeartbeatArgs {
    #[arg(long)]
    /// Holder.
    pub holder: Option<String>,
    #[arg(long)]
    /// Ttl secs.
    pub ttl_secs: Option<u64>,
}

#[derive(Args, Default)]
/// `StatusArgs` value.
pub struct StatusArgs {
    /// Attach a resume pack when attention is needed
    #[arg(long)]
    pub resume: bool,

    /// Approximate max tokens for an attached resume pack
    #[arg(long, default_value_t = 4000)]
    pub max_tokens: usize,
}

#[derive(Args, Default)]
/// `HandoffArgs` value.
pub struct HandoffArgs {
    /// Approximate max tokens for the resume pack
    #[arg(long, default_value_t = 4000)]
    pub max_tokens: usize,

    /// Always attach resume pack for last run (even if succeeded)
    #[arg(long)]
    pub always: bool,
}

#[derive(Args)]
/// `ContextArgs` value.
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
/// `SyncArgs` value.
pub struct SyncArgs {
    #[command(subcommand)]
    /// Action.
    pub action: SyncAction,
}

#[derive(Subcommand)]
/// `SyncAction` classification.
pub enum SyncAction {
    /// Export local runs into a sync directory
    Push(SyncDirArgs),
    /// Import missing runs from a sync directory
    Pull(SyncDirArgs),
}

#[derive(Args)]
/// `SyncDirArgs` value.
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
/// `DoctorArgs` value.
pub struct DoctorArgs {
    /// Rebuild the FTS5 full-text index
    #[arg(long)]
    pub reindex: bool,
}

#[derive(Args)]
/// `ServeArgs` value.
pub struct ServeArgs {
    /// Bind address (default 127.0.0.1:7788)
    #[arg(long, default_value = "127.0.0.1:7788")]
    pub bind: String,

    /// Rebuild FTS index before serving
    #[arg(long)]
    pub reindex: bool,

    /// Require this shared secret (browser: POST /session cookie; API: Authorization: Bearer).
    /// When omitted, a one-shot token is auto-generated and printed (fail-closed default).
    #[arg(long, env = "BLACKBOX_SERVE_TOKEN")]
    pub token: Option<String>,

    /// Danger: allow unauthenticated loopback/unix access (any local user can read traces).
    /// Default is off — prefer `--token` / auto-generated token.
    #[arg(long)]
    pub allow_anonymous: bool,

    /// Listen on a Unix domain socket instead of TCP (mode 0600)
    #[arg(long, value_name = "PATH")]
    pub unix_socket: Option<std::path::PathBuf>,

    /// Set Secure flag on session cookies (also implied for non-loopback binds)
    #[arg(long)]
    pub secure_cookies: bool,
}

#[derive(Args)]
/// `RunsArgs` value.
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
/// `TagArgs` value.
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
/// `StatsArgs` value.
pub struct StatsArgs {
    /// Max recent runs to sample for event totals (default: 50)
    #[arg(long, default_value = "50")]
    pub max_runs: usize,
}

#[derive(Args)]
/// `CompletionsArgs` value.
pub struct CompletionsArgs {
    /// Shell to generate completions for
    pub shell: Shell,
}

#[derive(Args)]
/// `SearchArgs` value.
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
/// `WatchArgs` value.
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

#[derive(Args, Clone, Default)]
/// `RunArgs` value.
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

    /// Disable auto-resume injection for this run (overrides config)
    #[arg(long)]
    pub no_auto_resume: bool,

    /// Force auto-resume injection even if config disables it
    /// (this invocation behaves as continuity=always for inject)
    #[arg(long)]
    pub auto_resume: bool,

    /// CI/eval mode: propagate child exit code; write artifacts when --artifact-dir set
    #[arg(long)]
    pub ci: bool,

    /// Eval harness mode: forces observe-only + CI exit codes + tags `eval` + `ci`.
    /// Use for model/harness benchmarks where capture must not mutate the launch.
    #[arg(long)]
    pub eval: bool,

    /// Hard observe-only mode: no prompt mutation, no continuity, no env injection.
    #[arg(long)]
    pub observe_only: bool,

    /// Directory for CI artifacts (run.json, postmortem.json, anomalies.json, optional portable)
    #[arg(long)]
    pub artifact_dir: Option<PathBuf>,

    // ── Experiment metadata (1.6) ──────────────────────────────────
    /// Experiment id to link this run to (creates typed metadata)
    #[arg(long)]
    pub experiment: Option<String>,
    /// Experiment task id
    #[arg(long)]
    pub task: Option<String>,
    /// Experiment variant label
    #[arg(long)]
    pub variant: Option<String>,
    /// Attempt number within task/variant
    #[arg(long)]
    pub attempt: Option<u32>,
    /// Role: baseline | candidate | control | treatment
    #[arg(long)]
    pub role: Option<String>,
    /// Seed string for reproducibility metadata
    #[arg(long)]
    pub seed: Option<String>,
    /// Dataset case id
    #[arg(long)]
    pub dataset_case: Option<String>,
    /// Model name metadata
    #[arg(long)]
    pub model: Option<String>,
    /// Provider name metadata
    #[arg(long)]
    pub provider: Option<String>,
    /// Harness name metadata
    #[arg(long)]
    pub harness: Option<String>,
    /// Path to boundary contract JSON (`blackbox.boundary/v1`) to attach after the run starts
    #[arg(long)]
    pub boundary: Option<PathBuf>,
    /// Parent boundary contract JSON for inheritance (repeatable; root first)
    #[arg(long = "boundary-parent")]
    pub boundary_parent: Vec<PathBuf>,
    /// Force fail-closed on the attached boundary
    #[arg(long)]
    pub boundary_fail_closed: bool,

    /// Harness version metadata
    #[arg(long)]
    pub harness_version: Option<String>,

    // ── Execution budgets (1.6) ────────────────────────────────────
    /// Max wall-clock seconds (enforced via watchdog kill)
    #[arg(long)]
    pub max_wall: Option<u64>,
    /// Max descendant processes (Linux: RLIMIT_NPROC + watchdog)
    #[arg(long)]
    pub max_processes: Option<u64>,
    /// Max captured output bytes (observed; may terminate when exceeded)
    #[arg(long)]
    pub max_output: Option<u64>,
    /// Max tool.call events before termination
    #[arg(long)]
    pub max_tool_calls: Option<u64>,
    /// Max observed tokens (observed-only unless harness enforces)
    #[arg(long)]
    pub max_tokens: Option<u64>,
    /// Max memory bytes (cgroup v2 memory.max when available; else RLIMIT_AS)
    #[arg(long)]
    pub max_memory: Option<u64>,
    /// Max CPU bandwidth as percent of one core (cgroup v2 cpu.max), e.g. 50
    #[arg(long)]
    pub max_cpu_percent: Option<u32>,
    /// Prefer contained launch backends where available (budget capability report)
    #[arg(long)]
    pub contained: bool,

    /// The command to observe (everything after `--`)
    #[arg(last = true, required = true)]
    pub command: Vec<String>,

    /// Prepared resume injection (filled by CLI, not a user flag).
    #[arg(skip)]
    pub resume_injection: Option<crate::resume_inject::ResumeInjection>,

    /// Claim id note for run.notes (filled by CLI when auto_claim acquires).
    #[arg(skip)]
    pub claim_id_note: Option<String>,

    /// When true, this path is ambient maybe-run (never hard-block on gate_mode).
    #[arg(skip)]
    pub ambient: bool,
}

#[derive(Args)]
/// `ShowArgs` value.
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
/// `TimelineArgs` value.
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
/// `RmArgs` value.
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
/// `PurgeArgs` value.
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
/// `MaybeRunArgs` value.
pub struct MaybeRunArgs {
    /// Optional label
    #[arg(long)]
    pub name: Option<String>,

    /// Command after `--`
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Args, Default)]
/// `EnableArgs` value.
pub struct EnableArgs {
    /// Install managed shell wrappers into rc / fish conf.d (idempotent)
    #[arg(long)]
    pub install_shell: bool,

    /// Remove managed shell wrappers from rc / fish conf.d
    #[arg(long)]
    pub uninstall_shell: bool,

    /// Shell for snippets/install: fish, bash, zsh, powershell (default: detect)
    #[arg(long)]
    pub shell: Option<String>,

    /// Set capture.continuity (always|attention|off). New projects default always.
    #[arg(long, value_name = "MODE")]
    pub continuity: Option<String>,

    /// Enable in observe-only mode (recording only, no continuity/memory bus).
    /// Equivalent to setting `capture.observe_only = true` in config.
    #[arg(long)]
    pub observe_only: bool,

    /// Alias for --continuity always (opt into full memory bus)
    #[arg(long)]
    pub memory_bus: bool,

    /// Hardened trust profile: encrypt_blobs + project native logs + external key path
    #[arg(long)]
    pub harden: bool,
}

/// `blackbox setup` — first-time project onboarding (1.3 T2).
#[derive(Args, Default, Clone)]
pub struct SetupArgs {
    /// Enable memory bus (continuity=always)
    #[arg(long)]
    pub memory_bus: bool,

    /// Install shell wrappers for harness basenames
    #[arg(long)]
    pub install_shell: bool,

    /// Shell for install: fish, bash, zsh, powershell (default: detect)
    #[arg(long)]
    pub shell: Option<String>,

    /// Hardened trust profile: encrypt_blobs + project native logs + retention
    #[arg(long)]
    pub harden: bool,

    /// Skip the sample supervised `true` run
    #[arg(long)]
    pub no_sample: bool,

    /// Exit non-zero if doctor daily-driver is not ready after setup
    #[arg(long)]
    pub require_ready: bool,
}

/// `blackbox fail` — one-shot failure story (1.3 T1).
#[derive(Args, Default, Clone)]
pub struct FailArgs {
    /// Run ID, prefix, or "latest" (default: best failure / attention focus)
    pub run_id: Option<String>,

    /// Larger SQL window for big runs
    #[arg(long)]
    pub full: bool,

    /// Exit 1 if the focused run failed/cancelled (CI-friendly)
    #[arg(long)]
    pub fail_on_failure: bool,
}

#[derive(Args)]
/// `SummaryArgs` value.
pub struct SummaryArgs {
    /// Run ID, prefix, or "latest"
    pub run_id: String,

    /// Smaller event window (fast path)
    #[arg(long)]
    pub short: bool,

    /// Larger SQL limit for big runs
    #[arg(long)]
    pub full: bool,

    /// Exit 1 when the run failed/cancelled (CI/eval)
    #[arg(long)]
    pub fail_on_failure: bool,
}

#[derive(Args)]
/// `GcArgs` value.
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
/// `InspectArgs` value.
pub struct InspectArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,
    /// Event ID, unique prefix, sequence number, or "latest"
    pub event_id: String,
}

#[derive(Args)]
/// `DiffArgs` value.
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
/// `ExportFormat` classification.
pub enum ExportFormat {
    /// JSON Lines format
    Jsonl,
    /// Standalone HTML report
    Html,
    /// Portable archive with all blobs
    Portable,
    /// Directory layout (streaming-friendly; requires --output)
    #[value(name = "portable-dir")]
    PortableDir,
}

#[derive(Args)]
/// `ExportArgs` value.
pub struct ExportArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,

    /// Export format
    #[arg(long, default_value = "jsonl")]
    pub format: ExportFormat,

    /// Write to file (or directory for `--format portable-dir`) instead of stdout
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Include secrets (disable redaction). Default is redacted.
    #[arg(long)]
    pub no_redact: bool,

    /// Seal portable export (ChaCha20-Poly1305). Use with --passphrase or store key.
    #[arg(long)]
    pub encrypt: bool,

    /// Passphrase for sealed export (PBKDF2). Implies --encrypt on portable.
    #[arg(long, env = "BLACKBOX_EXPORT_PASSPHRASE")]
    pub passphrase: Option<String>,
}

#[derive(Args)]
/// `ImportArgs` value.
pub struct ImportArgs {
    /// Path to portable JSON file, directory archive, or "-" for stdin
    pub path: String,

    /// Keep original ids (fails if run already exists). Default: assign new ids.
    #[arg(long)]
    pub keep_ids: bool,

    /// Passphrase if the file is a sealed export pack.
    #[arg(long, env = "BLACKBOX_EXPORT_PASSPHRASE")]
    pub passphrase: Option<String>,
}

#[derive(Args)]
/// `ReplayArgs` value.
pub struct ReplayArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,

    /// Recorded tool playback: mock tool results from the trace (no execution, filesystem unchanged).
    /// Guarantee: no child processes; no filesystem or external changes.
    #[arg(long)]
    pub mock_tools: bool,

    /// Workspace re-execution: re-run allowed local commands in a temp directory.
    /// Temporary-directory isolation only — not OS process/network isolation.
    /// External/destructive events blocked; lossy argv reconstruction blocked;
    /// shell interpreters blocked unless --live. Not deterministic LLM replay.
    #[arg(long = "workspace", alias = "sandbox")]
    pub workspace: bool,

    /// Linux contained re-execution via bubblewrap when available.
    /// Best-effort namespaces (network unshare + restricted binds). Fails closed
    /// if `bwrap` is missing. Mutually exclusive with --mock-tools and --live.
    #[arg(long)]
    pub contained: bool,

    /// Live re-execution against the current environment (dangerous).
    /// Guarantee: may change files, network, and external systems. Requires explicit opt-in.
    #[arg(long)]
    pub live: bool,

    /// Event ID (or prefix) to start playback / re-execution from
    #[arg(long)]
    pub from: Option<String>,
}

#[derive(Args)]
/// `ForkArgs` value.
pub struct ForkArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,

    /// Event ID (or prefix) to fork from
    #[arg(long)]
    pub at: Option<String>,

    /// Label for the new run
    #[arg(long)]
    pub name: Option<String>,

    /// After forking, launch the harness-native resume command under blackbox
    /// when a session id was captured. This is native harness resume (not a
    /// reconstructed transcript replay). Without a session id, --launch fails.
    #[arg(long)]
    pub launch: bool,
}

#[derive(Args)]
/// `AnalyzeArgs` value.
pub struct AnalyzeArgs {
    /// Run ID, unique prefix, or "latest"
    pub run_id: String,

    /// Persist derived analysis events back into the store
    #[arg(long)]
    pub persist: bool,
}

#[derive(Args)]
/// `ScrubArgs` value.
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
    /// Execute.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `execute` — see module docs for full workflow.
    /// ```
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
            Command::Enable(args) => cmd_enable(self, args, false).await,
            Command::Disable => cmd_disable(self).await,
            Command::Setup(args) => cmd_setup(self, args).await,
            Command::Fail(args) => cmd_fail(self, args).await,
            Command::Postmortem(args) | Command::Summary(args) => cmd_summary(self, args).await,
            Command::Gc(args) => cmd_gc(self, args).await,
            Command::Context(args) => cmd_context(self, args).await,
            Command::Status(args) => cmd_status(self, args).await,
            Command::Handoff(args) => cmd_handoff(self, args).await,
            Command::Memory(args) => cmd_memory(self, args).await,
            Command::Resolve(args) => cmd_resolve(self, args).await,
            Command::Claim(args) => cmd_claim(self, args).await,
            Command::Ack => cmd_ack(self).await,
            Command::Mcp => cmd_mcp(self).await,
            Command::Backup(args) => cmd_backup(self, args).await,
            Command::Restore(args) => cmd_restore(self, args).await,
            Command::Fsck(args) => {
                let store = open_store(self)?;
                let blob_dir = store.blob_dir().to_path_buf();
                let spool = crate::cli_ext::spool_dir_from_blob_dir(&blob_dir);
                let recovery = crate::cli_ext::recovery_dir_from_blob_dir(&blob_dir);
                crate::cli_ext::cmd_fsck(
                    std::sync::Arc::new(store),
                    blob_dir,
                    spool,
                    recovery,
                    args,
                    self.json,
                )
                .await
            }
            Command::Verify(args) => {
                let store = open_store(self)?;
                let run_id = resolve_run_id(&store, &args.run_id).await?;
                let cwd = std::env::current_dir()?;
                crate::cli_ext::cmd_verify(
                    std::sync::Arc::new(store),
                    &run_id,
                    &cwd,
                    args,
                    self.json,
                )
                .await
            }
            Command::Experiment(args) => {
                let store = open_store(self)?;
                crate::cli_ext::cmd_experiment(std::sync::Arc::new(store), args, self.json).await
            }
            Command::Report(args) => {
                let store = open_store(self)?;
                crate::cli_ext::cmd_report(std::sync::Arc::new(store), args, self.json).await
            }
            Command::Gate(args) => {
                let store = open_store(self)?;
                crate::cli_ext::cmd_gate(std::sync::Arc::new(store), args, self.json).await
            }
            Command::Capsule(args) => {
                let store = open_store(self)?;
                // Resolve run id for create subcommand when needed
                let mut args = args.clone();
                if let crate::cli_ext::CapsuleAction::Create { ref mut run_id, .. } = args.action {
                    *run_id = resolve_run_id(&store, run_id).await?;
                }
                crate::cli_ext::cmd_capsule(std::sync::Arc::new(store), &args, self.json).await
            }
            Command::Cassette(args) => crate::cli_ext::cmd_cassette(args, self.json).await,
            Command::Budget(args) => crate::cli_ext::cmd_budget(args, self.json).await,
            Command::Adapter(args) => crate::cli_ext::cmd_adapter(args, self.json).await,
            Command::Projects(args) => crate::cli_ext::cmd_projects(args, self.json).await,
            Command::Boundary(args) => {
                let store = open_store(self)?;
                let mut args = args.clone();
                // Resolve run ids for subcommands that need them.
                match &mut args.action {
                    crate::cli_ext::BoundaryAction::Show { run_id }
                    | crate::cli_ext::BoundaryAction::Set { run_id, .. }
                    | crate::cli_ext::BoundaryAction::Evaluate { run_id, .. }
                    | crate::cli_ext::BoundaryAction::Receipt { run_id, .. }
                    | crate::cli_ext::BoundaryAction::Detect { run_id, .. }
                    | crate::cli_ext::BoundaryAction::Provenance { run_id, .. } => {
                        *run_id = resolve_run_id(&store, run_id).await?;
                    }
                    crate::cli_ext::BoundaryAction::Validate { .. } => {}
                }
                crate::cli_ext::cmd_boundary(std::sync::Arc::new(store), &args, self.json).await
            }
            Command::Evidence(args) => {
                let store = open_store(self)?;
                let mut args = args.clone();
                if let crate::cli_ext::EvidenceAction::Import {
                    run: Some(ref mut rid),
                    ..
                } = args.action
                {
                    *rid = resolve_run_id(&store, rid).await?;
                }
                if let crate::cli_ext::EvidenceAction::List {
                    run: Some(ref mut rid),
                    ..
                } = args.action
                {
                    *rid = resolve_run_id(&store, rid).await?;
                }
                crate::cli_ext::cmd_evidence(std::sync::Arc::new(store), &args, self.json).await
            }
            Command::Incident(args) => {
                let store = open_store(self)?;
                let mut args = args.clone();
                if let crate::cli_ext::IncidentAction::Create { ref mut runs, .. } = args.action {
                    for rid in runs.iter_mut() {
                        *rid = resolve_run_id(&store, rid).await?;
                    }
                }
                if let crate::cli_ext::IncidentAction::Attach {
                    run: Some(ref mut rid),
                    ..
                } = args.action
                {
                    *rid = resolve_run_id(&store, rid).await?;
                }
                crate::cli_ext::cmd_incident(std::sync::Arc::new(store), &args, self.json).await
            }
            Command::Forensic(args) => {
                let store = open_store(self)?;
                let mut args = args.clone();
                match &mut args.action {
                    crate::cli_ext::ForensicAction::Pack { run_id, .. } => {
                        *run_id = resolve_run_id(&store, run_id).await?;
                    }
                    crate::cli_ext::ForensicAction::Analyze { .. } => {}
                }
                crate::cli_ext::cmd_forensic(std::sync::Arc::new(store), &args, self.json).await
            }
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
    let encrypt = discovery
        .config
        .as_ref()
        .map(|c| c.capture.encrypt_blobs)
        .unwrap_or(false)
        || std::env::var("BLACKBOX_ENCRYPT_BLOBS")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
    let crypto = if encrypt {
        let key_path = crate::crypto::resolve_key_path(&discovery.paths.root);
        Some(crate::crypto::BlobCrypto::load_or_create(&key_path)?)
    } else {
        None
    };
    SqliteStore::open_with_blobs_crypto(&discovery.paths.db_path, &discovery.paths.blob_dir, crypto)
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
    use crate::config::{resolve_continuity, ClaimPolicy, ContinuityMode, GateMode};
    use crate::run::RunSupervisor;
    use crate::state::{
        apply_run_outcome, claim_acquire, claim_holder_id, claim_release_for_run,
        consume_ack_if_present, release_or_rebind_claim, with_state_lock, OutcomeExtras,
        ProjectState,
    };

    if args.insecure_raw {
        eprintln!("warning: --insecure-raw stores unredacted terminal bytes");
    }
    if args.no_redact {
        eprintln!("warning: --no-redact disables all secret redaction");
    }

    // Mutate tags for --eval before execute (eval harness markers).
    let mut args = args.clone();
    if args.eval {
        if !args.tag.iter().any(|t| t == "eval") {
            args.tag.push("eval".into());
        }
        if !args.tag.iter().any(|t| t == "ci") {
            args.tag.push("ci".into());
        }
        args.observe_only = true;
        args.ci = true;
        args.no_auto_resume = true;
        args.auto_resume = false;
    }

    tracing::info!(
        command = ?args.command,
        name = ?args.name,
        project = ?args.project,
        tags = ?args.tag,
        insecure_raw = args.insecure_raw,
        eval = args.eval,
        "run command"
    );

    let discovery = discover(cli).ok();
    let store = open_store(cli)?;
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let cfg_ref = discovery.as_ref().and_then(|d| d.config.as_ref());
    // Effective observe-only: CLI flag, --eval, ambient wrap, or project config.
    // Ambient shell capture is always neutral (no continuity inject).
    // --eval is the model/harness benchmark mode: never mutate launch.
    let observe_only = args.observe_only
        || args.eval
        || args.ambient
        || cfg_ref.map(|c| c.capture.observe_only).unwrap_or(false);
    let ci_mode = args.ci || args.eval;
    let mut policy = CapturePolicy {
        insecure_raw: args.insecure_raw,
        redact: !args.no_redact,
        observe_only,
        ..CapturePolicy::default()
    };
    if let Some(c) = cfg_ref {
        policy = policy.with_process_from_config(&c.capture);
    }

    let continuity = if observe_only {
        ContinuityMode::Off
    } else {
        resolve_continuity(cfg_ref, args.no_auto_resume, args.auto_resume)
    };
    let max_tok = cfg_ref
        .map(|c| c.capture.memory_max_tokens_effective() as usize)
        .unwrap_or(4000);
    let gate_mode = cfg_ref
        .map(|c| c.capture.gate_mode)
        .unwrap_or(GateMode::Off);
    let auto_claim = cfg_ref.map(|c| c.capture.auto_claim).unwrap_or(false) || ci_mode;
    let claim_ttl = cfg_ref.map(|c| c.capture.claim_ttl_secs).unwrap_or(1800);
    let claim_policy = cfg_ref
        .map(|c| c.capture.claim_policy)
        .unwrap_or(ClaimPolicy::Warn);

    // L5 gate (explicit blackbox run only — never hard-block ambient maybe-run)
    if !args.ambient && gate_mode != GateMode::Off {
        if let Some(ref disc) = discovery {
            let sticky = ProjectState::load(&disc.paths.root)
                .ok()
                .flatten()
                .unwrap_or_default();
            if !sticky.attention_level.is_none() || sticky.attention_needed {
                match gate_mode {
                    GateMode::Warn => {
                        if !cli.json {
                            eprintln!(
                                "warning: gate_mode=warn — attention={:?}; run blackbox handoff --json",
                                sticky.attention_level
                            );
                        }
                    }
                    GateMode::RequireAck => {
                        if !consume_ack_if_present(&disc.paths.root) {
                            anyhow::bail!(
                                "gate_mode=require_ack: run `blackbox handoff --json` then `blackbox ack` \
                                 (or set BLACKBOX_ACK=1) before blackbox run"
                            );
                        }
                    }
                    GateMode::Off => {}
                }
            }
            // Claim conflict soft/hard
            if let Some(ref c) = sticky.active_claim {
                if c.is_active(chrono::Utc::now()) {
                    let msg = format!(
                        "project claim held by {} until {}",
                        c.holder,
                        c.expires_at.to_rfc3339()
                    );
                    if claim_policy == ClaimPolicy::BlockRecord && !args.ambient {
                        anyhow::bail!("claim.policy=block_record: {msg}");
                    } else if !cli.json {
                        eprintln!("warning: {msg}");
                    }
                }
            }
        }
    }

    // Prepare continuity injection when enabled.
    let mut args = args.clone();
    if continuity != ContinuityMode::Off {
        if let Some(ref disc) = discovery {
            match crate::resume_inject::prepare_continuity_injection(
                Some(store.as_ref()),
                &disc.paths.root,
                crate::resume_inject::ContinuityPrepareOpts {
                    max_tokens: max_tok,
                    continuity,
                    project_root: disc.project_root.clone(),
                    store_db: disc.paths.db_path.clone(),
                    end_of_run_write: false,
                },
            )
            .await
            {
                Ok(Some(inj)) => {
                    if !cli.json {
                        eprintln!(
                            "continuity: injecting project memory (prior {}, {})",
                            inj.short_id,
                            inj.file_path.display()
                        );
                    }
                    args.resume_injection = Some(inj);
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "continuity prepare failed"),
            }
        }
    }

    // Auto-claim when configured (or --ci)
    if auto_claim {
        if let Some(ref disc) = discovery {
            let (holder, kind) = claim_holder_id(None, None, ci_mode);
            match claim_acquire(&disc.paths.root, &holder, &kind, None, None, claim_ttl) {
                Ok(Ok(c)) => {
                    args.claim_id_note = Some(c.id.clone());
                    tracing::info!(claim = %c.id, "auto_claim acquired");
                }
                Ok(Err(conflict)) => {
                    if claim_policy == ClaimPolicy::BlockRecord && !args.ambient {
                        anyhow::bail!("auto_claim conflict: {conflict}");
                    }
                    if !cli.json {
                        eprintln!("warning: auto_claim: {conflict}");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "auto_claim failed"),
            }
        }
    }

    let budget = crate::budget::BudgetPolicy {
        max_wall_secs: args.max_wall,
        max_processes: args.max_processes,
        max_output_bytes: args.max_output,
        max_tool_calls: args.max_tool_calls,
        max_tokens: args.max_tokens,
        max_memory_bytes: args.max_memory,
        max_cpu_percent: args.max_cpu_percent,
        contained: args.contained,
        ..Default::default()
    };
    let supervisor = RunSupervisor::new(Arc::clone(&store))
        .with_policy(policy)
        .with_budget(budget);
    let run = supervisor.execute(&args).await?;

    // 1.7: mint trace identity for correlation (always for supervised runs).
    {
        use crate::boundary::{PropagationChannel, PropagationStatus, TraceIdentity};
        let mut identity = TraceIdentity::mint(&run.id);
        identity.record_propagation(
            PropagationChannel::ChildEnv,
            PropagationStatus::Attempted,
            Some("BLACKBOX_TRACE_ID not injected in recorder-neutral mode".into()),
        );
        if let Err(e) = store.put_trace_identity(&identity).await {
            tracing::warn!(error = %e, "failed to store trace identity");
        }
    }

    // 1.7: attach resolved boundary contract when --boundary is set.
    let mut attached_boundary = None;
    if let Some(ref boundary_path) = args.boundary {
        match crate::cli_ext::attach_boundary_to_run(
            store.as_ref(),
            &run.id,
            boundary_path,
            &args.boundary_parent,
            args.boundary_fail_closed,
        )
        .await
        {
            Ok(resolved) => {
                if !cli.json {
                    eprintln!(
                        "boundary: attached policy_hash={} to {}",
                        &resolved.policy_hash[..16.min(resolved.policy_hash.len())],
                        crate::util::short_id(&run.id)
                    );
                }
                attached_boundary = Some(resolved);
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to attach boundary contract");
                if !cli.json {
                    eprintln!("warning: failed to attach boundary: {e}");
                }
            }
        }
    }

    // 1.7: launch containment canaries (honest claims; not enforcement).
    {
        use crate::boundary::{launch_containment_receipts, post_run_canary_receipts, LaunchBackendInfo};
        let backend = LaunchBackendInfo {
            backend: if args.contained {
                "contained".into()
            } else {
                "none".into()
            },
            isolation_active: args.contained,
            network_restricted: false,
            ..Default::default()
        };
        let boundary = if attached_boundary.is_some() {
            attached_boundary.clone()
        } else {
            store.get_run_boundary(&run.id).await.ok().flatten()
        };
        for r in launch_containment_receipts(&run.id, boundary.as_ref(), &backend) {
            let _ = store.insert_containment_receipt(&r).await;
        }
        // Post-run canary from capture/external evidence.
        let events = store.get_events(&run.id).await.unwrap_or_default();
        let external = store
            .list_external_evidence_for_run(&run.id)
            .await
            .unwrap_or_default();
        let process_present = events.iter().any(|e| {
            matches!(e.source, crate::core::event::EventSource::Process)
        });
        let public_egress = external.iter().any(|e| {
            e.destination
                .as_deref()
                .map(|d| d.starts_with("http://") || d.starts_with("https://"))
                .unwrap_or(false)
        }) || events.iter().any(|e| {
            e.metadata
                .get("url")
                .or_else(|| e.metadata.get("destination"))
                .and_then(|v| v.as_str())
                .map(|d| d.starts_with("http://") || d.starts_with("https://"))
                .unwrap_or(false)
        });
        for r in post_run_canary_receipts(
            &run.id,
            boundary.as_ref(),
            public_egress,
            process_present,
        ) {
            let _ = store.insert_containment_receipt(&r).await;
        }
        // Auto-detect findings when boundary present.
        if boundary.is_some() {
            use crate::boundary::{detect_boundary_findings, DetectInputs};
            let findings = detect_boundary_findings(DetectInputs {
                run_id: &run.id,
                contract: boundary.as_ref().map(|b| &b.contract),
                events: &events,
                external: &external,
            });
            for f in findings {
                let _ = store.insert_boundary_finding(&f).await;
            }
        }
    }

    // 1.6: persist typed experiment metadata when --experiment (or related) set.
    if args.experiment.is_some()
        || args.task.is_some()
        || args.variant.is_some()
        || args.model.is_some()
    {
        use crate::experiment::{ExperimentRole, RunExperimentMeta};
        let role = match args.role.as_deref() {
            Some("baseline") => ExperimentRole::Baseline,
            Some("candidate") => ExperimentRole::Candidate,
            Some("control") => ExperimentRole::Control,
            Some("treatment") => ExperimentRole::Treatment,
            _ => ExperimentRole::Unknown,
        };
        // Ensure experiment row exists when id provided.
        if let Some(ref exp_id) = args.experiment {
            if store.get_experiment(exp_id).await?.is_none() {
                let m = crate::experiment::ExperimentManifest::new(
                    exp_id,
                    exp_id,
                );
                let _ = store.upsert_experiment(&m).await;
            }
        }
        let mut meta = RunExperimentMeta {
            experiment_id: args.experiment.clone(),
            task_id: args.task.clone(),
            variant: args.variant.clone(),
            attempt: args.attempt,
            role,
            seed: args.seed.clone(),
            dataset_case: args.dataset_case.clone(),
            model: args.model.clone(),
            provider: args.provider.clone(),
            harness: args.harness.clone(),
            harness_version: args.harness_version.clone(),
            git_commit: None,
            config_fingerprint: None,
        };
        // Auto-number attempts when omitted; always stamp config fingerprint.
        if meta.attempt.is_none() {
            if let Some(ref exp_id) = meta.experiment_id {
                let run_ids = store
                    .list_runs_for_experiment(exp_id)
                    .await
                    .unwrap_or_default();
                let mut existing = Vec::new();
                for rid in run_ids {
                    if rid == run.id {
                        continue;
                    }
                    if let Ok(Some(m)) = store.get_run_experiment_meta(&rid).await {
                        existing.push(m);
                    }
                }
                meta.attempt =
                    Some(crate::experiment::next_attempt_number(&existing, &meta));
            } else {
                meta.attempt = Some(1);
            }
        }
        meta = meta.with_fingerprint();
        if let Err(e) = store.put_run_experiment_meta(&run.id, &meta).await {
            tracing::warn!(error = %e, "failed to store experiment metadata");
        } else if !cli.json {
            if let Some(ref e) = args.experiment {
                eprintln!("experiment: linked run {} → {e}", crate::util::short_id(&run.id));
            }
        }

        // 1.7: auto provenance from experiment dataset_case / task + observed evidence.
        {
            use crate::boundary::auto_provenance_record;
            let external = store
                .list_external_evidence_for_run(&run.id)
                .await
                .unwrap_or_default();
            if let Some(rec) = auto_provenance_record(&run.id, Some(&meta), &external) {
                if let Err(e) = store.insert_provenance_record(&rec).await {
                    tracing::warn!(error = %e, "auto provenance record failed");
                } else if !cli.json {
                    eprintln!(
                        "provenance: auto status={} declared={} observed={}",
                        rec.status.as_str(),
                        rec.declared_sources.len(),
                        rec.observed_sources.len()
                    );
                }
            }
        }
    }

    // Sticky project state under state.lock + MEMORY refresh (1.2).
    if let Some(ref disc) = discovery {
        let run_for_state = run.clone();
        let claim_note = args.claim_id_note.clone();
        let git_dirty = crate::memory::live_git_status(&disc.project_root).dirty;
        let files_touched_nonempty = {
            if let Ok(events) = store.get_events(&run_for_state.id).await {
                events.iter().any(|e| {
                    e.kind.starts_with("filesystem.")
                        && !e.kind.contains("observer")
                        && !e.kind.contains("snapshot")
                })
            } else {
                false
            }
        };

        if let Err(e) = with_state_lock(&disc.paths.root, |state| {
            let claim_released = release_or_rebind_claim(state, &run_for_state);
            let _ = claim_note; // claim id already used at acquire; release is by run_id
            apply_run_outcome(
                state,
                &run_for_state,
                OutcomeExtras {
                    git_dirty,
                    files_touched_nonempty,
                    claim_released,
                    ..Default::default()
                },
            );
            // Goal extract: use run name if goal empty
            if state.intent.goal.is_none() {
                if let Some(ref n) = run_for_state.name {
                    if !n.is_empty() {
                        state.intent.goal = Some(n.clone());
                    }
                }
            }
            Ok(())
        }) {
            tracing::warn!(error = %e, "failed to update sticky state under lock");
        }

        // Release auto-claim held for this run (best-effort outside, also under lock path)
        if args.claim_id_note.is_some() {
            let _ = claim_release_for_run(&disc.paths.root, &run.id);
        }

        // End-of-run MEMORY refresh when continuity ≠ off and not observe-only
        if !args.observe_only {
            if let Err(e) = crate::resume_inject::refresh_memory_files_end_of_run(
                Some(store.as_ref()),
                &disc.paths.root,
                &disc.project_root,
                &disc.paths.db_path,
                continuity,
                max_tok,
            )
            .await
            {
                tracing::warn!(error = %e, "end-of-run MEMORY refresh failed");
            }
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

    // CI artifacts: stable files for eval pipelines.
    if let Some(ref dir) = args.artifact_dir {
        if let Err(e) = write_ci_artifacts(store.as_ref(), &run, dir).await {
            tracing::warn!(error = %e, "failed to write CI artifacts");
            if ci_mode {
                anyhow::bail!("CI artifact write failed: {e}");
            }
        } else if !cli.json {
            eprintln!("artifacts: {}", dir.display());
        }
    }

    let attention = matches!(
        run.status,
        crate::core::run::RunStatus::Failed | crate::core::run::RunStatus::Cancelled
    );

    if cli.json {
        #[derive(serde::Serialize)]
        struct RunDone {
            run_id: String,
            short_id: String,
            exit_code: Option<i32>,
            status: String,
            attention_needed: bool,
            handoff_hint: String,
            artifact_dir: Option<String>,
            ci: bool,
            eval: bool,
        }
        let result = output::emit_ok(
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
                artifact_dir: args.artifact_dir.as_ref().map(|p| p.display().to_string()),
                ci: ci_mode,
                eval: args.eval,
            },
        );
        if ci_mode {
            let code = run.exit_code.unwrap_or(1);
            if code != 0 {
                std::process::exit(code);
            }
        }
        return result;
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
    if attention {
        println!(
            "  handoff: blackbox handoff --json  (or: blackbox context {} --for-resume --json)",
            short_id(&run.id)
        );
    }

    // CI/eval: propagate supervised process exit code.
    if ci_mode {
        let code = run.exit_code.unwrap_or(1);
        if code != 0 {
            std::process::exit(code);
        }
    }
    Ok(())
}

/// Write `run.json` + `postmortem.json` under artifact_dir (CI/eval convention).
async fn write_ci_artifacts(
    store: &dyn TraceStore,
    run: &crate::core::run::Run,
    dir: &std::path::Path,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let run_path = dir.join("run.json");
    std::fs::write(&run_path, serde_json::to_string_pretty(run)?)?;

    let summary = crate::summary::build_summary(
        store,
        run,
        crate::summary::SummaryOptions {
            short: false,
            full: false,
        },
    )
    .await?;
    std::fs::write(
        dir.join("postmortem.json"),
        serde_json::to_string_pretty(&summary)?,
    )?;
    // Anomalies as a first-class eval artifact
    std::fs::write(
        dir.join("anomalies.json"),
        serde_json::to_string_pretty(&summary.anomalies)?,
    )?;
    // Headline + next for quick CI logs
    std::fs::write(
        dir.join("summary.txt"),
        format!(
            "headline: {}\nnext: {}\nstatus: {:?}\nexit: {:?}\nanomalies: {}\n",
            summary.headline,
            summary.next_action,
            summary.status,
            summary.exit_code,
            summary.anomalies.len()
        ),
    )?;

    // Stable eval scorer document (blackbox.score/v1)
    let score = crate::score::EvalScore::from_run_summary(run, &summary);
    std::fs::write(dir.join("score.json"), score.to_pretty_json()?)?;

    // Optional portable export for offline eval scoring
    if let Ok(events) = store.get_events(&run.id).await {
        if let Ok(archive) = crate::export::export_portable_secure(store, run, &events, true).await
        {
            let _ = std::fs::write(dir.join("portable.json"), archive);
        }
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
    }

    // Cursor-friendly page API: avoid loading the entire runs table when limited.
    let page_limit = args.limit.unwrap_or(10_000).max(1);
    let filters = crate::storage::RunFilters {
        status: args.status.clone(),
        tag: args.tag.first().cloned(),
    };
    let page = store.list_runs_page(None, page_limit, &filters).await?;
    // Multi-tag: if more than one --tag, filter the page in memory.
    let mut runs = page.runs;
    if args.tag.len() > 1 {
        runs.retain(|r| args.tag.iter().any(|t| r.tags.iter().any(|rt| rt == t)));
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
    let db_bytes = std::fs::metadata(store.db_path()).ok().map(|m| m.len());
    let total_storage_bytes = db_bytes.map(|d| d.saturating_add(blob_bytes));
    let storage_warning = storage_soft_warning(total_storage_bytes, blob_bytes);
    let avg_events_per_run = if sample.is_empty() {
        None
    } else {
        Some(total_events as f64 / sample.len() as f64)
    };
    let avg_blob_bytes_per_run = if runs.is_empty() {
        None
    } else {
        Some(blob_bytes as f64 / runs.len() as f64)
    };

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
            avg_events_per_run,
            avg_blob_bytes_per_run,
            top_kinds: top_kinds.clone(),
            blob_files,
            blob_bytes,
            db_bytes,
            total_storage_bytes,
            storage_warning: storage_warning.clone(),
        };
        return output::emit_ok("stats", &view);
    }

    println!("Store: {}", store.db_path().display());
    println!("Blobs: {}", store.blob_dir().display());
    if let Some(total) = total_storage_bytes {
        println!(
            "Size:  {} total (db {} + blobs {} in {} files)",
            format_bytes(total),
            format_bytes(db_bytes.unwrap_or(0)),
            format_bytes(blob_bytes),
            blob_files
        );
    }
    if let Some(ref w) = storage_warning {
        println!("warn:  {w}");
    }
    if let Some(avg) = avg_events_per_run {
        println!(
            "Avg:   {:.1} events/run (sample {}) · {:.0} blob bytes/run",
            avg,
            sample.len(),
            avg_blob_bytes_per_run.unwrap_or(0.0)
        );
    }
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
        let capture_coverage = events
            .iter()
            .find(|e| e.kind == "capture.coverage")
            .and_then(|e| e.metadata.get("coverage").cloned());
        let process_tree = {
            let roots = crate::core::process_tree::rebuild_from_events(&events);
            if roots.is_empty() {
                None
            } else {
                Some(views::ProcessTreeShowView {
                    root_count: roots.len(),
                    node_count: roots.iter().map(|r| r.count_nodes()).sum(),
                    ascii: crate::core::process_tree::ProcessNode::format_forest(&roots),
                })
            }
        };
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
            capture_coverage,
            process_tree,
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
    if let Some(cov) = events
        .iter()
        .find(|e| e.kind == "capture.coverage")
        .and_then(|e| e.metadata.get("coverage"))
    {
        let score = cov
            .get("quality_score")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let surfaces = cov
            .get("surfaces")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        println!("  Capture:  quality={score}% · {surfaces} surfaces");
    }
    let tree_roots = crate::core::process_tree::rebuild_from_events(&events);
    if !tree_roots.is_empty() {
        let nodes: usize = tree_roots.iter().map(|r| r.count_nodes()).sum();
        println!("  Process:  {nodes} node(s) in tree");
        let ascii = crate::core::process_tree::ProcessNode::format_forest(&tree_roots);
        for line in ascii.lines().take(12) {
            println!("    {line}");
        }
        if ascii.lines().count() > 12 {
            println!("    … (truncated; use --json for full tree)");
        }
    }

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

    // Trajectory-first compare with explain text (ultimate debugger UX).
    let traj = crate::trajectory::diff_trajectories(&id_a, &events_a, &id_b, &events_b);
    if cli.json {
        return output::emit_ok("diff", &traj);
    }
    print!("{}", crate::trajectory::format_diff_text(&traj));
    if args.trajectory {
        return Ok(());
    }
    println!();

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
    use crate::export::portable::export_portable_dir;

    let redact = !args.no_redact;
    let want_seal = args.encrypt || args.passphrase.is_some();
    tracing::info!(run_id = %args.run_id, format = ?args.format, redact = %redact, seal = %want_seal, "export run");

    let store = open_store(cli)?;
    let run_id = resolve_run_id(&store, &args.run_id).await?;

    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {}", run_id))?;

    let events = store.get_events(&run_id).await?;

    if matches!(args.format, ExportFormat::PortableDir) {
        if want_seal {
            anyhow::bail!("--encrypt / --passphrase not supported with --format portable-dir");
        }
        let out = args.output.as_deref().ok_or_else(|| {
            anyhow::anyhow!("--format portable-dir requires -o/--output <directory>")
        })?;
        let dir = std::path::Path::new(out);
        export_portable_dir(&store, &run, &events, dir, redact).await?;
        if cli.json {
            return output::emit_ok(
                "export",
                &serde_json::json!({
                    "run_id": run.id,
                    "format": "portable.dir/v1",
                    "path": out,
                    "redacted": redact,
                }),
            );
        }
        println!("exported portable directory to {}", dir.display());
        return Ok(());
    }

    let format_str = match args.format {
        ExportFormat::Jsonl => "jsonl",
        ExportFormat::Html => "html",
        ExportFormat::Portable => "portable",
        ExportFormat::PortableDir => unreachable!("handled above"),
    };

    if want_seal && format_str != "portable" {
        anyhow::bail!("--encrypt / --passphrase only supported with --format portable");
    }

    let mut output = export_run(&store, &run, &events, format_str, redact).await?;
    if want_seal {
        let discovery = discover(cli).ok();
        let store_crypto = discovery.as_ref().and_then(|d| {
            crate::crypto::BlobCrypto::load_existing(&crate::crypto::resolve_key_path(
                &d.paths.root,
            ))
            .ok()
            .flatten()
        });
        // Prefer store crypto from open path when encrypt_blobs is on
        let store_crypto = store_crypto.or_else(|| {
            if store.blob_encryption_enabled() {
                discovery.as_ref().and_then(|d| {
                    crate::crypto::BlobCrypto::load_or_create(&crate::crypto::resolve_key_path(
                        &d.paths.root,
                    ))
                    .ok()
                })
            } else {
                None
            }
        });
        output = crate::crypto::seal_export_pack(
            &output,
            args.passphrase.as_deref(),
            store_crypto.as_ref(),
        )?;
    }
    if let Some(path) = args.output.as_deref() {
        std::fs::write(path, &output).map_err(|e| anyhow::anyhow!("write {}: {e}", path))?;
        if cli.json {
            return output::emit_ok(
                "export",
                &serde_json::json!({
                    "run_id": run.id,
                    "format": format_str,
                    "path": path,
                    "redacted": redact,
                    "bytes": output.len(),
                }),
            );
        }
        eprintln!("wrote {} ({} bytes)", path, output.len());
        return Ok(());
    }
    print!("{}", output);

    Ok(())
}

async fn cmd_import(cli: &Cli, args: &ImportArgs) -> anyhow::Result<()> {
    use crate::export::portable::{import_portable, import_portable_dir};

    // Directory layout (streaming portable) — import before reading as a single file.
    let path_obj = std::path::Path::new(&args.path);
    if args.path != "-" && path_obj.is_dir() {
        let store = open_store(cli)?;
        let result = import_portable_dir(&store, path_obj, !args.keep_ids).await?;
        if cli.json {
            return output::emit_ok(
                "import",
                &serde_json::json!({
                    "run_id": result.run_id,
                    "events": result.events,
                    "blobs": result.blobs,
                    "remapped": result.remapped,
                    "format": "portable.dir/v1",
                }),
            );
        }
        println!(
            "imported run {} ({} events, {} blobs{})",
            crate::util::short_id(&result.run_id),
            result.events,
            result.blobs,
            if result.remapped {
                ", remapped ids"
            } else {
                ""
            }
        );
        return Ok(());
    }

    let mut json = if args.path == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(&args.path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", args.path))?
    };

    // Unwrap sealed export packs before import.
    if crate::crypto::is_sealed_export_pack(&json) {
        let discovery = discover(cli).ok();
        let store_crypto = discovery.as_ref().and_then(|d| {
            crate::crypto::BlobCrypto::load_existing(&crate::crypto::resolve_key_path(
                &d.paths.root,
            ))
            .ok()
            .flatten()
        });
        json = crate::crypto::open_export_pack(
            &json,
            args.passphrase.as_deref(),
            store_crypto.as_ref(),
        )?;
    }

    let store = open_store(cli)?;
    let new_ids = !args.keep_ids;
    if args.keep_ids {
        // Validate that the input is a JSON object with an "id" field before
        // attempting import, so we fail early with a clear message.
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| anyhow::anyhow!("--keep-ids requires valid JSON: {e}"))?;
        // Portable packs nest id under run; accept either shape.
        let has_id =
            parsed.get("id").is_some() || parsed.get("run").and_then(|r| r.get("id")).is_some();
        if !has_id {
            anyhow::bail!(
                "--keep-ids: imported JSON must contain a top-level \"id\" or run.id field"
            );
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
    // --contained implies workspace-style re-execution with bwrap when available.
    let mode_count =
        args.mock_tools as u8 + args.workspace as u8 + args.contained as u8 + args.live as u8;
    if mode_count > 1 {
        anyhow::bail!(
            "conflicting replay flags: --mock-tools, --workspace/--sandbox, --contained, and --live are mutually exclusive"
        );
    }

    use crate::core::command::CommandMetadata;
    use crate::replay::mock::MockReplay;
    use crate::replay::sandbox::{probe_contained_backend, SandboxReplay};
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

    // Preflight: honest guarantees before any execution.
    let mode_name = if args.live {
        "Live re-execution"
    } else if args.contained {
        "Contained re-execution"
    } else if args.workspace {
        "Workspace re-execution"
    } else if args.mock_tools {
        "Recorded tool playback"
    } else {
        "Timeline playback"
    };
    let mut executable_cmds = 0usize;
    let mut lossy_cmds = 0usize;
    let mut shell_cmds = 0usize;
    for ev in &events {
        if let Some(meta) = CommandMetadata::from_event(ev) {
            if meta.fidelity.is_safe_for_sandbox() {
                executable_cmds += 1;
            } else if !meta.argv.is_empty() || meta.shell_source.is_some() {
                lossy_cmds += 1;
            }
            if meta
                .argv
                .first()
                .map(|a| {
                    let base = std::path::Path::new(a)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(a);
                    matches!(base, "sh" | "bash" | "dash" | "zsh" | "fish" | "ksh")
                })
                .unwrap_or(false)
            {
                shell_cmds += 1;
            }
        }
    }
    if !cli.json {
        println!("═══ Replay preflight ═══");
        println!("mode:       {mode_name}");
        println!("run:        {}", crate::util::short_id(&run.id));
        println!("events:     {}", events.len());
        match mode_name {
            "Timeline playback" => {
                println!("executes:   no — prints the recorded timeline only");
                println!("filesystem: unchanged");
                println!("external:   unchanged");
                println!("note:       not deterministic LLM replay");
            }
            "Recorded tool playback" => {
                println!("executes:   no — mocks tool outputs from the trace");
                println!("filesystem: unchanged");
                println!("external:   unchanged");
                println!("note:       not deterministic LLM replay");
            }
            "Workspace re-execution" => {
                println!("executes:   yes — allowed local commands only (temp directory)");
                println!("filesystem: temporary workspace (seeded/best-effort git restore)");
                println!("isolation:  temporary-directory (NOT OS process/network isolation)");
                println!("external:   not kernel-blocked (policy filter only)");
                println!("destructive:blocked by default (policy)");
                println!("lossy argv: blocked ({lossy_cmds} lossy / {executable_cmds} exact-or-inferred)");
                println!("shell cmds: blocked under workspace policy ({shell_cmds} detected)");
                println!("note:       not deterministic LLM replay");
            }
            "Contained re-execution" => {
                let probe = probe_contained_backend();
                println!("executes:   yes — allowed local commands under bwrap when available");
                println!("filesystem: temporary workspace (seeded/best-effort git restore)");
                if probe.available {
                    println!("isolation:  best-effort namespaces (bwrap unshare-net + binds)");
                    println!("backend:    {}", probe.reason);
                } else {
                    println!("isolation:  UNAVAILABLE — will fail closed");
                    println!("backend:    {}", probe.reason);
                }
                println!("destructive:blocked by default (policy)");
                println!("lossy argv: blocked ({lossy_cmds} lossy / {executable_cmds} exact-or-inferred)");
                println!("shell cmds: blocked under workspace policy ({shell_cmds} detected)");
                println!("note:       not multi-tenant hardened; not deterministic LLM replay");
            }
            "Live re-execution" => {
                println!("executes:   yes — against the CURRENT environment");
                println!("filesystem: MAY CHANGE");
                println!("external:   MAY CHANGE");
                println!("destructive:ALLOWED");
                println!("warning:    live mode is dangerous; prefer --workspace");
                println!("note:       not deterministic LLM replay");
            }
            _ => {}
        }
        println!("{}", "─".repeat(48));
    }

    let mut engine: Box<dyn ReplayEngine> = if args.mock_tools {
        Box::new(MockReplay)
    } else if args.workspace || args.contained || args.live {
        let policy = if args.live {
            crate::replay::ReplayPolicy::Live
        } else {
            crate::replay::ReplayPolicy::Sandbox
        };
        let checkpoints = store.get_checkpoints(&run_id).await.unwrap_or_default();
        let git_commit = checkpoints
            .iter()
            .rev()
            .find_map(|c| c.git_commit.clone().filter(|g| !g.is_empty()));
        let git_diff = {
            let mut text = None;
            for cp in checkpoints.iter().rev() {
                if let Some(ref key) = cp.git_diff_blob {
                    if let Some(bref) = crate::core::blob::BlobReference::try_new(key.clone(), 0) {
                        if let Ok(bytes) = store.load_blob(&bref).await {
                            text = Some(String::from_utf8_lossy(&bytes).into_owned());
                            break;
                        }
                    }
                }
            }
            text
        };
        Box::new(
            SandboxReplay::new()
                .with_policy(policy)
                .with_git_commit(git_commit)
                .with_git_diff(git_diff)
                .with_contained(args.contained),
        )
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
    println!("Forked continuation guarantee:");
    if let Some(ref cmd) = resume {
        println!("  mode:    native harness resume (session-based)");
        println!("  command: {}", crate::resume::format_command(cmd));
        println!("  note:    not reconstructed-context or deterministic LLM replay");
    } else {
        println!("  mode:    fork record only (no native session to resume)");
        println!("  command: (unavailable — no harness session id captured)");
        println!("  tip:     record with `claude -p …` so session ids are captured");
        println!("  note:    not reconstructed-context or deterministic LLM replay");
    }

    if args.launch {
        let cmd = resume.ok_or_else(|| {
            anyhow::anyhow!("--launch requires a known harness session (native resume); none found")
        })?;
        println!();
        println!(
            "Launching native harness resume under blackbox: {}",
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
            no_auto_resume: false,
            auto_resume: false,
            ci: false,
            eval: false,
            observe_only: false,
            artifact_dir: None,
            resume_injection: None,
            claim_id_note: None,
            ambient: false,
            command: cmd,
        ..Default::default()
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

    // Auto-GC when scrub rewrote blobs (old secret content-addressed keys become orphans).
    let rewrote = report.blobs_rewritten > 0;
    if rewrote && !args.gc && !args.dry_run {
        let (files, meta) = gc_unreferenced_blobs(store.as_ref(), &blob_dir, false).await?;
        println!(
            "auto-gc after scrub: {} orphan file(s), {} metadata row(s)",
            files, meta
        );
    }

    if report.runs_updated + report.events_updated + report.blobs_rewritten == 0 && !args.gc {
        println!("No secrets found (or already clean).");
    } else if args.dry_run {
        println!("Re-run without --dry-run to apply.");
    } else if !args.gc && !rewrote {
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
    // Legacy env only here; decide() also checks supervisor PID markers (1.4 N1).
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
            let result = cmd_run(cli, &run_args).await;
            // Optional one-line ambient notice (default off)
            if result.is_ok() {
                if let Ok(discovery) = discover_project(
                    &std::env::current_dir().unwrap_or_default(),
                    cli.store.as_deref(),
                ) {
                    let notice = discovery
                        .config
                        .as_ref()
                        .map(|c| c.capture.ambient_notice)
                        .unwrap_or(false);
                    if notice {
                        if let Ok(store) = open_store(cli) {
                            if let Ok(runs) = store.list_runs().await {
                                if let Some(r) = runs.first() {
                                    eprintln!(
                                        "blackbox: recorded {} (exit={:?})",
                                        short_id(&r.id),
                                        r.exit_code
                                    );
                                }
                            }
                        }
                    }
                }
            }
            result
        }
    }
}

/// Resolve which run `blackbox fail` should explain.
///
/// Order: explicit spec → sticky unresolved failure → last failed in list → latest.
async fn resolve_fail_focus(
    store: &dyn TraceStore,
    discovery: &crate::config::ProjectDiscovery,
    spec: Option<&str>,
) -> anyhow::Result<(String, &'static str)> {
    if let Some(s) = spec {
        let id = resolve_run_id(store, s).await?;
        return Ok((id, "explicit"));
    }

    // Sticky unresolved failure (M6)
    if let Ok(Some(st)) = crate::state::ProjectState::load(&discovery.paths.root) {
        if let Some(fid) = st.unresolved_failure_id {
            if store.get_run(&fid).await?.is_some() {
                return Ok((fid, "unresolved_failure"));
            }
        }
    }

    let runs = store.list_runs().await?;
    if runs.is_empty() {
        anyhow::bail!("no runs recorded — blackbox run -- <cmd> first");
    }

    // Prefer failed/cancelled or non-zero exit
    if let Some(r) = runs.iter().find(|r| {
        matches!(
            r.status,
            crate::core::run::RunStatus::Failed | crate::core::run::RunStatus::Cancelled
        ) || r.exit_code.is_some_and(|c| c != 0)
    }) {
        return Ok((r.id.clone(), "last_failure"));
    }

    Ok((runs[0].id.clone(), "latest"))
}

async fn cmd_fail(cli: &Cli, args: &FailArgs) -> anyhow::Result<()> {
    use crate::summary::{build_summary, format_summary_text, SummaryOptions};

    let discovery = discover(cli)?;
    let store = open_store(cli)?;
    let (run_id, focus_reason) =
        resolve_fail_focus(&store, &discovery, args.run_id.as_deref()).await?;
    let run = store
        .get_run(&run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found: {run_id}"))?;

    let opts = if args.full {
        SummaryOptions {
            short: false,
            full: true,
        }
    } else {
        SummaryOptions::default()
    };
    let summary = build_summary(&store, &run, opts).await?;
    let short = short_id(&run.id).to_string();
    let failed = matches!(
        run.status,
        crate::core::run::RunStatus::Failed | crate::core::run::RunStatus::Cancelled
    ) || run.exit_code.is_some_and(|c| c != 0);

    let next_commands = vec![
        format!("blackbox timeline {short} --semantic"),
        format!("blackbox show {short} --tui"),
        format!("blackbox postmortem {short} --json"),
        "blackbox resolve".into(),
    ];

    #[derive(serde::Serialize)]
    struct FailView {
        focus: String,
        run_id: String,
        short_id: String,
        failed: bool,
        summary: crate::summary::SummaryView,
        next_commands: Vec<String>,
    }

    let view = FailView {
        focus: focus_reason.into(),
        run_id: run.id.clone(),
        short_id: short.clone(),
        failed,
        summary: summary.clone(),
        next_commands: next_commands.clone(),
    };

    if cli.json {
        let result = output::emit_ok("fail", &view);
        if args.fail_on_failure && failed {
            std::process::exit(1);
        }
        return result;
    }

    println!(
        "blackbox fail · focus={} · {} · {:?} · exit={:?}",
        focus_reason, short, run.status, run.exit_code
    );
    print!("{}", format_summary_text(&summary));
    if !summary.anomalies.is_empty() {
        println!("── Anomalies (top) ───────────────────────────────");
        for a in summary.anomalies.iter().take(8) {
            let seq = a.sequence.map(|s| format!(" seq={s}")).unwrap_or_default();
            println!(
                "  ! [{}|{}] {}{seq}",
                a.severity,
                a.kind,
                crate::util::truncate(&a.detail, 100)
            );
        }
    }
    println!("── Next ──────────────────────────────────────────");
    for c in &next_commands {
        println!("  {c}");
    }
    if args.fail_on_failure && failed {
        std::process::exit(1);
    }
    Ok(())
}

async fn cmd_setup(cli: &Cli, args: &SetupArgs) -> anyhow::Result<()> {
    use crate::config::BlackboxConfig;

    // 1) Enable (reuse enable flags). Force text mode so --json only emits setup once.
    let enable_args = EnableArgs {
        install_shell: args.install_shell,
        uninstall_shell: false,
        shell: args.shell.clone(),
        continuity: None,
        observe_only: false,
        memory_bus: args.memory_bus,
        harden: args.harden,
    };
    // Quiet enable: no JSON/text so `setup --json` emits a single envelope.
    let enable_cli = Cli {
        store: cli.store.clone(),
        json: false,
        command: Command::Disable, // unused by cmd_enable
    };
    cmd_enable(&enable_cli, &enable_args, true).await?;

    let cwd = std::env::current_dir()?;
    let discovery = discover_project(&cwd, cli.store.as_deref())?;
    let config_path = discovery.paths.root.join("config.toml");

    let mut key_path_note: Option<String> = None;
    let mut hardened = false;

    // 2) Harden profile (also available via `enable --harden`)
    if args.harden {
        hardened = true;
        let mut cfg = BlackboxConfig::load_from_path(&config_path)?
            .unwrap_or_else(crate::maybe_run::default_enable_config);
        cfg.enabled = true;
        apply_harden_profile(&mut cfg);
        cfg.write_to_path(&config_path)?;
        key_path_note = Some(
            ensure_harden_key(&discovery.paths.root)?
                .display()
                .to_string(),
        );
    }

    // 3) Sample run
    let mut sample_run_id: Option<String> = None;
    if !args.no_sample {
        let store = open_store(cli)?;
        let store: std::sync::Arc<dyn crate::storage::TraceStore> = std::sync::Arc::new(store);
        let supervisor = crate::run::RunSupervisor::new(store);
        let run_args = RunArgs {
            name: Some("setup-sample".into()),
            project: Some(discovery.project_root.display().to_string()),
            tag: vec!["setup".into()],
            insecure_raw: false,
            no_redact: false,
            no_auto_resume: true,
            auto_resume: false,
            ci: false,
            eval: false,
            observe_only: true,
            artifact_dir: None,
            resume_injection: None,
            claim_id_note: None,
            ambient: false,
            command: vec!["true".into()],
        ..Default::default()
    };
        match supervisor.execute(&run_args).await {
            Ok(run) => sample_run_id = Some(run.id),
            Err(e) => tracing::warn!(error = %e, "setup sample run failed"),
        }
    }

    // 4) Doctor snapshot (reuse open paths)
    let ready = doctor_ready_snapshot(cli).await;

    #[derive(serde::Serialize)]
    struct SetupView {
        project_root: String,
        config_path: String,
        memory_bus: bool,
        install_shell: bool,
        hardened: bool,
        key_path: Option<String>,
        sample_run_id: Option<String>,
        daily_driver_ready: Option<bool>,
        daily_driver_score: Option<u8>,
        next: Vec<String>,
    }

    let mut next = vec![
        "blackbox doctor".into(),
        "blackbox run -- echo hello".into(),
        "blackbox fail".into(),
    ];
    if args.install_shell {
        next.insert(0, "restart shell or source your rc file".into());
    }
    if hardened {
        next.push("export BLACKBOX_STORE_KEY_FILE=… if key is external".into());
        next.push("blackbox backup -o vault.bbx.json --passphrase …".into());
    }

    let view = SetupView {
        project_root: discovery.project_root.display().to_string(),
        config_path: config_path.display().to_string(),
        memory_bus: args.memory_bus,
        install_shell: args.install_shell,
        hardened,
        key_path: key_path_note.clone(),
        sample_run_id: sample_run_id.clone(),
        daily_driver_ready: ready.as_ref().map(|r| r.ready),
        daily_driver_score: ready.as_ref().map(|r| r.score),
        next: next.clone(),
    };

    if cli.json {
        let result = output::emit_ok("setup", &view);
        if args.require_ready && ready.as_ref().map(|r| !r.ready).unwrap_or(true) {
            std::process::exit(1);
        }
        return result;
    }

    println!("blackbox setup complete");
    println!("  project:  {}", view.project_root);
    println!("  config:   {}", view.config_path);
    println!(
        "  memory_bus={}  shell={}  harden={}",
        args.memory_bus, args.install_shell, hardened
    );
    if let Some(ref k) = key_path_note {
        println!("  store key: {k}");
        println!("  tip: export BLACKBOX_STORE_KEY_FILE={k}");
    }
    if let Some(ref id) = sample_run_id {
        println!("  sample run: {}", short_id(id));
    }
    if let Some(ref r) = ready {
        println!(
            "  daily-driver: {} (score {}%)",
            if r.ready { "ready" } else { "not ready" },
            r.score
        );
        for n in r.notes.iter().take(6) {
            println!("    · {n}");
        }
    }
    println!("  next:");
    for c in &next {
        println!("    {c}");
    }

    if args.require_ready && ready.as_ref().map(|r| !r.ready).unwrap_or(true) {
        anyhow::bail!("setup require-ready: daily-driver not ready (see notes above)");
    }
    Ok(())
}

struct DoctorReadySnap {
    ready: bool,
    score: u8,
    notes: Vec<String>,
}

/// Lightweight ready snapshot for setup (avoids full doctor JSON reimplementation).
async fn doctor_ready_snapshot(cli: &Cli) -> Option<DoctorReadySnap> {
    let discovery = discover(cli).ok()?;
    let mut score: u8 = 100;
    let mut notes = Vec::new();
    if discovery.config.as_ref().map(|c| c.enabled) != Some(true) {
        score = score.saturating_sub(40);
        notes.push("project not enabled".into());
    }
    let on_path = std::process::Command::new("sh")
        .arg("-c")
        .arg("command -v blackbox >/dev/null 2>&1")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !on_path {
        score = score.saturating_sub(5);
        notes.push("blackbox not on PATH".into());
    }
    if let Ok(store) = open_store(cli) {
        if let Ok(runs) = store.list_runs().await {
            let running = runs
                .iter()
                .filter(|r| r.status == crate::core::run::RunStatus::Running)
                .count();
            if running > 0 {
                score = score.saturating_sub(10);
                notes.push("orphan Running run(s)".into());
            }
            if runs.is_empty() {
                notes.push("no runs yet — sample or blackbox run".into());
            }
        }
    } else {
        score = score.saturating_sub(20);
        notes.push("store not openable".into());
    }
    if discovery
        .config
        .as_ref()
        .map(|c| c.capture.encrypt_blobs)
        .unwrap_or(false)
    {
        notes.push("encrypt_blobs=on".into());
    }
    let ready = score >= 80;
    if ready {
        notes.push("daily-driver ready (soft)".into());
    }
    Some(DoctorReadySnap {
        ready,
        score,
        notes,
    })
}

fn dirs_config_blackbox_key() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        std::path::PathBuf::from(home)
            .join(".config")
            .join("blackbox")
            .join("default.key"),
    )
}

/// Apply 1.3 hardened trust defaults onto config (encrypt + project logs + retention).
fn apply_harden_profile(cfg: &mut crate::config::BlackboxConfig) {
    use crate::config::NativeLogScope;
    cfg.capture.encrypt_blobs = true;
    cfg.capture.native_log_scope = NativeLogScope::Project;
    cfg.capture.env_capture = crate::config::EnvCaptureMode::Allowlist;
    if cfg.retention.keep_runs == 0 {
        cfg.retention.keep_runs = 50;
    }
    cfg.retention.auto_apply = true;
}

/// Create external (preferred) or project store encryption key; write HARDEN.txt tip.
fn ensure_harden_key(store_root: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    let ext = dirs_config_blackbox_key();
    let key_path = if let Some(ref p) = ext {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
            crate::privacy::restrict_dir(parent);
        }
        p.clone()
    } else {
        crate::crypto::default_key_path(store_root)
    };
    let _ = crate::crypto::BlobCrypto::load_or_create(&key_path)?;
    let tip = store_root.join("HARDEN.txt");
    let _ = std::fs::write(
        &tip,
        format!(
            "blackbox harden\nencrypt_blobs=true\nkey={}\nexport BLACKBOX_STORE_KEY_FILE={}\nbackup: blackbox backup -o vault.bbx.json --passphrase …\n",
            key_path.display(),
            key_path.display()
        ),
    );
    Ok(key_path)
}

async fn cmd_enable(cli: &Cli, args: &EnableArgs, quiet: bool) -> anyhow::Result<()> {
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

    let is_new = !config_path.exists();
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
    // Continuity / observe-only: flags opt-in; new projects default to neutral recorder.
    if let Some(ref mode) = args.continuity {
        let m = crate::config::ContinuityMode::parse(mode)
            .ok_or_else(|| anyhow::anyhow!("unknown --continuity {mode:?}"))?;
        cfg.capture.continuity = Some(m);
        cfg.capture.auto_resume = m != crate::config::ContinuityMode::Off;
        // Explicit continuity implies not hard observe-only (unless mode is off).
        cfg.capture.observe_only = m == crate::config::ContinuityMode::Off;
    } else if args.memory_bus {
        cfg.capture.continuity = Some(crate::config::ContinuityMode::Always);
        cfg.capture.auto_resume = true;
        cfg.capture.observe_only = false;
    } else if args.observe_only {
        // Observe-only: no continuity, no auto-resume, no adapter mutations
        cfg.capture.observe_only = true;
        cfg.capture.continuity = Some(crate::config::ContinuityMode::Off);
        cfg.capture.auto_resume = false;
    } else if is_new {
        // New project daily-driver default: neutral ambient recorder.
        // Opt into memory bus with --continuity always / --memory-bus.
        cfg.capture.observe_only = true;
        cfg.capture.continuity = Some(crate::config::ContinuityMode::Off);
        cfg.capture.auto_resume = false;
    }
    // Re-enable without flags: preserve existing/derived continuity (do not flip)
    // Always serialize both keys when writing
    if cfg.capture.continuity.is_none() {
        cfg.capture.continuity = Some(cfg.capture.continuity_from_config());
    }
    if args.harden {
        apply_harden_profile(&mut cfg);
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

    if args.harden {
        let _ = ensure_harden_key(&paths.root)?;
    }

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

    if quiet {
        return Ok(());
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
    if cfg.capture.observe_only {
        println!("  mode:   observe-only (no continuity, no prompt mutation)");
    }
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

async fn cmd_backup(cli: &Cli, args: &BackupArgs) -> anyhow::Result<()> {
    use crate::backup::{create_sealed_backup, BackupOptions};

    let discovery = discover(cli)?;
    discovery.paths.ensure_dirs()?;
    // Flush WAL so the on-disk DB is as consistent as possible.
    if discovery.paths.db_path.exists() {
        if let Ok(store) = open_store(cli) {
            let _ = store.wal_checkpoint();
        }
    }
    let opts = BackupOptions {
        include_db: args.include_db,
        include_blobs: args.include_blobs,
        max_blob_bytes: args.max_blob_bytes,
    };
    let key_path = crate::crypto::resolve_key_path(&discovery.paths.root);
    let store_crypto = if args.store_key {
        Some(crate::crypto::BlobCrypto::load_or_create(&key_path)?)
    } else {
        crate::crypto::BlobCrypto::load_existing(&key_path)?.filter(|_| args.passphrase.is_none())
    };
    if args.passphrase.is_none() && !args.store_key && store_crypto.is_none() {
        anyhow::bail!(
            "backup requires --passphrase (recommended) or --store-key with encrypt_blobs/store.key"
        );
    }
    let sealed = create_sealed_backup(
        &discovery.paths.root,
        &discovery.paths.db_path,
        &discovery.paths.blob_dir,
        &opts,
        args.passphrase.as_deref(),
        store_crypto.as_ref(),
    )?;
    if args.output == "-" {
        print!("{sealed}");
    } else {
        std::fs::write(&args.output, &sealed)
            .map_err(|e| anyhow::anyhow!("write {}: {e}", args.output))?;
        crate::privacy::restrict_file(std::path::Path::new(&args.output));
        println!(
            "sealed backup written: {} ({} bytes)",
            args.output,
            sealed.len()
        );
        println!("  restore: blackbox restore {} --passphrase …", args.output);
    }
    Ok(())
}

async fn cmd_restore(cli: &Cli, args: &RestoreArgs) -> anyhow::Result<()> {
    use crate::backup::restore_sealed_backup;

    let discovery = discover(cli)?;
    let sealed = if args.path == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(&args.path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", args.path))?
    };
    let key_path = crate::crypto::resolve_key_path(&discovery.paths.root);
    let store_crypto = crate::crypto::BlobCrypto::load_existing(&key_path)?;
    let report = restore_sealed_backup(
        &sealed,
        &discovery.paths.root,
        &discovery.paths.db_path,
        &discovery.paths.blob_dir,
        args.passphrase.as_deref(),
        store_crypto.as_ref(),
    )?;
    println!(
        "restored {} file(s), {} bytes → {}",
        report.files_written,
        report.bytes_written,
        discovery.paths.root.display()
    );
    for n in report.notes.iter().take(6) {
        println!("  note: {n}");
    }
    Ok(())
}

async fn cmd_mcp(cli: &Cli) -> anyhow::Result<()> {
    // MCP is stdio JSON-RPC; never emit human chatter on stdout.
    crate::mcp::run_mcp_stdio(cli.store.as_deref()).await
}

async fn cmd_memory(cli: &Cli, args: &MemoryArgs) -> anyhow::Result<()> {
    use crate::memory::{build_project_memory, format_memory_markdown, MemoryBuildOptions};
    use crate::redaction::scanner::SecretScanner;
    use crate::redaction::RedactionConfig;
    use crate::state::{with_state_lock, ProjectState};

    let action = args.action.clone().unwrap_or_default();
    match action {
        MemoryAction::Show(show) => {
            let discovery = discover(cli)?;
            let store = if discovery.paths.db_path.exists() {
                Some(open_store(cli)?)
            } else {
                None
            };
            let sticky = ProjectState::load(&discovery.paths.root)?.unwrap_or_default();
            let max_tokens = if show.max_tokens != 4000 {
                show.max_tokens
            } else {
                args.max_tokens
            };
            let pack = build_project_memory(
                store.as_ref().map(|s| s as &dyn TraceStore),
                &sticky,
                MemoryBuildOptions {
                    max_tokens,
                    purpose: "project-memory".into(),
                    continuity_mode: discovery
                        .config
                        .as_ref()
                        .map(|c| c.capture.continuity_from_config().as_str().into())
                        .unwrap_or_else(|| "off".into()),
                    project_root: discovery.project_root.clone(),
                    store_db: discovery.paths.db_path.clone(),
                    skip_porcelain_if_none: sticky.attention_level.is_none(),
                },
            )
            .await?;
            if cli.json {
                return output::emit_ok("memory", &pack);
            }
            print!("{}", format_memory_markdown(&pack));
            Ok(())
        }
        MemoryAction::Set(set) => {
            let discovery = discover(cli)?;
            let scanner = SecretScanner::new(RedactionConfig::default());
            with_state_lock(&discovery.paths.root, |state| {
                if set.clear_goal {
                    state.intent.goal = None;
                } else if let Some(ref g) = set.goal {
                    state.intent.goal = if g.is_empty() {
                        None
                    } else {
                        Some(scanner.redact(g))
                    };
                }
                if set.clear_open {
                    state.intent.open_items.clear();
                } else if !set.open.is_empty() {
                    state.intent.open_items =
                        set.open.iter().map(|s| scanner.redact(s)).take(8).collect();
                }
                if let Some(ref p) = set.plan {
                    state.intent.plan_summary = if p.is_empty() {
                        None
                    } else {
                        Some(scanner.redact(p))
                    };
                }
                // Recompute WIP attention when open items change
                if !state.intent.open_items.is_empty() && state.unresolved_failure_id.is_none() {
                    state.attention_level = crate::state::AttentionLevel::Continue;
                    state.attention_reason = Some("wip".into());
                    state.attention_needed = true;
                } else if state.intent.open_items.is_empty()
                    && state.unresolved_failure_id.is_none()
                    && state.active_claim.is_none()
                {
                    // Don't clear dirty-based wip here (live git); leave level if failure/claim
                }
                state.updated_at = chrono::Utc::now();
                Ok(())
            })?;
            if cli.json {
                let sticky = ProjectState::load(&discovery.paths.root)?.unwrap_or_default();
                return output::emit_ok("memory_set", &sticky);
            }
            println!("memory updated");
            Ok(())
        }
    }
}

async fn cmd_resolve(cli: &Cli, args: &ResolveArgs) -> anyhow::Result<()> {
    use crate::core::run::{Run, RunStatus};
    use crate::state::{apply_run_outcome, with_state_lock, OutcomeExtras};

    let discovery = discover(cli)?;
    let result = with_state_lock(&discovery.paths.root, |state| {
        let fid = args
            .run_id
            .clone()
            .or_else(|| state.unresolved_failure_id.clone())
            .or_else(|| state.last_failure.as_ref().map(|r| r.id.clone()));
        // Synthetic success run carrying resolve
        let mut run = Run::new(
            vec!["blackbox".into(), "resolve".into()],
            discovery.project_root.display().to_string(),
        );
        run.status = RunStatus::Succeeded;
        run.exit_code = Some(0);
        run.ended_at = Some(chrono::Utc::now());
        if let Some(ref id) = fid {
            run.parent_run_id = Some(id.clone());
            run.tags.push(format!("resolves:{id}"));
        }
        apply_run_outcome(
            state,
            &run,
            OutcomeExtras {
                resolve_failure: true,
                clear_wip: args.clear_wip,
                ..Default::default()
            },
        );
        if args.clear_goal {
            state.intent.goal = None;
        }
        Ok(state.unresolved_failure_id.clone())
    })?;

    if cli.json {
        #[derive(serde::Serialize)]
        struct R {
            resolved: bool,
            unresolved_failure_id: Option<String>,
        }
        return output::emit_ok(
            "resolve",
            &R {
                resolved: result.is_none(),
                unresolved_failure_id: result,
            },
        );
    }
    if result.is_none() {
        println!("resolved: no unresolved failure");
    } else {
        println!("resolve applied (remaining unresolved: {result:?})");
    }
    Ok(())
}

async fn cmd_claim(cli: &Cli, args: &ClaimArgs) -> anyhow::Result<()> {
    use crate::state::{claim_heartbeat, claim_holder_id, claim_release, ProjectState};

    let discovery = discover(cli)?;
    let ttl_default = discovery
        .config
        .as_ref()
        .map(|c| c.capture.claim_ttl_secs)
        .unwrap_or(1800);

    match &args.action {
        ClaimAction::Acquire(a) => {
            use crate::state::claim_acquire_scoped;
            let (default_holder, kind) = claim_holder_id(None, None, false);
            let holder = a.holder.clone().unwrap_or(default_holder);
            let ttl = a.ttl_secs.unwrap_or(ttl_default);
            match claim_acquire_scoped(
                &discovery.paths.root,
                &holder,
                &kind,
                None,
                a.goal.clone(),
                ttl,
                a.path.clone(),
            )? {
                Ok(c) => {
                    if cli.json {
                        return output::emit_ok("claim_acquire", &c);
                    }
                    println!(
                        "claim acquired id={} holder={} scope={} until {}",
                        c.id,
                        c.holder,
                        c.path_scope.as_deref().unwrap_or("(project)"),
                        c.expires_at.to_rfc3339()
                    );
                }
                Err(conflict) => {
                    if cli.json {
                        #[derive(serde::Serialize)]
                        struct E {
                            ok: bool,
                            conflict: String,
                        }
                        return output::emit_ok(
                            "claim_acquire",
                            &E {
                                ok: false,
                                conflict,
                            },
                        );
                    }
                    anyhow::bail!("{conflict}");
                }
            }
            Ok(())
        }
        ClaimAction::Release(a) => {
            let released = claim_release(&discovery.paths.root, a.holder.as_deref())?;
            if cli.json {
                return output::emit_ok("claim_release", &released);
            }
            match released {
                Some(c) => println!("released claim {}", c.id),
                None => println!("no active claim"),
            }
            Ok(())
        }
        ClaimAction::Status => {
            let mut sticky = ProjectState::load(&discovery.paths.root)?.unwrap_or_default();
            sticky.expire_claim_if_needed(chrono::Utc::now());
            if cli.json {
                #[derive(serde::Serialize)]
                struct ClaimStatusView {
                    project_claim: Option<crate::state::ClaimPointer>,
                    path_claims: Vec<crate::state::ClaimPointer>,
                }
                return output::emit_ok(
                    "claim_status",
                    &ClaimStatusView {
                        project_claim: sticky.active_claim.clone(),
                        path_claims: sticky.path_claims.clone(),
                    },
                );
            }
            if sticky.active_claim.is_none() && sticky.path_claims.is_empty() {
                println!("no active claims");
            }
            if let Some(c) = &sticky.active_claim {
                println!(
                    "project claim holder={} kind={} until {} run={:?}",
                    c.holder, c.holder_kind, c.expires_at, c.run_id
                );
            }
            for c in &sticky.path_claims {
                println!(
                    "path claim scope={} holder={} kind={} until {}",
                    c.path_scope.as_deref().unwrap_or("?"),
                    c.holder,
                    c.holder_kind,
                    c.expires_at
                );
            }
            Ok(())
        }
        ClaimAction::Heartbeat(a) => {
            let (default_holder, _) = claim_holder_id(None, None, false);
            let holder = a.holder.clone().unwrap_or(default_holder);
            let ttl = a.ttl_secs.unwrap_or(ttl_default);
            let ok = claim_heartbeat(&discovery.paths.root, &holder, ttl)?;
            if cli.json {
                #[derive(serde::Serialize)]
                struct H {
                    ok: bool,
                }
                return output::emit_ok("claim_heartbeat", &H { ok });
            }
            println!(
                "{}",
                if ok {
                    "heartbeat ok"
                } else {
                    "no claim for holder"
                }
            );
            Ok(())
        }
    }
}

async fn cmd_ack(cli: &Cli) -> anyhow::Result<()> {
    let discovery = discover(cli)?;
    let path = crate::state::write_ack(&discovery.paths.root)?;
    if cli.json {
        #[derive(serde::Serialize)]
        struct A {
            path: String,
        }
        return output::emit_ok(
            "ack",
            &A {
                path: path.display().to_string(),
            },
        );
    }
    println!("ack written: {}", path.display());
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
            include_project_memory: args.resume,
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
            // 1.2: project_memory by default when enabled
            include_project_memory: true,
        },
    )
    .await?;

    if cli.json {
        return output::emit_ok("handoff", &view);
    }
    print!("{}", format_status_text(&view));
    if view.project_memory.is_none() && view.resume_pack.is_none() && !view.attention.needed {
        println!("  (no memory/resume pack — nothing needs attention; pass --always to force)");
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
    println!("  headline: {}", pack.headline);
    println!("  attention: {}", pack.attention_reason);
    println!("  next: {}", pack.next_action);
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
    if !pack.errors_top.is_empty() {
        println!("  errors_top:");
        for e in pack.errors_top.iter().take(8) {
            println!("    seq={} [{}] {}", e.sequence, e.error_type, e.message);
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
    let failed = matches!(
        run.status,
        crate::core::run::RunStatus::Failed | crate::core::run::RunStatus::Cancelled
    ) || run.exit_code.is_some_and(|c| c != 0);

    if cli.json {
        let result = output::emit_ok("postmortem", &view);
        if args.fail_on_failure && failed {
            std::process::exit(1);
        }
        return result;
    }
    print!("{}", format_summary_text(&view));
    if args.fail_on_failure && failed {
        std::process::exit(1);
    }
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
    let mut blob_bytes = None;
    let mut blob_files = None;

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
        let (bf, bb) = dir_file_stats(store.blob_dir());
        blob_files = Some(bf);
        blob_bytes = Some(bb);
    }

    // Best-effort blob stats even if store open failed but dir exists
    if blob_bytes.is_none() && paths.blob_dir.exists() {
        let (bf, bb) = dir_file_stats(&paths.blob_dir);
        blob_files = Some(bf);
        blob_bytes = Some(bb);
    }
    if store_size_bytes.is_none() && paths.db_path.exists() {
        store_size_bytes = std::fs::metadata(&paths.db_path).ok().map(|m| m.len());
    }

    let total_storage_bytes = match (store_size_bytes, blob_bytes) {
        (Some(d), Some(b)) => Some(d.saturating_add(b)),
        (Some(d), None) => Some(d),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    let storage_warning = storage_soft_warning(total_storage_bytes, blob_bytes.unwrap_or(0));

    let config_view = match &discovery.config {
        Some(c) => views::DoctorConfigView {
            present: true,
            enabled: Some(c.enabled),
            wrap: Some(c.capture.wrap.clone()),
            retention: Some(views::DoctorRetentionView {
                keep_runs: c.retention.keep_runs,
                max_age_days: c.retention.max_age_days,
                auto_apply: c.retention.auto_apply,
            }),
        },
        None => views::DoctorConfigView {
            present: false,
            enabled: None,
            wrap: None,
            retention: None,
        },
    };

    let sticky = crate::state::ProjectState::load(&discovery.paths.root)
        .ok()
        .flatten();
    let continuity_mode = discovery
        .config
        .as_ref()
        .map(|c| c.capture.continuity_from_config().as_str().to_string());
    let observe_only = discovery.config.as_ref().map(|c| c.capture.observe_only);
    let memory_path = paths.root.join("MEMORY.json");
    let memory_file_present = Some(memory_path.exists());
    let memory_age_secs = memory_path
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .map(|d| d.as_secs());
    let claims_active = Some(
        sticky
            .as_ref()
            .and_then(|s| s.active_claim.as_ref())
            .is_some(),
    );
    let unresolved_failure_id = sticky
        .as_ref()
        .and_then(|s| s.unresolved_failure_id.clone());
    let attention_level = sticky
        .as_ref()
        .map(|s| s.attention_level.as_str().to_string());

    // Daily-driver readiness (soft score for ambient trust).
    let mut dd_notes: Vec<String> = Vec::new();
    let mut dd_score: u8 = 100;
    let mut last_capture_quality: Option<u8> = None;
    let redact_ok = secrets_clean.unwrap_or(true);
    let enabled_ok = discovery
        .config
        .as_ref()
        .map(|c| c.enabled)
        .unwrap_or(false);
    let observe = observe_only.unwrap_or(false);
    if !enabled_ok {
        dd_score = dd_score.saturating_sub(40);
        dd_notes.push("project not enabled — run blackbox enable".into());
    }
    if !observe {
        dd_score = dd_score.saturating_sub(15);
        dd_notes.push(
            "continuity/memory may mutate launches — prefer enable --observe-only for ambient trust"
                .into(),
        );
    } else {
        dd_notes.push(
            "observe-only: ambient recording will not mutate launches or inject BLACKBOX_* into children"
                .into(),
        );
    }
    if crate::nest::neutrality_supported() {
        dd_notes.push(
            "recorder neutrality: supported (supervisor PID nest guard; no child-visible BLACKBOX_ACTIVE_RUN)"
                .into(),
        );
    } else {
        dd_score = dd_score.saturating_sub(10);
        dd_notes.push("recorder neutrality: not supported on this host".into());
    }
    if !redact_ok {
        dd_score = dd_score.saturating_sub(35);
        dd_notes.push("recent run argv still matches secret patterns — run blackbox scrub".into());
    }
    if storage_warning.is_some() {
        dd_score = dd_score.saturating_sub(10);
        dd_notes.push("store size soft warning active — consider blackbox gc".into());
    }
    // Store filesystem privacy (other local users)
    #[cfg(unix)]
    {
        if crate::privacy::is_world_or_group_readable(&paths.root) {
            dd_score = dd_score.saturating_sub(20);
            dd_notes.push(
                "store directory is group/other-readable — chmod 700 .blackbox (privacy)".into(),
            );
        }
        if paths.db_path.exists() && crate::privacy::is_world_or_group_readable(&paths.db_path) {
            dd_score = dd_score.saturating_sub(20);
            dd_notes.push(
                "database file is group/other-readable — chmod 600 blackbox.db (privacy)".into(),
            );
        }
        // Best-effort harden on doctor for existing installs
        crate::privacy::restrict_dir(&paths.root);
        crate::privacy::restrict_dir(&paths.blob_dir);
        if paths.db_path.exists() {
            crate::privacy::restrict_file(&paths.db_path);
        }
    }
    // Progressive retention tips
    let keep = discovery
        .config
        .as_ref()
        .map(|c| c.retention.keep_runs)
        .unwrap_or(50);
    for tip in crate::retention::progressive_gc_advice(
        run_count.unwrap_or(0),
        total_storage_bytes.unwrap_or(0),
        keep,
    ) {
        dd_score = dd_score.saturating_sub(5);
        dd_notes.push(tip);
    }
    if let Some(true) = claims_active {
        dd_notes.push("active project claim held — see blackbox claim status".into());
    }
    if let Some(ref mode) = discovery.config.as_ref().map(|c| c.capture.product_mode()) {
        dd_notes.push(format!("product_mode={}", mode.as_str()));
    }
    if let Some(cfg) = discovery.config.as_ref() {
        dd_notes.push(format!(
            "native_log_scope={}",
            cfg.capture.native_log_scope.as_str()
        ));
        if cfg.capture.encrypt_blobs {
            let kp = crate::crypto::resolve_key_path(&paths.root);
            let ext = crate::crypto::key_is_external(&paths.root);
            dd_notes.push(format!(
                "blob encryption: on (key={}{})",
                kp.display(),
                if ext { "; external to project" } else { "" }
            ));
            if !ext {
                dd_notes.push(
                    "tip: set BLACKBOX_STORE_KEY_FILE=~/.config/blackbox/default.key so project theft without key is useless"
                        .into(),
                );
            }
        } else {
            dd_notes.push(
                "blob encryption: off — set capture.encrypt_blobs=true for at-rest protection"
                    .into(),
            );
        }
        dd_notes.push("offline vault: blackbox backup -o vault.bbx.json --passphrase …".into());
        dd_notes.push(
            "live SQLCipher is not used; at-rest path is encrypt_blobs + sealed backup (DB offline vault)"
                .into(),
        );
        dd_notes.push("eval harness: blackbox run --eval --artifact-dir ./out -- <agent>".into());
    }
    if running_count.unwrap_or(0) > 0 {
        dd_score = dd_score.saturating_sub(10);
        dd_notes.push("orphan Running run(s) present — may need recovery".into());
    }
    if !on_path {
        dd_score = dd_score.saturating_sub(5);
        dd_notes.push("blackbox not on PATH".into());
    }
    // Sample last run coverage if store open
    if let Ok(store) = open_store(cli) {
        if let Ok(runs) = store.list_runs().await {
            if let Some(run) = runs.first() {
                if let Ok(events) = store.get_events(&run.id).await {
                    if let Some(cov) = events
                        .iter()
                        .find(|e| e.kind == "capture.coverage")
                        .and_then(|e| e.metadata.get("coverage"))
                    {
                        if let Some(q) = cov.get("quality_score").and_then(|v| v.as_u64()) {
                            last_capture_quality = Some(q as u8);
                            if q < 40 {
                                dd_score = dd_score.saturating_sub(15);
                                dd_notes.push(format!(
                                    "last run capture quality low ({q}%) — check capture surfaces"
                                ));
                            }
                        }
                        if cov
                            .get("notes")
                            .and_then(|n| n.as_array())
                            .map(|a| a.iter().any(|x| x.as_str().unwrap_or("").contains("lag")))
                            .unwrap_or(false)
                        {
                            dd_score = dd_score.saturating_sub(10);
                            dd_notes.push("last run reported capture lag".into());
                        }
                    }
                    if events.iter().any(|e| e.kind == "capture.warning") {
                        dd_score = dd_score.saturating_sub(10);
                        dd_notes.push("last run has capture.warning events".into());
                    }
                    if events.iter().any(|e| {
                        e.kind == "capture.warning"
                            && e.metadata.get("warning").and_then(|v| v.as_str())
                                == Some("adapter_drought")
                    }) {
                        dd_score = dd_score.saturating_sub(10);
                        dd_notes.push(
                            "last run adapter drought (0 tool.call for known harness) — check stream-json / native logs"
                                .into(),
                        );
                    }
                }
            }
        }
    }
    let daily_driver_ready = dd_score >= 80 && redact_ok && enabled_ok;

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
            blob_bytes,
            blob_files,
            total_storage_bytes,
            storage_warning: storage_warning.clone(),
            run_count,
            running_count,
            fts5,
            secrets_clean,
            config: config_view,
            shell_integration_hint:
                "functions call maybe-run; install via blackbox enable --install-shell".into(),
            blackbox_on_path: on_path,
            continuity_mode,
            observe_only,
            memory_file_present,
            memory_age_secs,
            claims_active,
            unresolved_failure_id,
            attention_level,
            daily_driver_score: Some(dd_score),
            daily_driver_ready: Some(daily_driver_ready),
            daily_driver_notes: dd_notes.clone(),
            last_capture_quality,
            recorder_neutrality_supported: Some(crate::nest::neutrality_supported()),
            nest_guard: Some("supervisor_pid_marker".into()),
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
    if let Some(total) = total_storage_bytes {
        println!(
            "storage:    {} total (db {} · blobs {} / {} files)",
            format_bytes(total),
            format_bytes(store_size_bytes.unwrap_or(0)),
            format_bytes(blob_bytes.unwrap_or(0)),
            blob_files.unwrap_or(0)
        );
    }
    if let Some(ref w) = storage_warning {
        println!("warning:    {w}");
    }
    println!(
        "config:     {}",
        if config_view.present { "yes" } else { "no" }
    );
    if let Some(ref ret) = config_view.retention {
        println!(
            "retention:  keep_runs={} max_age_days={:?} auto_apply={}",
            ret.keep_runs, ret.max_age_days, ret.auto_apply
        );
    }
    if let Some(true) = observe_only {
        println!("mode:       observe-only (no continuity, no prompt mutation)");
    } else if let Some(ref mode) = continuity_mode {
        println!("mode:       continuity={mode}");
    }
    println!(
        "daily-driver: {} (score {}%)",
        if daily_driver_ready {
            "ready"
        } else {
            "not ready"
        },
        dd_score
    );
    if let Some(q) = last_capture_quality {
        println!("last capture quality: {q}%");
    }
    for n in dd_notes.iter().take(6) {
        println!("  note: {n}");
    }
    println!(
        "neutrality: recorder contract {} (nest=supervisor_pid_marker)",
        if crate::nest::neutrality_supported() {
            "supported"
        } else {
            "unsupported on this host"
        }
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

/// Soft thresholds for A4 cost visibility (not hard deletes).
const STORAGE_WARN_TOTAL: u64 = 1_073_741_824; // 1 GiB
const STORAGE_WARN_BLOBS: u64 = 536_870_912; // 512 MiB

fn dir_file_stats(dir: &std::path::Path) -> (usize, u64) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return (0, 0),
    };
    let mut files = 0usize;
    let mut bytes = 0u64;
    for e in rd.filter_map(|e| e.ok()) {
        if let Ok(m) = e.metadata() {
            if m.is_file() {
                files += 1;
                bytes = bytes.saturating_add(m.len());
            }
        }
    }
    (files, bytes)
}

fn storage_soft_warning(total: Option<u64>, blob_bytes: u64) -> Option<String> {
    if total.is_some_and(|t| t >= STORAGE_WARN_TOTAL) || blob_bytes >= STORAGE_WARN_BLOBS {
        Some(
            "store is large — run `blackbox gc` / `blackbox stats` (retention auto_apply may already be on)"
                .into(),
        )
    } else {
        None
    }
}

fn format_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

async fn cmd_serve(cli: &Cli, args: &ServeArgs) -> anyhow::Result<()> {
    let store = open_store(cli)?;
    let addr: std::net::SocketAddr = if args.unix_socket.is_some() {
        // Placeholder; unix path is used instead of TCP.
        "127.0.0.1:0".parse().unwrap()
    } else {
        args.bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --bind address: {e}"))?
    };
    crate::serve::serve(
        Arc::new(store),
        crate::serve::ServeOptions {
            addr,
            token: args.token.clone(),
            reindex: args.reindex,
            unix_socket: args.unix_socket.clone(),
            secure_cookies: args.secure_cookies,
            allow_anonymous: args.allow_anonymous,
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
            "mcp",
            "backup",
            "restore",
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
