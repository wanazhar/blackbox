//! CLI handlers for Blackbox 1.6 commands (fsck, verify, experiment, report, gate, capsule, …).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Subcommand};

use crate::adapter_protocol::{
    run_live_conformance, validate_adapter_event, validate_adapter_manifest, AdapterManifest,
};
use crate::budget::{evaluate_budgets, BudgetPolicy, ObservedBudgets};
use crate::capsule::{create_capsule, CapsuleCreateOpts};
use crate::capsule::inspect_capsule;
use crate::cassette::CassetteFile;
use crate::cassette::{match_request, MatchMode};
use crate::experiment::{evaluate_gate, GateConfig};
use crate::experiment::{ExperimentManifest, ExperimentRole, RunExperimentMeta};
use crate::experiment::{build_experiment_report, RunReportInput};
use crate::ingest::EventSpool;
use crate::ingest::{recover_spool_on_open, RecoveryStats};
use crate::integrity::{fsck_store, FsckMode, FsckOptions};
use crate::output::{self, OutputMode};
use crate::projects::{default_index_path, discover_project_stores, ProjectIndexQuery, ProjectRegistry};
use crate::storage::sqlite::SqliteStore;
use crate::storage::TraceStore;
use crate::verification::verify_command;
use crate::verification::{parse_junit_xml, receipt_from_junit};
use crate::verification::build_outcome_view;
use crate::verification::{
    VerificationConfidence, VerificationReceipt, VerificationStatus, VerifierType,
};
use crate::verification::{parse_tap, receipt_from_tap};

// ── Arg structs ───────────────────────────────────────────────────

#[derive(Args)]
/// `FsckArgs` value.
pub struct FsckArgs {
    /// Deep mode: load and re-hash every referenced blob
    #[arg(long)]
    pub deep: bool,
    /// Generate repair plan, write recovery artifact, apply auto-safe repairs
    #[arg(long)]
    pub repair: bool,
}

#[derive(Args)]
/// `VerifyArgs` value.
pub struct VerifyArgs {
    /// Run ID, prefix, or "latest"
    pub run_id: String,
    /// Parse JUnit XML result file
    #[arg(long)]
    pub junit: Option<PathBuf>,
    /// Parse TAP result file
    #[arg(long)]
    pub tap: Option<PathBuf>,
    /// Assert a relative file exists
    #[arg(long)]
    pub assert_file: Option<PathBuf>,
    /// Assert git working tree is clean
    #[arg(long)]
    pub assert_git_clean: bool,
    /// Explicit verification scope label
    #[arg(long)]
    pub scope: Option<String>,
    /// Parent receipt id for re-verification lineage
    #[arg(long)]
    pub parent: Option<String>,
    /// Command argv after `--`
    #[arg(last = true)]
    pub command: Vec<String>,
}

#[derive(Args)]
/// `ExperimentArgs` value.
pub struct ExperimentArgs {
    #[command(subcommand)]
    /// Action.
    pub action: ExperimentAction,
}

#[derive(Subcommand)]
/// `ExperimentAction` classification.
pub enum ExperimentAction {
    /// Create a new experiment
    Init {
        /// Display name.
        name: String,
        #[arg(long)]
        /// Unique identifier.
        id: Option<String>,
    },
    /// Show experiment manifest.
    Show {
        /// Experiment id.
        id: String,
    },
    /// List experiments.
    List,
    /// Validate experiment has runs / required fields.
    Validate {
        /// Experiment id.
        id: String,
    },
    /// Attach experiment metadata to a run
    Link {
        /// Experiment.
        experiment: String,
        /// Owning run id.
        run_id: String,
        #[arg(long)]
        /// Task.
        task: Option<String>,
        #[arg(long)]
        /// Variant.
        variant: Option<String>,
        #[arg(long)]
        /// Attempt.
        attempt: Option<u32>,
        #[arg(long)]
        /// Role.
        role: Option<String>,
        #[arg(long)]
        /// Model.
        model: Option<String>,
    },
}

#[derive(Args)]
/// `ReportArgs` value.
pub struct ReportArgs {
    #[arg(long)]
    /// Experiment.
    pub experiment: String,
    #[arg(long, default_value = "variant")]
    /// Group by.
    pub group_by: String,
    #[arg(long, default_value_t = 3)]
    /// Min samples.
    pub min_samples: usize,
}

#[derive(Args)]
/// `GateArgs` value.
pub struct GateArgs {
    #[arg(long)]
    /// Experiment.
    pub experiment: String,
    #[arg(long)]
    /// Baseline.
    pub baseline: Option<String>,
    #[arg(long)]
    /// Candidate.
    pub candidate: Option<String>,
    #[arg(long)]
    /// Min verified rate.
    pub min_verified_rate: Option<f64>,
    #[arg(long)]
    /// Max p95 duration regression.
    pub max_p95_duration_regression: Option<String>,
    #[arg(long)]
    /// Require capture complete.
    pub require_capture_complete: bool,
    #[arg(long, default_value_t = 3)]
    /// Min attempts.
    pub min_attempts: usize,
    #[arg(long, default_value = "variant")]
    /// Group by.
    pub group_by: String,
}

#[derive(Args, Clone)]
/// `CapsuleArgs` value.
pub struct CapsuleArgs {
    #[command(subcommand)]
    /// Action.
    pub action: CapsuleAction,
}

#[derive(Subcommand, Clone)]
/// `CapsuleAction` classification.
pub enum CapsuleAction {
    /// `Create` variant.
    Create {
        /// Owning run id.
        run_id: String,
        #[arg(short = 'o', long, default_value = "capsule.bbx.json")]
        /// Output.
        output: PathBuf,
    },
    /// `Inspect` variant.
    Inspect {
        /// Filesystem path.
        path: PathBuf,
    },
    /// `Verify` variant.
    Verify {
        /// Filesystem path.
        path: PathBuf,
    },
    /// Import capsule portable archive into the store (optional re-execute contained).
    Execute {
        /// Filesystem path.
        path: PathBuf,
        /// Prefer contained/sandbox backends when re-running the recorded command.
        #[arg(long, default_value_t = true)]
        contained: bool,
        /// Also re-run the recorded command after import (experimental).
        #[arg(long, default_value_t = false)]
        rerun: bool,
    },
}

#[derive(Args)]
/// `CassetteArgs` value.
pub struct CassetteArgs {
    #[command(subcommand)]
    /// Action.
    pub action: CassetteAction,
}

#[derive(Subcommand)]
/// `CassetteAction` classification.
pub enum CassetteAction {
    /// Inspect a cassette file (experimental).
    Inspect {
        /// Cassette file path.
        path: PathBuf,
    },
    /// Match a sample JSON-RPC request against a cassette (experimental)
    Match {
        /// Filesystem path.
        path: PathBuf,
        /// Path to JSON request
        request: PathBuf,
        #[arg(long, default_value = "normalized")]
        /// Mode.
        mode: String,
        #[arg(long, default_value = "tools/call")]
        /// Tool.
        tool: String,
    },
    /// Stdio MCP proxy: record tool calls into a cassette (experimental)
    ///
    /// Usage: `blackbox cassette proxy --record out.bbx.json -- <server> ...`
    Proxy {
        /// Record mode (write cassette)
        #[arg(long, conflicts_with = "replay")]
        record: Option<PathBuf>,
        /// Replay mode (read cassette)
        #[arg(long, conflicts_with = "record")]
        replay: Option<PathBuf>,
        /// Matching mode for replay: strict | normalized | ordered | allow_extra
        #[arg(long, default_value = "normalized")]
        mode: String,
        /// Unmatched request policy: fail | deny | live
        #[arg(long, default_value = "fail")]
        on_unknown: String,
        /// Redact string secrets while recording
        #[arg(long, default_value_t = true)]
        redact: bool,
        /// MCP server command after `--` (required for record and for live passthrough)
        #[arg(last = true)]
        server: Vec<String>,
    },
}

#[derive(Args)]
/// `BudgetArgs` value.
pub struct BudgetArgs {
    /// Max wall-clock seconds
    #[arg(long)]
    pub max_wall: Option<u64>,
    #[arg(long)]
    /// Max processes.
    pub max_processes: Option<u64>,
    #[arg(long)]
    /// Max output.
    pub max_output: Option<u64>,
    #[arg(long)]
    /// Max store growth.
    pub max_store_growth: Option<u64>,
    #[arg(long)]
    /// Max tool calls.
    pub max_tool_calls: Option<u64>,
    #[arg(long)]
    /// Max tokens.
    pub max_tokens: Option<u64>,
    #[arg(long)]
    /// Max memory.
    pub max_memory: Option<u64>,
    #[arg(long)]
    /// Max cpu percent.
    pub max_cpu_percent: Option<u32>,
    #[arg(long)]
    /// Contained.
    pub contained: bool,
    /// Optional observed values for evaluation demo
    #[arg(long)]
    pub observed_wall: Option<u64>,
    #[arg(long)]
    /// Observed processes.
    pub observed_processes: Option<u64>,
}

#[derive(Args)]
/// `AdapterArgs` value.
pub struct AdapterArgs {
    #[command(subcommand)]
    /// Action.
    pub action: AdapterAction,
}

#[derive(Subcommand)]
/// `AdapterAction` classification.
pub enum AdapterAction {
    /// Validate an adapter manifest file.
    Validate {
        /// Path to the adapter manifest (TOML or JSON).
        manifest: PathBuf,
    },
    /// Run fixture and optional live conformance tests.
    Test {
        /// Path to the adapter manifest.
        manifest: PathBuf,
        /// NDJSON fixture file of adapter events
        #[arg(long)]
        fixtures: Option<PathBuf>,
    },
}

#[derive(Args)]
/// `ProjectsArgs` value.
pub struct ProjectsArgs {
    #[command(subcommand)]
    /// Action.
    pub action: ProjectsAction,
}

#[derive(Args, Clone)]
/// Boundary contract commands (1.7).
pub struct BoundaryArgs {
    #[command(subcommand)]
    /// Action.
    pub action: BoundaryAction,
}

#[derive(Subcommand, Clone)]
/// Boundary subcommands.
pub enum BoundaryAction {
    /// Validate a boundary contract JSON file
    Validate {
        /// Path to `blackbox.boundary/v1` JSON
        file: PathBuf,
    },
    /// Show the resolved boundary attached to a run
    Show {
        /// Run ID, prefix, or "latest"
        run_id: String,
    },
    /// Attach (or replace) a resolved boundary on a run
    Set {
        /// Run ID, prefix, or "latest"
        run_id: String,
        /// Path to boundary contract JSON
        #[arg(long, short = 'f')]
        file: PathBuf,
        /// Optional parent boundary JSON (experiment-level); repeatable, root first
        #[arg(long = "parent")]
        parents: Vec<PathBuf>,
        /// Force fail-closed after resolution
        #[arg(long)]
        fail_closed: bool,
    },
    /// Evaluate required evidence / containment gate for a run
    Evaluate {
        /// Run ID, prefix, or "latest"
        run_id: String,
        /// Capture classes present (repeatable), e.g. process, network
        #[arg(long = "present")]
        present: Vec<String>,
        /// Capture classes unavailable on this platform
        #[arg(long = "unavailable")]
        unavailable: Vec<String>,
        /// Mark artifact provenance as present
        #[arg(long)]
        artifact_provenance: bool,
        /// Exit non-zero when fail-closed gate fails
        #[arg(long)]
        gate: bool,
    },
    /// Record an immutable containment receipt for a run
    Receipt {
        /// Run ID, prefix, or "latest"
        run_id: String,
        /// Claim state: configured|enforced|verified|observed_only|failed|unknown|unavailable
        #[arg(long, default_value = "configured")]
        claim: String,
        /// Result: held|violated|denied|unreachable|inconclusive|not_observed|not_applicable
        #[arg(long, default_value = "not_observed")]
        result: String,
        /// Verifier identity
        #[arg(long, default_value = "blackbox")]
        verifier: String,
        /// Method (launch_record, preflight_canary, post_run_canary, …)
        #[arg(long, default_value = "launch_record")]
        method: String,
        /// Control name (e.g. network_egress)
        #[arg(long)]
        control: Option<String>,
        /// Backend (e.g. bwrap, none)
        #[arg(long)]
        backend: Option<String>,
        /// Summary text
        #[arg(long)]
        summary: Option<String>,
    },
}

#[derive(Subcommand)]
/// `ProjectsAction` classification.
pub enum ProjectsAction {
    /// Scan roots and update the metadata-only global index
    Scan {
        #[arg(default_value = ".")]
        /// Roots.
        roots: Vec<PathBuf>,
    },
    /// Query the global project index
    List {
        #[arg(long)]
        /// Query.
        query: Option<String>,
        #[arg(long, default_value_t = 50)]
        /// Configured limit, if any.
        limit: usize,
    },
    /// Remove index entries whose store path no longer exists
    Prune,
    /// Remove a specific project root from the index (metadata only)
    Remove {
        /// Project root.
        project_root: PathBuf,
    },
}

// ── Handlers ──────────────────────────────────────────────────────

/// Cmd fsck.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `cmd_fsck` — see module docs for full workflow.
/// ```
pub async fn cmd_fsck(
    store: Arc<dyn TraceStore>,
    blob_dir: PathBuf,
    spool_dir: PathBuf,
    recovery_dir: PathBuf,
    args: &FsckArgs,
    json: bool,
) -> anyhow::Result<()> {
    let opts = FsckOptions {
        mode: if args.deep {
            FsckMode::Deep
        } else {
            FsckMode::Fast
        },
        repair: args.repair,
        blob_dir: Some(blob_dir),
        spool_dir: Some(spool_dir.clone()),
        recovery_dir: if args.repair {
            Some(recovery_dir)
        } else {
            None
        },
    };
    // Optional spool replay before repair.
    if args.repair && spool_dir.exists() {
        let stats: RecoveryStats = recover_spool_on_open(store.clone(), &spool_dir).await?;
        if stats.batches_seen > 0 {
            tracing::info!(
                replayed = stats.batches_replayed,
                inserted = stats.events_inserted,
                "fsck spool recovery"
            );
        }
    }
    let report = fsck_store(store, opts).await?;
    if json {
        return output::emit_ok("fsck", &report);
    }
    print!("{}", report.format_text());
    if !report.ok {
        std::process::exit(1);
    }
    Ok(())
}

/// Cmd verify.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `cmd_verify` — see module docs for full workflow.
/// ```
pub async fn cmd_verify(
    store: Arc<dyn TraceStore>,
    run_id: &str,
    cwd: &std::path::Path,
    args: &VerifyArgs,
    json: bool,
) -> anyhow::Result<()> {
    let mut receipt = if let Some(ref junit_path) = args.junit {
        let xml = std::fs::read_to_string(junit_path)?;
        let summary = parse_junit_xml(&xml)?;
        receipt_from_junit(run_id, &summary, &junit_path.display().to_string())
    } else if let Some(ref tap_path) = args.tap {
        let text = std::fs::read_to_string(tap_path)?;
        let summary = parse_tap(&text);
        receipt_from_tap(run_id, &summary, &tap_path.display().to_string())
    } else if let Some(ref file) = args.assert_file {
        let mut r = VerificationReceipt::new(run_id, VerifierType::FileAssertion);
        let path = cwd.join(file);
        if path.is_file() {
            r.status = VerificationStatus::Passed;
            r.summary = Some(format!("file exists: {}", file.display()));
        } else {
            r.status = VerificationStatus::Failed;
            r.summary = Some(format!("file missing: {}", file.display()));
        }
        r.confidence = VerificationConfidence::Confirmed;
        r.verified_scope = args.scope.clone();
        r
    } else if args.assert_git_clean {
        let mut r = VerificationReceipt::new(run_id, VerifierType::GitState);
        let out = std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(cwd)
            .output()?;
        let dirty = !out.stdout.is_empty();
        r.status = if dirty {
            VerificationStatus::Failed
        } else {
            VerificationStatus::Passed
        };
        r.summary = Some(if dirty {
            "git working tree dirty".into()
        } else {
            "git working tree clean".into()
        });
        r.confidence = VerificationConfidence::Confirmed;
        r
    } else if !args.command.is_empty() {
        verify_command(
            store.as_ref(),
            run_id,
            &args.command,
            cwd,
            args.parent.clone(),
            args.scope.clone(),
        )
        .await?
    } else {
        anyhow::bail!(
            "specify a verifier: -- command ..., --junit, --tap, --assert-file, or --assert-git-clean"
        );
    };

    if let Some(ref p) = args.parent {
        receipt.parent_receipt_id = Some(p.clone());
    }
    // Domain match: correlate receipt to latest failure event when present.
    {
        let errors = store.get_error_events(run_id, 8).await.unwrap_or_default();
        let failure = errors.last();
        let domain = crate::verification::match_receipt_to_failure(
            &receipt,
            failure,
            &[],
        );
        receipt.confidence = crate::verification::confidence_from_domain(domain.class);
        if receipt.failure_fingerprint.is_none() {
            if let Some(ev) = failure {
                receipt.failure_fingerprint =
                    Some(crate::verification::domain::failure_fingerprint(ev));
            }
        }
        if receipt.verified_scope.is_none() {
            receipt.verified_scope = args.scope.clone();
        }
        receipt.limitations.push(format!(
            "domain_match={:?} score={}",
            domain.class, domain.score
        ));
    }

    store.insert_verification_receipt(&receipt).await?;

    let run = store
        .get_run(run_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("run not found"))?;
    let receipts = store.list_verification_receipts(run_id).await?;
    let outcome = build_outcome_view(&run, &receipts, None);

    if json {
        return output::emit_ok(
            "verify",
            &serde_json::json!({
                "receipt": receipt,
                "outcome": outcome,
            }),
        );
    }
    println!(
        "verification {} status={:?} confidence={:?}",
        crate::util::short_id(&receipt.id),
        receipt.status,
        receipt.confidence
    );
    if let Some(ref s) = receipt.summary {
        println!("  {s}");
    }
    println!(
        "outcome: execution={:?} verification={:?} capture={:?}",
        outcome.execution.status, outcome.verification.status, outcome.capture.status
    );
    Ok(())
}

/// Cmd experiment.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `cmd_experiment` — see module docs for full workflow.
/// ```
pub async fn cmd_experiment(
    store: Arc<dyn TraceStore>,
    args: &ExperimentArgs,
    json: bool,
) -> anyhow::Result<()> {
    match &args.action {
        ExperimentAction::Init { name, id } => {
            let id = id
                .clone()
                .unwrap_or_else(|| name.to_lowercase().replace(' ', "-"));
            let m = ExperimentManifest::new(&id, name);
            store.upsert_experiment(&m).await?;
            if json {
                return output::emit_ok("experiment_init", &m);
            }
            println!("experiment {} created", m.id);
        }
        ExperimentAction::Show { id } => {
            let m = store
                .get_experiment(id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("experiment not found: {id}"))?;
            if json {
                return output::emit_ok("experiment_show", &m);
            }
            println!("{} — {}", m.id, m.name);
            println!("tasks: {:?}", m.tasks);
            println!("variants: {:?}", m.variants);
        }
        ExperimentAction::List => {
            let list = store.list_experiments().await?;
            if json {
                return output::emit_ok("experiment_list", &list);
            }
            for m in list {
                println!("{}  {}", m.id, m.name);
            }
        }
        ExperimentAction::Validate { id } => {
            let m = store
                .get_experiment(id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("experiment not found: {id}"))?;
            let runs = store.list_runs_for_experiment(id).await?;
            let ok = !runs.is_empty();
            let view = serde_json::json!({
                "experiment": m,
                "run_count": runs.len(),
                "ok": ok,
                "missing": if ok { Vec::<String>::new() } else { vec!["no linked runs".to_string()] },
            });
            if json {
                return output::emit_ok("experiment_validate", &view);
            }
            println!(
                "experiment {} — {} run(s) — {}",
                id,
                runs.len(),
                if ok { "ok" } else { "incomplete" }
            );
        }
        ExperimentAction::Link {
            experiment,
            run_id,
            task,
            variant,
            attempt,
            role,
            model,
        } => {
            let _ = store
                .get_experiment(experiment)
                .await?
                .ok_or_else(|| anyhow::anyhow!("experiment not found: {experiment}"))?;
            let role = match role.as_deref() {
                Some("baseline") => ExperimentRole::Baseline,
                Some("candidate") => ExperimentRole::Candidate,
                Some("control") => ExperimentRole::Control,
                Some("treatment") => ExperimentRole::Treatment,
                _ => ExperimentRole::Unknown,
            };
            let mut meta = RunExperimentMeta {
                experiment_id: Some(experiment.clone()),
                task_id: task.clone(),
                variant: variant.clone(),
                attempt: *attempt,
                role,
                model: model.clone(),
                ..Default::default()
            };
            if meta.attempt.is_none() {
                let run_ids = store.list_runs_for_experiment(experiment).await?;
                let mut existing = Vec::new();
                for rid in run_ids {
                    if &rid == run_id {
                        continue;
                    }
                    if let Ok(Some(m)) = store.get_run_experiment_meta(&rid).await {
                        existing.push(m);
                    }
                }
                meta.attempt =
                    Some(crate::experiment::next_attempt_number(&existing, &meta));
            }
            meta = meta.with_fingerprint();
            store.put_run_experiment_meta(run_id, &meta).await?;
            if json {
                return output::emit_ok("experiment_link", &meta);
            }
            println!("linked run {} → experiment {}", run_id, experiment);
        }
    }
    Ok(())
}

/// Cmd report.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `cmd_report` — see module docs for full workflow.
/// ```
pub async fn cmd_report(
    store: Arc<dyn TraceStore>,
    args: &ReportArgs,
    json: bool,
) -> anyhow::Result<()> {
    let run_ids = store.list_runs_for_experiment(&args.experiment).await?;
    let mut rows = Vec::new();
    for rid in run_ids {
        let Some(run) = store.get_run(&rid).await? else {
            continue;
        };
        let meta = store
            .get_run_experiment_meta(&rid)
            .await?
            .unwrap_or_default();
        let receipts = store.list_verification_receipts(&rid).await?;
        let duration_ms = run.duration_ms.or_else(|| {
            run.ended_at
                .map(|e| (e - run.started_at).num_milliseconds().max(0) as u64)
        });
        rows.push(RunReportInput {
            run,
            meta,
            receipts,
            capture_complete: true, // conservative default without coverage event
            duration_ms,
        });
    }
    let report = build_experiment_report(
        &args.experiment,
        &args.group_by,
        &rows,
        args.min_samples,
    );
    if json {
        return output::emit_ok("report", &report);
    }
    println!(
        "experiment {} group_by={} verdict={:?} n={}",
        report.experiment_id, report.group_by, report.verdict, report.sample_size_total
    );
    for v in &report.variants {
        println!(
            "  {}: runs={} verified={}/{} p95_ms={:?}",
            v.key, v.run_count, v.verified_success, v.run_count, v.duration_p95_ms
        );
    }
    for lim in &report.limitations {
        println!("  note: {lim}");
    }
    Ok(())
}

/// Cmd gate.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `cmd_gate` — see module docs for full workflow.
/// ```
pub async fn cmd_gate(
    store: Arc<dyn TraceStore>,
    args: &GateArgs,
    json: bool,
) -> anyhow::Result<()> {
    let report_args = ReportArgs {
        experiment: args.experiment.clone(),
        group_by: args.group_by.clone(),
        min_samples: args.min_attempts,
    };
    // Build report then gate.
    let run_ids = store.list_runs_for_experiment(&args.experiment).await?;
    let mut rows = Vec::new();
    for rid in run_ids {
        let Some(run) = store.get_run(&rid).await? else {
            continue;
        };
        let meta = store
            .get_run_experiment_meta(&rid)
            .await?
            .unwrap_or_default();
        let receipts = store.list_verification_receipts(&rid).await?;
        let duration_ms = run.duration_ms.or_else(|| {
            run.ended_at
                .map(|e| (e - run.started_at).num_milliseconds().max(0) as u64)
        });
        rows.push(RunReportInput {
            run,
            meta,
            receipts,
            capture_complete: true,
            duration_ms,
        });
    }
    let report = build_experiment_report(
        &args.experiment,
        &args.group_by,
        &rows,
        args.min_attempts,
    );
    let mut config = GateConfig {
        min_attempts: Some(args.min_attempts),
        min_verified_rate: args.min_verified_rate,
        require_capture_complete: args.require_capture_complete,
        fail_on_insufficient_evidence: true,
        baseline_key: args.baseline.clone(),
        candidate_key: args.candidate.clone(),
        ..Default::default()
    };
    if let Some(ref s) = args.max_p95_duration_regression {
        let s = s.trim().trim_end_matches('%');
        let v: f64 = s.parse().unwrap_or(0.0);
        config.max_p95_duration_regression = Some(if v > 1.0 { v / 100.0 } else { v });
    }
    let result = evaluate_gate(&report, &config);
    if json {
        let _ = report_args;
        output::emit_ok("gate", &result)?;
    } else {
        println!(
            "gate {} — {:?}",
            if result.passed { "PASS" } else { "FAIL" },
            result.verdict
        );
        for f in &result.failures {
            println!("  FAIL {}: {}", f.rule, f.message);
        }
    }
    if !result.passed {
        std::process::exit(result.exit_code);
    }
    Ok(())
}

/// Cmd capsule.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `cmd_capsule` — see module docs for full workflow.
/// ```
pub async fn cmd_capsule(
    store: Arc<dyn TraceStore>,
    args: &CapsuleArgs,
    json: bool,
) -> anyhow::Result<()> {
    match &args.action {
        CapsuleAction::Create { run_id, output } => {
            let run = store
                .get_run(run_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("run not found"))?;
            // allow prefix resolution done by caller
            let receipts = store.list_verification_receipts(&run.id).await?;
            let json_doc = create_capsule(
                store.as_ref(),
                &run,
                &receipts,
                None,
                CapsuleCreateOpts {
                    include_receipts: true,
                    ..Default::default()
                },
            )
            .await?;
            std::fs::write(output, &json_doc)?;
            let report = inspect_capsule(&json_doc)?;
            if json {
                return output::emit_ok(
                    "capsule_create",
                    &serde_json::json!({
                        "path": output,
                        "manifest": report.manifest,
                    }),
                );
            }
            println!(
                "capsule written to {} (completeness={:?})",
                output.display(),
                report.completeness
            );
        }
        CapsuleAction::Inspect { path } => {
            let s = std::fs::read_to_string(path)?;
            let report = inspect_capsule(&s)?;
            if json {
                return output::emit_ok("capsule_inspect", &report);
            }
            println!(
                "capsule source_run={} completeness={:?} integrity_ok={}",
                report.manifest.source_run_id, report.completeness, report.integrity_ok
            );
            for i in &report.issues {
                println!("  issue: {i}");
            }
            println!(
                "model_replay_deterministic={}",
                report.model_replay_deterministic
            );
        }
        CapsuleAction::Verify { path } => {
            let s = std::fs::read_to_string(path)?;
            let report = inspect_capsule(&s)?;
            if json {
                return output::emit_ok("capsule_verify", &report);
            }
            if report.integrity_ok {
                println!("capsule OK");
            } else {
                println!("capsule FAILED integrity");
                for i in &report.issues {
                    println!("  {i}");
                }
                std::process::exit(1);
            }
        }
        CapsuleAction::Execute {
            path,
            contained,
            rerun,
        } => {
            let s = std::fs::read_to_string(path)?;
            let report = inspect_capsule(&s)?;
            if !report.integrity_ok {
                anyhow::bail!("capsule integrity failed; refuse execute");
            }
            let root: serde_json::Value = serde_json::from_str(&s)?;
            let portable = root
                .get("portable")
                .ok_or_else(|| anyhow::anyhow!("capsule missing portable section"))?;
            let portable_json = serde_json::to_string(portable)?;
            let imported =
                crate::export::portable::import_portable(store.as_ref(), &portable_json, true)
                    .await?;
            // Re-attach receipts from capsule when present.
            if let Some(arr) = root.get("receipts").and_then(|v| v.as_array()) {
                for r in arr {
                    if let Ok(mut receipt) =
                        serde_json::from_value::<crate::verification::VerificationReceipt>(
                            r.clone(),
                        )
                    {
                        receipt.run_id = imported.run_id.clone();
                        receipt.id = format!("verify-{}", uuid::Uuid::new_v4());
                        let _ = store.insert_verification_receipt(&receipt).await;
                    }
                }
            }
            let mut view = serde_json::json!({
                "imported_run_id": imported.run_id,
                "events": imported.events,
                "blobs": imported.blobs,
                "contained": *contained,
                "rerun": *rerun,
                "completeness": report.completeness,
                "model_replay_deterministic": false,
                "note": "capsule execute imports portable archive; model output is not deterministic replay",
            });
            if *rerun {
                let cmd = report.manifest.command.clone();
                if cmd.is_empty() {
                    anyhow::bail!("capsule has empty command; cannot rerun");
                }
                let budget = BudgetPolicy {
                    contained: *contained,
                    ..Default::default()
                };
                let args = crate::cli::RunArgs {
                    command: cmd,
                    contained: *contained,
                    ..Default::default()
                };
                let supervisor =
                    crate::run::RunSupervisor::new(Arc::clone(&store)).with_budget(budget);
                let new_run = supervisor.execute(&args).await?;
                view["rerun_run_id"] = serde_json::json!(new_run.id);
                view["rerun_status"] = serde_json::json!(format!("{:?}", new_run.status));
            }
            if json {
                return output::emit_ok("capsule_execute", &view);
            }
            println!(
                "capsule imported run {} (events={} blobs={}) contained={} rerun={}",
                crate::util::short_id(&imported.run_id),
                imported.events,
                imported.blobs,
                contained,
                rerun
            );
            println!("model_replay_deterministic=false");
        }
    }
    Ok(())
}

/// Cmd cassette.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `cmd_cassette` — see module docs for full workflow.
/// ```
pub async fn cmd_cassette(args: &CassetteArgs, json: bool) -> anyhow::Result<()> {
    match &args.action {
        CassetteAction::Inspect { path } => {
            let s = std::fs::read_to_string(path)?;
            let cass = CassetteFile::from_json(&s)?;
            if json {
                return output::emit_ok("cassette_inspect", &cass);
            }
            println!(
                "cassette protocol={} entries={} experimental={}",
                cass.protocol,
                cass.entries.len(),
                cass.experimental
            );
            for lim in &cass.limitations {
                println!("  limit: {lim}");
            }
        }
        CassetteAction::Match {
            path,
            request,
            mode,
            tool,
        } => {
            let cass = CassetteFile::from_json(&std::fs::read_to_string(path)?)?;
            let req: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(request)?)?;
            let mode = match mode.as_str() {
                "strict" => MatchMode::Strict,
                "ordered" => MatchMode::Ordered,
                "allow_extra" => MatchMode::AllowExtra,
                _ => MatchMode::Normalized,
            };
            let (result, _) = match_request(mode, &cass.entries, 0, &req, tool);
            if json {
                return output::emit_ok("cassette_match", &result);
            }
            println!("matched={} mode={:?}", result.matched, result.mode);
            if let Some(d) = &result.diff {
                println!("diff: {d}");
            }
        }
        CassetteAction::Proxy {
            record,
            replay,
            mode,
            on_unknown,
            redact,
            server,
        } => {
            use crate::cassette::{
                run_mcp_proxy, ProxyConfig, ProxyMode, UnknownPolicy,
            };
            let match_mode = match mode.as_str() {
                "strict" => MatchMode::Strict,
                "ordered" => MatchMode::Ordered,
                "allow_extra" => MatchMode::AllowExtra,
                _ => MatchMode::Normalized,
            };
            let (proxy_mode, path) = match (record, replay) {
                (Some(p), None) => (ProxyMode::Record, p.clone()),
                (None, Some(p)) => (ProxyMode::Replay, p.clone()),
                _ => anyhow::bail!("specify exactly one of --record PATH or --replay PATH"),
            };
            let cfg = ProxyConfig {
                mode: proxy_mode,
                cassette_path: path,
                match_mode,
                on_unknown: UnknownPolicy::parse(on_unknown)?,
                server_argv: server.clone(),
                redact: *redact,
            };
            // Proxy is blocking stdio; run on blocking pool.
            let report = tokio::task::spawn_blocking(move || run_mcp_proxy(cfg))
                .await
                .map_err(|e| anyhow::anyhow!("proxy task: {e}"))??;
            if json {
                return output::emit_ok("cassette_proxy", &report);
            }
            eprintln!(
                "cassette proxy mode={} entries={} matched={} unmatched={} live={} path={}",
                report.mode,
                report.entries,
                report.matched,
                report.unmatched,
                report.live_passthrough,
                report.cassette_path
            );
            eprintln!("experimental: MCP cassette only — unproxied harness tools unsupported");
        }
    }
    Ok(())
}

/// Cmd budget.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `cmd_budget` — see module docs for full workflow.
/// ```
pub async fn cmd_budget(args: &BudgetArgs, json: bool) -> anyhow::Result<()> {
    let policy = BudgetPolicy {
        max_wall_secs: args.max_wall,
        max_processes: args.max_processes,
        max_output_bytes: args.max_output,
        max_store_growth_bytes: args.max_store_growth,
        max_tool_calls: args.max_tool_calls,
        max_tokens: args.max_tokens,
        max_memory_bytes: args.max_memory,
        max_cpu_percent: args.max_cpu_percent,
        contained: args.contained,
    };
    let observed = ObservedBudgets {
        wall_secs: args.observed_wall,
        processes: args.observed_processes,
        ..Default::default()
    };
    let report = evaluate_budgets(&policy, &observed);
    if json {
        return output::emit_ok("budget", &report);
    }
    println!("budget capabilities:");
    for c in &report.capabilities {
        println!(
            "  {} {:?} limit={:?} observed={:?}",
            c.name, c.capability, c.limit, c.observed
        );
    }
    if let Some(ref reason) = report.breach_reason {
        println!("breach: {reason}");
    }
    Ok(())
}

/// Cmd adapter.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `cmd_adapter` — see module docs for full workflow.
/// ```
pub async fn cmd_adapter(args: &AdapterArgs, json: bool) -> anyhow::Result<()> {
    match &args.action {
        AdapterAction::Validate { manifest } => {
            let text = std::fs::read_to_string(manifest)?;
            let m = if manifest.extension().and_then(|e| e.to_str()) == Some("json") {
                AdapterManifest::from_json(&text)?
            } else {
                AdapterManifest::from_toml(&text)?
            };
            let report = validate_adapter_manifest(&m);
            if json {
                return output::emit_ok("adapter_validate", &report);
            }
            println!(
                "adapter {} — {}",
                m.name,
                if report.ok { "ok" } else { "INVALID" }
            );
            for e in &report.errors {
                println!("  error: {e}");
            }
            if !report.ok {
                std::process::exit(1);
            }
        }
        AdapterAction::Test { manifest, fixtures } => {
            let text = std::fs::read_to_string(manifest)?;
            let m = if manifest.extension().and_then(|e| e.to_str()) == Some("json") {
                AdapterManifest::from_json(&text)?
            } else {
                AdapterManifest::from_toml(&text)?
            };
            let mut report = validate_adapter_manifest(&m);
            if let Some(fix) = fixtures {
                let body = std::fs::read_to_string(fix)?;
                for (i, line) in body.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let ev = validate_adapter_event(line);
                    if !ev.ok {
                        report.ok = false;
                        for e in ev.errors {
                            report.errors.push(format!("line {}: {e}", i + 1));
                        }
                    }
                }
            }
            // Live process conformance: run adapter command and validate NDJSON stdout.
            if report.ok && !m.command.is_empty() {
                let live = run_live_conformance(&m, Duration::from_secs(5));
                report.warnings.extend(live.warnings);
                if !live.ok {
                    report.ok = false;
                    report.errors.extend(live.errors);
                } else if live.events_validated > 0 {
                    report.warnings.push(format!(
                        "live process emitted {} valid event(s)",
                        live.events_validated
                    ));
                }
            }
            if json {
                return output::emit_ok("adapter_test", &report);
            }
            println!(
                "adapter test {} — {}",
                m.name,
                if report.ok { "ok" } else { "FAILED" }
            );
            for e in &report.errors {
                println!("  {e}");
            }
            for w in &report.warnings {
                println!("  warn: {w}");
            }
            if !report.ok {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

/// Cmd projects.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `cmd_projects` — see module docs for full workflow.
/// ```
pub async fn cmd_projects(args: &ProjectsArgs, json: bool) -> anyhow::Result<()> {
    let index_path = default_index_path();
    match &args.action {
        ProjectsAction::Scan { roots } => {
            let found = discover_project_stores(roots);
            let mut reg = ProjectRegistry::load(&index_path).unwrap_or_else(|_| ProjectRegistry::empty());
            for e in found {
                reg.upsert(e);
            }
            reg.save(&index_path)?;
            if json {
                return output::emit_ok("projects_scan", &reg);
            }
            println!(
                "indexed {} project store(s) → {}",
                reg.entries.len(),
                index_path.display()
            );
            println!("note: index is metadata-only; stores remain authoritative");
        }
        ProjectsAction::List { query, limit } => {
            let reg = ProjectRegistry::load(&index_path).unwrap_or_else(|_| ProjectRegistry::empty());
            let q = ProjectIndexQuery {
                name_substr: query.clone(),
                limit: Some(*limit),
            };
            let hits: Vec<_> = reg.query(&q).into_iter().cloned().collect();
            if json {
                return output::emit_ok("projects_list", &hits);
            }
            for e in hits {
                println!(
                    "{}  store={}",
                    e.project_root.display(),
                    e.store_path.display()
                );
            }
        }
        ProjectsAction::Prune => {
            let mut reg =
                ProjectRegistry::load(&index_path).unwrap_or_else(|_| ProjectRegistry::empty());
            let before = reg.entries.len();
            let removed = reg.prune_missing();
            reg.save(&index_path)?;
            if json {
                return output::emit_ok(
                    "projects_prune",
                    &serde_json::json!({
                        "removed": removed,
                        "remaining": reg.entries.len(),
                        "before": before,
                    }),
                );
            }
            println!(
                "pruned {removed} missing store(s); {} remain in {}",
                reg.entries.len(),
                index_path.display()
            );
        }
        ProjectsAction::Remove { project_root } => {
            let mut reg =
                ProjectRegistry::load(&index_path).unwrap_or_else(|_| ProjectRegistry::empty());
            let root = project_root.canonicalize().unwrap_or_else(|_| project_root.clone());
            let removed = reg.remove_root(&root) || reg.remove_root(project_root);
            reg.save(&index_path)?;
            if json {
                return output::emit_ok(
                    "projects_remove",
                    &serde_json::json!({ "removed": removed, "project_root": project_root }),
                );
            }
            if removed {
                println!("removed {} from index", project_root.display());
            } else {
                println!("no index entry for {}", project_root.display());
            }
        }
    }
    Ok(())
}

/// Open store as Arc for shared handlers.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `store_arc` — see module docs for full workflow.
/// ```
pub fn store_arc(store: SqliteStore) -> Arc<dyn TraceStore> {
    Arc::new(store)
}

/// Spool directory next to blobs: `<blackbox_root>/spool`.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `spool_dir_from_blob_dir` — see module docs for full workflow.
/// ```
pub fn spool_dir_from_blob_dir(blob_dir: &std::path::Path) -> PathBuf {
    blob_dir
        .parent()
        .unwrap_or(blob_dir)
        .join("spool")
}

/// Recovery artifacts directory.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `recovery_dir_from_blob_dir` — see module docs for full workflow.
/// ```
pub fn recovery_dir_from_blob_dir(blob_dir: &std::path::Path) -> PathBuf {
    blob_dir
        .parent()
        .unwrap_or(blob_dir)
        .join("recovery")
}

/// Ensure spool exists (best-effort).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `ensure_spool` — see module docs for full workflow.
/// ```
pub fn ensure_spool(blob_dir: &std::path::Path) -> anyhow::Result<EventSpool> {
    EventSpool::open(spool_dir_from_blob_dir(blob_dir))
}

/// Mode helper
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `is_json` — see module docs for full workflow.
/// ```
pub fn is_json(mode: OutputMode) -> bool {
    matches!(mode, OutputMode::Json)
}

/// Boundary contract CLI (1.7 Phase A).
pub async fn cmd_boundary(
    store: Arc<dyn TraceStore>,
    args: &BoundaryArgs,
    json: bool,
) -> anyhow::Result<()> {
    use crate::boundary::{
        evaluate_required_evidence, load_boundary_file, resolve_boundary, ContainmentReceipt,
        ContainmentScope, ObservedEvidence, ResolveOpts, BOUNDARY_SCHEMA,
    };

    match &args.action {
        BoundaryAction::Validate { file } => {
            let contract = load_boundary_file(file)?;
            let resolved = resolve_boundary(&contract, ResolveOpts::default())?;
            if json {
                return output::emit_ok(
                    "boundary_validate",
                    &serde_json::json!({
                        "ok": true,
                        "schema": BOUNDARY_SCHEMA,
                        "policy_hash": resolved.policy_hash,
                        "contract": contract,
                    }),
                );
            }
            println!(
                "boundary ok schema={} policy_hash={}",
                BOUNDARY_SCHEMA,
                &resolved.policy_hash[..16.min(resolved.policy_hash.len())]
            );
            if let Some(ref p) = contract.purpose {
                println!("  purpose: {p}");
            }
            println!(
                "  prohibited={} required_evidence={} fail_closed={}",
                contract.prohibited.len(),
                contract.required_evidence.len(),
                contract.fail_closed
            );
            Ok(())
        }
        BoundaryAction::Show { run_id } => {
            let boundary = store
                .get_run_boundary(run_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("no boundary contract on run {run_id}"))?;
            if json {
                return output::emit_ok("boundary_show", &boundary);
            }
            println!(
                "boundary run={} policy_hash={}",
                crate::util::short_id(&boundary.run_id),
                &boundary.policy_hash[..16.min(boundary.policy_hash.len())]
            );
            if let Some(ref p) = boundary.contract.purpose {
                println!("  purpose: {p}");
            }
            println!(
                "  fail_closed={} required_evidence={:?}",
                boundary.contract.fail_closed, boundary.contract.required_evidence
            );
            println!("  prohibited={:?}", boundary.contract.prohibited);
            if !boundary.inheritance_chain.is_empty() {
                println!("  inheritance_chain={:?}", boundary.inheritance_chain);
            }
            Ok(())
        }
        BoundaryAction::Set {
            run_id,
            file,
            parents,
            fail_closed,
        } => {
            // Ensure run exists.
            store
                .get_run(run_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("run not found: {run_id}"))?;
            let leaf = load_boundary_file(file)?;
            let mut parent_contracts = Vec::new();
            for p in parents {
                parent_contracts.push(load_boundary_file(p)?);
            }
            let resolved = resolve_boundary(
                &leaf,
                ResolveOpts {
                    parents: parent_contracts,
                    force_fail_closed: if *fail_closed { Some(true) } else { None },
                    ..Default::default()
                },
            )?
            .with_run_id(run_id.clone());
            store.put_run_boundary(&resolved).await?;
            if json {
                return output::emit_ok("boundary_set", &resolved);
            }
            println!(
                "boundary set on {} policy_hash={}",
                crate::util::short_id(run_id),
                &resolved.policy_hash[..16.min(resolved.policy_hash.len())]
            );
            Ok(())
        }
        BoundaryAction::Evaluate {
            run_id,
            present,
            unavailable,
            artifact_provenance,
            gate,
        } => {
            let boundary = store.get_run_boundary(run_id).await?;
            let containment_receipts = store.list_containment_receipts(run_id).await?;
            // Auto-detect common capture classes from events when --present omitted.
            let mut present_classes = present.clone();
            if present_classes.is_empty() {
                if let Ok(events) = store.get_events(run_id).await {
                    let mut seen = std::collections::BTreeSet::new();
                    for e in &events {
                        let class = match e.source {
                            crate::core::event::EventSource::Process => Some("process"),
                            crate::core::event::EventSource::Filesystem => Some("filesystem"),
                            crate::core::event::EventSource::Git => Some("git"),
                            crate::core::event::EventSource::Terminal => Some("pty"),
                            crate::core::event::EventSource::Network => Some("network"),
                            _ => None,
                        };
                        if let Some(c) = class {
                            seen.insert(c.to_string());
                        }
                        if e.kind.contains("network") || e.kind.contains("dns") {
                            seen.insert("network".into());
                        }
                    }
                    present_classes.extend(seen);
                }
            }
            let observed = ObservedEvidence {
                present_classes,
                unavailable_classes: unavailable.clone(),
                partial_classes: Vec::new(),
                containment_receipts,
                has_artifact_provenance: *artifact_provenance,
            };
            let report = evaluate_required_evidence(boundary.as_ref(), &observed);
            if json {
                if *gate && report.gate_failed {
                    let _ = output::emit_ok("boundary_evaluate", &report);
                    std::process::exit(2);
                }
                return output::emit_ok("boundary_evaluate", &report);
            }
            println!(
                "boundary evaluate status={} gate_failed={} fail_closed={}",
                report.status.as_str(),
                report.gate_failed,
                report.fail_closed
            );
            if let Some(ref h) = report.policy_hash {
                println!("  policy_hash={}", &h[..16.min(h.len())]);
            }
            for req in &report.requirements {
                println!(
                    "  evidence {} → {}",
                    req.class,
                    req.availability.as_str()
                );
            }
            for r in &report.reasons {
                println!("  reason: {r}");
            }
            if *gate && report.gate_failed {
                std::process::exit(2);
            }
            Ok(())
        }
        BoundaryAction::Receipt {
            run_id,
            claim,
            result,
            verifier,
            method,
            control,
            backend,
            summary,
        } => {
            store
                .get_run(run_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("run not found: {run_id}"))?;
            let claim_state = parse_claim_state(claim)?;
            let result_v = parse_containment_result(result)?;
            let mut receipt = ContainmentReceipt::new(
                run_id.clone(),
                claim_state,
                result_v,
                verifier.clone(),
                method.clone(),
            );
            receipt.scope = ContainmentScope {
                control: control.clone(),
                backend: backend.clone(),
                sandbox_id: None,
                label: None,
            };
            receipt.summary = summary.clone();
            if let Ok(Some(b)) = store.get_run_boundary(run_id).await {
                receipt.policy_hash = Some(b.policy_hash);
            }
            store.insert_containment_receipt(&receipt).await?;
            if json {
                return output::emit_ok("boundary_receipt", &receipt);
            }
            println!(
                "containment receipt {} claim={} result={}",
                crate::util::short_id(&receipt.id),
                receipt.claim_state.as_str(),
                receipt.result.as_str()
            );
            Ok(())
        }
    }
}

fn parse_claim_state(s: &str) -> anyhow::Result<crate::boundary::ContainmentClaimState> {
    use crate::boundary::ContainmentClaimState;
    Ok(match s {
        "configured" => ContainmentClaimState::Configured,
        "enforced" => ContainmentClaimState::Enforced,
        "verified" => ContainmentClaimState::Verified,
        "observed_only" => ContainmentClaimState::ObservedOnly,
        "failed" => ContainmentClaimState::Failed,
        "unknown" => ContainmentClaimState::Unknown,
        "unavailable" => ContainmentClaimState::Unavailable,
        other => anyhow::bail!("unknown claim state {other:?}"),
    })
}

fn parse_containment_result(s: &str) -> anyhow::Result<crate::boundary::ContainmentResult> {
    use crate::boundary::ContainmentResult;
    Ok(match s {
        "held" => ContainmentResult::Held,
        "violated" => ContainmentResult::Violated,
        "denied" => ContainmentResult::Denied,
        "unreachable" => ContainmentResult::Unreachable,
        "inconclusive" => ContainmentResult::Inconclusive,
        "not_observed" => ContainmentResult::NotObserved,
        "not_applicable" => ContainmentResult::NotApplicable,
        other => anyhow::bail!("unknown containment result {other:?}"),
    })
}

/// Resolve and attach a boundary file to a run (used by `run --boundary`).
pub async fn attach_boundary_to_run(
    store: &dyn TraceStore,
    run_id: &str,
    boundary_path: &std::path::Path,
    parent_paths: &[std::path::PathBuf],
    fail_closed: bool,
) -> anyhow::Result<crate::boundary::ResolvedBoundary> {
    use crate::boundary::{load_boundary_file, resolve_boundary, ResolveOpts};

    let leaf = load_boundary_file(boundary_path)?;
    let mut parents = Vec::new();
    for p in parent_paths {
        parents.push(load_boundary_file(p)?);
    }
    let resolved = resolve_boundary(
        &leaf,
        ResolveOpts {
            parents,
            force_fail_closed: if fail_closed { Some(true) } else { None },
            ..Default::default()
        },
    )?
    .with_run_id(run_id);
    store.put_run_boundary(&resolved).await?;
    Ok(resolved)
}
