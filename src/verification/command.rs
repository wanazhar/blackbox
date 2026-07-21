//! Command-exit verifier.

use std::path::Path;
use std::process::Stdio;
use std::time::Instant;

use chrono::Utc;

use crate::crypto::content_key;
use crate::storage::TraceStore;
use crate::verification::receipt::{
    VerificationConfidence, VerificationReceipt, VerificationStatus, VerifierType,
};

/// Run `argv` in `cwd` and produce an immutable receipt linked to `run_id`.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `verify_command` — see module docs for full workflow.
/// ```
pub async fn verify_command(
    store: &dyn TraceStore,
    run_id: &str,
    argv: &[String],
    cwd: &Path,
    parent_receipt_id: Option<String>,
    scope: Option<String>,
) -> anyhow::Result<VerificationReceipt> {
    if argv.is_empty() {
        anyhow::bail!("verify command requires a non-empty argv after `--`");
    }
    let started = Utc::now();
    let t0 = Instant::now();
    let output = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let ended = Utc::now();
    let duration_ms = t0.elapsed().as_millis() as u64;
    let exit_code = output.status.code().unwrap_or(-1);

    let stdout_key = if output.stdout.is_empty() {
        None
    } else {
        let r = store.store_blob(&output.stdout).await?;
        Some(r.key)
    };
    let stderr_key = if output.stderr.is_empty() {
        None
    } else {
        let r = store.store_blob(&output.stderr).await?;
        Some(r.key)
    };

    let status = if output.status.success() {
        VerificationStatus::Passed
    } else {
        VerificationStatus::Failed
    };

    let mut receipt = VerificationReceipt::new(run_id, VerifierType::CommandExit);
    receipt.command_argv = argv.to_vec();
    receipt.command_fidelity = Some("exact_argv".into());
    receipt.cwd = Some(cwd.display().to_string());
    receipt.contained = Some(false);
    receipt.started_at = Some(started);
    receipt.ended_at = Some(ended);
    receipt.duration_ms = Some(duration_ms);
    receipt.exit_code = Some(exit_code);
    receipt.stdout_blob = stdout_key;
    receipt.stderr_blob = stderr_key;
    receipt.verified_scope = scope;
    receipt.status = status;
    receipt.confidence = VerificationConfidence::Confirmed;
    receipt.parent_receipt_id = parent_receipt_id;
    receipt.limitations = vec![
        "verification performed in workspace-only mode; does not claim containment".into(),
    ];
    receipt.summary = Some(format!(
        "command {:?} exited {exit_code}",
        argv.first().map(|s| s.as_str()).unwrap_or("?")
    ));
    // Fingerprint from argv + exit
    let fp_src = format!("{}|{exit_code}", argv.join("\0"));
    receipt.failure_fingerprint = Some(content_key(fp_src.as_bytes())[..16].to_string());
    Ok(receipt)
}
