use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use tokio::sync::mpsc;

use crate::adapters::claude::ClaudeAdapter;
use crate::adapters::codex::CodexAdapter;
use crate::adapters::generic::GenericAdapter;
use crate::adapters::harness::HarnessAdapter;
use crate::adapters::native_logs::{discover_log_roots, poll_native_logs};
use crate::adapters::{LaunchContext, RunContext};
use crate::capture::filesystem::FilesystemCapture;
use crate::capture::git::GitCapture;
use crate::capture::process::ProcessCapture;
use crate::capture::pty::PtyCapture;
use crate::capture::{merge_layers, CaptureLayer};
use crate::cli::RunArgs;
use crate::config::CapturePolicy;
use crate::core::checkpoint::Checkpoint;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::run::{Run, RunStatus};
use crate::pipeline::EventWriter;
use crate::redaction::environment::EnvironmentRedactor;
use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;
use crate::storage::TraceStore;
use crate::terminal::ansi::AnsiNormalizer;
use crate::terminal::coalesce::{CoalescePolicy, TerminalCoalescer};
use crate::terminal::recorder::RawRecorder;
use crate::terminal::TerminalRecorder;
const MAX_LINE_BUF_BYTES: usize = 64 * 1024;

/// Grace period (ms) after SIGINT before escalating to SIGKILL.
const SIGGRACE_MS: u64 = 5000;

/// Supervises a child process in a PTY and captures trace events.
pub struct RunSupervisor {
    store: Arc<dyn TraceStore>,
    policy: CapturePolicy,
}

impl RunSupervisor {
    pub fn new(store: Arc<dyn TraceStore>) -> Self {
        Self {
            store,
            policy: CapturePolicy::default(),
        }
    }

    pub fn with_policy(mut self, policy: CapturePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Run a command under observation.
    pub async fn execute(&self, args: &RunArgs) -> anyhow::Result<Run> {
        let cwd = args
            .project
            .clone()
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .map(|p| p.to_string_lossy().to_string())
            })
            .unwrap_or_else(|| ".".to_string());

        let mut run = Run::new(args.command.clone(), cwd);
        run.name = args.name.clone();
        run.tags = args.tag.clone();
        run.status = RunStatus::Running;

        match self.execute_inner(args, &mut run).await {
            Ok(()) => Ok(run),
            Err(e) => {
                if run.status == RunStatus::Running {
                    run.status = RunStatus::Failed;
                    run.ended_at = Some(chrono::Utc::now());
                    run.notes = Some(match run.notes.take() {
                        Some(n) => format!("{}; error: {}", n, e),
                        None => format!("error: {}", e),
                    });
                    if let Err(update_err) = self.store.update_run(&run).await {
                        tracing::error!(
                            error = %update_err,
                            "failed to mark run as Failed after error"
                        );
                    }
                }
                Err(e)
            }
        }
    }

    async fn execute_inner(&self, args: &RunArgs, run: &mut Run) -> anyhow::Result<()> {
        let redact_cfg = RedactionConfig {
            enabled: self.policy.redact,
            ..RedactionConfig::default()
        };
        let scanner = SecretScanner::new(redact_cfg.clone());

        // Redact argv before any persistence (secrets in command lines)
        if self.policy.redact {
            run.command = scanner.redact_command(&run.command);
        }

        // ── Detect harness adapter (use original args for detection) ──
        let detect_cmd = &args.command;
        let adapter: Arc<dyn HarnessAdapter> = if ClaudeAdapter::new().detect(detect_cmd) {
            Arc::new(ClaudeAdapter::new())
        } else if CodexAdapter::new().detect(detect_cmd) {
            Arc::new(CodexAdapter::new())
        } else {
            Arc::new(GenericAdapter::new())
        };
        let adapter_id = adapter.id();
        tracing::info!(adapter = adapter_id, "detected harness adapter");

        // Launch uses the *original* unredacted command so the process still works.
        // Only the stored Run record is redacted.
        let launch_cmd = args.command.clone();
        let launch_context = LaunchContext {
            project_dir: run.cwd.clone(),
            environment: std::env::vars().collect(),
            run_id: run.id.clone(),
        };
        let mut spawn_cmd = launch_cmd;
        if let Some(prepared) = adapter.prepare_launch(&spawn_cmd, &launch_context) {
            spawn_cmd = prepared.command;
            tracing::debug!(adapter = adapter_id, "applied adapter launch preparation");
        }
        run.notes = Some(format!(
            "adapter:{}{}",
            adapter_id,
            if self.policy.insecure_raw {
                ";insecure_raw"
            } else {
                ""
            }
        ));

        self.store
            .insert_run(run)
            .await
            .context("failed to persist run record")?;

        let writer = Arc::new(EventWriter::new(self.store.clone(), run.id.clone()));

        // ── Capture and redact environment variables ───────────────
        let env_redactor = EnvironmentRedactor::new(redact_cfg.clone());
        let env_vars: HashMap<String, String> = std::env::vars().collect();
        let redactions = env_redactor.scan_env(&env_vars);
        let redacted_env = if self.policy.redact {
            env_redactor.redact_env(&env_vars)
        } else {
            env_vars.clone()
        };

        if !redactions.is_empty() {
            tracing::warn!(
                count = redactions.len(),
                "redacted sensitive environment variables"
            );
        }

        let env_json =
            serde_json::to_vec(&redacted_env).context("failed to serialize environment")?;
        let env_blob = self
            .store
            .store_blob(&env_json)
            .await
            .context("failed to store environment blob")?;

        let mut env_event = TraceEvent::new(&run.id, EventSource::System, "environment.captured");
        env_event.status = EventStatus::Success;
        env_event.metadata.insert(
            "environment_blob".to_string(),
            serde_json::json!(env_blob.key),
        );
        env_event.metadata.insert(
            "var_count".to_string(),
            serde_json::json!(redacted_env.len()),
        );
        if !redactions.is_empty() {
            env_event.metadata.insert(
                "redactions".to_string(),
                serde_json::json!(redactions.len()),
            );
        }
        let env_event = writer.write(env_event).await?;

        // ── Start Capture Layers ──────────────────────────────────
        let mut pty_capture = PtyCapture::new();
        let mut git_capture = GitCapture::new().with_store(self.store.clone());
        let mut fs_capture = FilesystemCapture::new();
        let mut process_capture = ProcessCapture::new();

        let pty_rx = pty_capture.start(run).await?;
        let git_rx = git_capture.start(run).await?;
        let fs_rx = fs_capture.start(run).await?;
        let process_rx = process_capture.start(run).await?;

        let (mut merged_rx, _layer_handles) = merge_layers(vec![pty_rx, git_rx, fs_rx, process_rx]);
        // H-22: merge_layers uses fixed insertion-order priority (first receiver wins on
        // concurrent events). Timestamp-based merge is too risky for this fix cycle.
        // Order (pty -> git -> fs -> process) is intentional: terminal output is highest priority.

        // Single-writer ingress for all capture-layer events
        let layer_writer = writer.clone();
        let event_writer_handle = tokio::spawn(async move {
            while let Some(ev) = merged_rx.recv().await {
                if let Err(e) = layer_writer.write(ev).await {
                    tracing::error!(error = %e, "failed to persist capture event");
                }
            }
        });

        // ── Native harness log side-channel ───────────────────────
        let (log_stop_tx, log_stop_rx) = tokio::sync::watch::channel(false);
        let native_roots = {
            let ctx = RunContext {
                run_id: run.id.clone(),
                project_dir: run.cwd.clone(),
                command: args.command.clone(),
            };
            let mut roots: Vec<std::path::PathBuf> = adapter
                .locate_native_logs(&ctx)
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect();
            // Also use discoverer (may add home dirs adapter missed)
            for r in discover_log_roots(adapter_id, &run.cwd) {
                if !roots.contains(&r) {
                    roots.push(r);
                }
            }
            roots
        };
        let native_handle = {
            let adapter_logs = adapter.clone();
            let writer_logs = writer.clone();
            let scanner_logs = SecretScanner::new(redact_cfg.clone());
            tokio::spawn(async move {
                poll_native_logs(
                    adapter_logs,
                    writer_logs,
                    native_roots,
                    scanner_logs,
                    log_stop_rx,
                )
                .await;
            })
        };

        // ── Start checkpoint ──────────────────────────────────────
        let mut start_checkpoint = Checkpoint::new(&run.id, &env_event.id, &run.cwd);
        start_checkpoint.environment_blob = Some(env_blob.key.clone());
        start_checkpoint.git_commit = git_capture.commit_hash().map(str::to_string);
        start_checkpoint.git_diff_blob = git_capture.before_diff_blob_key().map(str::to_string);
        self.store
            .insert_checkpoint(&start_checkpoint)
            .await
            .context("failed to persist start checkpoint")?;
        tracing::debug!(checkpoint_id = %start_checkpoint.id, "start checkpoint created");
        tracing::info!(run_id = %run.id, command = ?run.command, "run started");

        // ── Spawn child in a PTY ──────────────────────────────────
        let (rows, cols) = match term_size::dimensions() {
            Some((w, h)) => (h as u16, w as u16),
            None => {
                tracing::info!(
                    "terminal size unavailable; defaulting to 24x80 (L-25)"
                );
                (24, 80)
            }
        };

        let pty_system = NativePtySystem::default();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("failed to open PTY")?;

        let mut cmd = CommandBuilder::new(&spawn_cmd[0]);
        for arg in &spawn_cmd[1..] {
            cmd.arg(arg);
        }
        cmd.cwd(&run.cwd);

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .context("failed to spawn child process")?;

        drop(pair.slave);

        let child_pid = child.process_id().unwrap_or(0);
        tracing::info!(pid = child_pid, rows, cols, "child process spawned");
        // C-10: Process group isolation -- portable-pty pre_exec calls libc::setsid(),
        // making this child a session leader with PGID == child PID.
        // kill(-child_pid, signal) targets the entire group including grandchildren.

        process_capture.set_pid(child_pid);
        process_capture.emit_spawned().await;

        // Share master so we can resize on SIGWINCH while I/O runs.
        let master = std::sync::Arc::new(std::sync::Mutex::new(pair.master));
        let mut reader = master
            .lock()
            .map_err(|e| anyhow::anyhow!("pty master lock: {}", e))?
            .try_clone_reader()
            .context("failed to clone PTY reader")?;
        let writer_pty = master
            .lock()
            .map_err(|e| anyhow::anyhow!("pty master lock: {}", e))?
            .take_writer()
            .context("failed to take PTY writer")?;

        let stdin_is_tty = std::io::stdin().is_terminal();
        tracing::debug!(stdin_is_tty, "stdin terminal status");

        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Option<Vec<u8>>>(256);
        let (pty_out_tx, mut pty_out_rx) = mpsc::channel::<Vec<u8>>(256);

        let reader_handle = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if pty_out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        tracing::debug!(error = %e, "PTY reader closed");
                        break;
                    }
                }
            }
        });

        let stdin_handle = tokio::task::spawn_blocking(move || {
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 4096];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => {
                        let _ = stdin_tx.blocking_send(None);
                        break;
                    }
                    Ok(n) => {
                        if stdin_tx.blocking_send(Some(buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        tracing::debug!(error = %e, "stdin read error");
                        let _ = stdin_tx.blocking_send(None);
                        break;
                    }
                }
            }
        });

        let pty_writer_handle = tokio::task::spawn_blocking(move || {
            let mut w = writer_pty;
            while let Some(msg) = stdin_rx.blocking_recv() {
                match msg {
                    Some(data) => {
                        if let Err(e) = w.write_all(&data) {
                            tracing::debug!(error = %e, "PTY write failed");
                            break;
                        }
                        if let Err(e) = w.flush() {
                            tracing::debug!(error = %e, "PTY flush failed");
                        }
                    }
                    None => {
                        tracing::debug!("host stdin EOF — closing PTY writer (sends VEOF)");
                        break;
                    }
                }
            }
            drop(w);
        });

        // H-20/H-21: SIGKILL escalation -- on Ctrl+C or SIGTERM, send SIGINT then SIGKILL after grace.
        let signal_child_pid = child_pid;
        let signal_handle = tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = match signal(SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(error = %e, "SIGTERM handler unavailable");
                        // Fall back to ctrl_c only
                        loop {
                            if tokio::signal::ctrl_c().await.is_err() {
                                break;
                            }
                            forward_sigint(signal_child_pid).await;
                            tokio::time::sleep(Duration::from_millis(SIGGRACE_MS)).await;
                            escalate_sigkill(signal_child_pid).await;
                            break;
                        }
                        return;
                    }
                };
                loop {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = sigterm.recv() => {
                            tracing::info!("received SIGTERM, forwarding to child");
                        }
                    }
                    if signal_child_pid == 0 {
                        continue;
                    }
                    forward_sigint(signal_child_pid).await;
                    // Wait SIGGRACE_MS, then escalate to SIGKILL if still alive.
                    tokio::time::sleep(Duration::from_millis(SIGGRACE_MS)).await;
                    escalate_sigkill(signal_child_pid).await;
                    break;
                }
            }
            #[cfg(not(unix))]
            {
                if tokio::signal::ctrl_c().await.is_err() {
                    return;
                }
                if signal_child_pid == 0 {
                    return;
                }
                forward_sigint(signal_child_pid).await;
                tokio::time::sleep(Duration::from_millis(SIGGRACE_MS)).await;
                escalate_sigkill(signal_child_pid).await;
            }
        });

        // C-11: Zombie reaping -- the primary child is collected by child.wait() below.
        // Orphaned grandchildren are reparented to init and reaped automatically.
        // We do NOT use waitpid(-pgid, WNOHANG) here because it would race with
        // child.wait() and reap the primary child prematurely (causing ECHILD).
        let _reap_child_pid = child_pid; // reserved for future per-pid reaping if needed

        // Forward terminal resize (SIGWINCH) to the PTY so interactive apps reflow.
        let resize_master = master.clone();
        let resize_handle = tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sig = match signal(SignalKind::window_change()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(error = %e, "SIGWINCH handler unavailable");
                        return;
                    }
                };
                loop {
                    if sig.recv().await.is_none() {
                        break;
                    }
                    if let Some((w, h)) = term_size::dimensions() {
                        let size = PtySize {
                            rows: h as u16,
                            cols: w as u16,
                            pixel_width: 0,
                            pixel_height: 0,
                        };
                        match resize_master.lock() {
                            Ok(m) => {
                                if let Err(e) = m.resize(size) {
                                    tracing::debug!(error = %e, "PTY resize failed");
                                } else {
                                    tracing::debug!(rows = size.rows, cols = size.cols, "PTY resized");
                                }
                            }
                            Err(e) => tracing::debug!(error = %e, "PTY master lock poisoned"),
                        }
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = resize_master;
            }
        });

        // Consume PTY output: normalize → redact → blob → adapter parse
        let store_writer = self.store.clone();
        let run_id_writer = run.id.clone();
        let adapter_writer = adapter.clone();
        let event_writer = writer.clone();
        let insecure_raw = self.policy.insecure_raw;
        let do_redact = self.policy.redact;
        let scanner_term = SecretScanner::new(redact_cfg);
        let ansi_normalizer = AnsiNormalizer::new();
        let output_handle = tokio::spawn(async move {
            let mut recorder = RawRecorder::new();
            if let Err(e) = recorder.start(&run_id_writer).await {
                tracing::error!(error = %e, "failed to start RawRecorder");
            }

            let mut segment_count: u64 = 0;
            let mut event_count: u64 = 0;
            let mut line_buf = String::new();
            let mut total_redactions: u64 = 0;
            let mut coalescer =
                TerminalCoalescer::new(CoalescePolicy::default(), insecure_raw);

            // Persist one coalesced terminal.output event
            async fn emit_terminal(
                store: &Arc<dyn TraceStore>,
                writer: &EventWriter,
                run_id: &str,
                seg: crate::terminal::coalesce::CoalescedSegment,
                insecure_raw: bool,
            ) -> anyhow::Result<()> {
                let text_blob = store.store_blob(seg.text.as_bytes()).await?.key;
                let mut ev = TraceEvent::new(run_id, EventSource::Terminal, "terminal.output");
                ev.status = EventStatus::Success;
                ev.output_blob = Some(text_blob);
                if insecure_raw && !seg.insecure_raw.is_empty() {
                    let raw_key = store.store_blob(&seg.insecure_raw).await?.key;
                    ev.input_blob = Some(raw_key);
                    ev.metadata
                        .insert("raw_stored".to_string(), serde_json::json!(true));
                }
                ev.metadata
                    .insert("bytes".to_string(), serde_json::json!(seg.raw_bytes));
                ev.metadata
                    .insert("chunks".to_string(), serde_json::json!(seg.chunks));
                ev.metadata
                    .insert("preview".to_string(), serde_json::json!(seg.preview));
                if seg.redactions > 0 {
                    ev.metadata.insert(
                        "redactions".to_string(),
                        serde_json::json!(seg.redactions),
                    );
                }
                writer.write(ev).await?;
                Ok(())
            }

            while let Some(data) = pty_out_rx.recv().await {
                segment_count += 1;

                if let Err(e) = recorder.record_output(&data).await {
                    tracing::warn!(error = %e, "RawRecorder.record_output failed");
                }

                let normalized_text = ansi_normalizer.normalize(&data);
                let redactions = if do_redact {
                    scanner_term.scan(
                        &normalized_text,
                        &format!("terminal:{}", segment_count),
                        None,
                    )
                } else {
                    Vec::new()
                };
                let redact_n = redactions.len() as u64;
                let safe_text = if do_redact {
                    if redact_n > 0 {
                        total_redactions += redact_n;
                        tracing::warn!(
                            count = redact_n,
                            segment = segment_count,
                            "redacted secrets in terminal output"
                        );
                    }
                    scanner_term.redact(&normalized_text)
                } else {
                    normalized_text.clone()
                };

                // Coalesce for storage (adapter parse is still immediate below)
                if let Some(seg) = coalescer.push(&safe_text, &data, redact_n) {
                    if let Err(e) = emit_terminal(
                        &store_writer,
                        event_writer.as_ref(),
                        &run_id_writer,
                        seg,
                        insecure_raw,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "failed to persist terminal event");
                    } else {
                        event_count += 1;
                    }
                }

                // Line-buffered adapter parse on redacted text (not coalesced)
                // Guard against unbounded growth when PTY produces very long lines.
                if line_buf.len() + safe_text.len() > MAX_LINE_BUF_BYTES {
                    tracing::warn!(
                        buf_len = line_buf.len(),
                        added = safe_text.len(),
                        "line_buf exceeded max size; flushing incomplete line"
                    );
                    // Flush whatever is in the buffer as a partial line
                    if !line_buf.trim().is_empty() {
                        for mut parsed in
                            adapter_writer.parse_output(&run_id_writer, line_buf.as_bytes())
                        {
                            if do_redact {
                                let mut meta_val = serde_json::to_value(&parsed.metadata)
                                    .unwrap_or_else(|_| serde_json::json!({}));
                                scanner_term.redact_json(&mut meta_val);
                                match serde_json::from_value(meta_val) {
                                    Ok(m) => parsed.metadata = m,
                                    Err(e) => tracing::warn!(error = %e, "metadata deserialization failed after redaction; keeping original"),
                                }
                            }
                            if let Err(e) = event_writer.write(parsed).await {
                                tracing::error!(error = %e, "failed to persist adapter event");
                            }
                        }
                    }
                    line_buf.clear();
                }
                line_buf.push_str(&safe_text.replace('\r', ""));
                while let Some(pos) = line_buf.find('\n') {
                    let line = line_buf[..pos].to_string();
                    line_buf = line_buf[pos + 1..].to_string();
                    if line.trim().is_empty() {
                        continue;
                    }
                    for mut parsed in adapter_writer.parse_output(&run_id_writer, line.as_bytes()) {
                        if do_redact {
                            let mut meta_val = serde_json::to_value(&parsed.metadata)
                                .unwrap_or_else(|_| serde_json::json!({}));
                            scanner_term.redact_json(&mut meta_val);
                            match serde_json::from_value(meta_val) {
                                Ok(m) => parsed.metadata = m,
                                Err(e) => tracing::warn!(error = %e, "metadata deserialization failed after redaction; keeping original"),
                            }
                        }
                        if let Err(e) = event_writer.write(parsed).await {
                            tracing::error!(error = %e, "failed to persist adapter event");
                        }
                    }
                }
            }

            // Drain coalescer
            if let Some(seg) = coalescer.finish() {
                if let Err(e) = emit_terminal(
                    &store_writer,
                    event_writer.as_ref(),
                    &run_id_writer,
                    seg,
                    insecure_raw,
                )
                .await
                {
                    tracing::error!(error = %e, "failed to persist final terminal event");
                } else {
                    event_count += 1;
                }
            }

            if !line_buf.trim().is_empty() {
                for mut parsed in adapter_writer.parse_output(&run_id_writer, line_buf.as_bytes()) {
                    if do_redact {
                        let mut meta_val = serde_json::to_value(&parsed.metadata)
                            .unwrap_or_else(|_| serde_json::json!({}));
                        scanner_term.redact_json(&mut meta_val);
                        if let Ok(m) = serde_json::from_value(meta_val) {
                            parsed.metadata = m;
                        }
                    }
                    if let Err(e) = event_writer.write(parsed).await {
                        tracing::error!(error = %e, "failed to persist trailing adapter event");
                    }
                }
            }

            match recorder.stop().await {
                Ok(summary_events) => {
                    for ev in summary_events {
                        if let Err(e) = event_writer.write(ev).await {
                            tracing::error!(error = %e, "failed to persist recorder summary");
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "RawRecorder.stop failed"),
            }

            let _ = event_count;
            (segment_count, total_redactions)
        });

        let wait_handle = tokio::task::spawn_blocking(move || child.wait());

        let exit_status = tokio::select! {
            result = wait_handle => {
                result.context("wait task panicked")?
                    .context("failed to wait for child process")?
            }
            _ = tokio::time::sleep(Duration::from_secs(4 * 3600)) => {
                // H-20/H-21: After 4h timeout, escalate: SIGINT -> 5s -> SIGKILL.
                tracing::warn!(pid = child_pid, "child wait timed out; escalating to SIGKILL");
                let _ = unsafe { libc::kill(-(child_pid as i32), libc::SIGINT) };
                tokio::time::sleep(Duration::from_secs(5)).await;
                let _ = unsafe { libc::kill(-(child_pid as i32), libc::SIGKILL) };
                let _ = unsafe { libc::kill(child_pid as i32, libc::SIGKILL) };
                tokio::task::spawn_blocking(move || {
                    let mut status: libc::c_int = 0;
                    loop {
                        let ret = unsafe { libc::waitpid(child_pid as i32, &mut status, 0) };
                        if ret > 0 || ret == -1 { break; }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    use std::os::unix::process::ExitStatusExt;
                    let std_status = std::process::ExitStatus::from_raw(status);
                    portable_pty::ExitStatus::with_exit_code(std_status.code().unwrap_or(137) as u32)
                })
                .await
                .context("wait task panicked after SIGKILL")?
            }
        };

        signal_handle.abort();
        resize_handle.abort();
        stdin_handle.abort();
        // Stop native log poller; give it one final cycle via channel
        let _ = log_stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_millis(500), native_handle).await;
        let _ = tokio::time::timeout(Duration::from_millis(200), pty_writer_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), reader_handle).await;
        // H-27: Stop capture layers FIRST -- closing their event channels causes
        // merged_rx to close, letting output_handle finish draining naturally.
        drop(master);
        if let Err(e) = pty_capture.stop().await {
            tracing::debug!(error = %e, "pty_capture.stop failed");
        }
        if let Err(e) = git_capture.stop().await {
            tracing::debug!(error = %e, "git_capture.stop failed");
        }
        if let Err(e) = fs_capture.stop().await {
            tracing::debug!(error = %e, "fs_capture.stop failed");
        }
        if let Err(e) = process_capture.stop().await {
            tracing::debug!(error = %e, "process_capture.stop failed");
        }
        // H-23: Now that capture layers are stopped, output_handle drains remaining
        // events from closed channels. Give it time to flush, then log if it stalls.
        let (segments, total_redactions) =
            match tokio::time::timeout(Duration::from_secs(5), output_handle).await {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "output collector task panicked");
                    (0, 0)
                }
                Err(_elapsed) => {
                    tracing::warn!("cleanup timeout: output collector did not finish after 5s, zeroing counts");
                    (0, 0)
                }
            };
        let _ = tokio::time::timeout(Duration::from_secs(2), event_writer_handle).await;

        tracing::info!(
            exit_code = exit_status.exit_code(),
            success = exit_status.success(),
            segments = segments,
            redactions = total_redactions,
            "child process exited"
        );

        // ── End event + checkpoint ────────────────────────────────
        let mut end_ev = TraceEvent::new(&run.id, EventSource::System, "run.completed");
        end_ev.status = if exit_status.success() {
            EventStatus::Success
        } else {
            EventStatus::Error
        };
        end_ev.metadata.insert(
            "exit_code".to_string(),
            serde_json::json!(exit_status.exit_code()),
        );
        end_ev
            .metadata
            .insert("segments".to_string(), serde_json::json!(segments));
        if total_redactions > 0 {
            end_ev.metadata.insert(
                "total_redactions".to_string(),
                serde_json::json!(total_redactions),
            );
        }
        let end_ev = writer.write(end_ev).await?;

        let all_events = match self.store.get_events(&run.id).await {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!(error = %e, "failed to fetch events for session_id discovery; proceeding with empty list");
                Vec::new()
            }
        };
        let session_id = adapter.discover_session_id(&all_events);
        if let Some(ref sid) = session_id {
            tracing::info!(session_id = %sid, "discovered harness session");
        }

        // End checkpoint uses AFTER state (not before)
        let mut end_checkpoint = Checkpoint::new(&run.id, &end_ev.id, &run.cwd);
        end_checkpoint.environment_blob = Some(env_blob.key);
        end_checkpoint.git_commit = git_capture.after_commit_hash().map(str::to_string);
        end_checkpoint.git_diff_blob = git_capture.after_diff_blob_key().map(str::to_string);
        end_checkpoint.harness_session_id = session_id.clone();
        self.store
            .insert_checkpoint(&end_checkpoint)
            .await
            .context("failed to persist end checkpoint")?;
        tracing::debug!(checkpoint_id = %end_checkpoint.id, "end checkpoint created");

        // ── Finalize ──────────────────────────────────────────────
        run.finish(exit_status.exit_code() as i32);
        run.next_sequence = writer.next_sequence();
        if let Some(sid) = session_id {
            let note = run.notes.take().unwrap_or_default();
            run.notes = Some(if note.is_empty() {
                format!("session:{}", sid)
            } else {
                format!("{}; session:{}", note, sid)
            });
        }
        self.store
            .update_run(run)
            .await
            .context("failed to update run record")?;

        let _ = stdin_is_tty;
        Ok(())
    }
}

/// Forward SIGINT to a child process (process group first, fallback to direct).
async fn forward_sigint(pid: u32) {
    tracing::debug!(pid, "forwarding SIGINT to child");
    // SAFETY: signal_child_pid was obtained from process::Command output and is a valid
    // child PID. The negative PID sends the signal to the entire process group.
    let ret = unsafe { libc::kill(-(pid as i32), libc::SIGINT) };
    if ret != 0 {
        // SAFETY: Same PID; falling back to direct process signal when process-group kill fails.
        let ret2 = unsafe { libc::kill(pid as i32, libc::SIGINT) };
        if ret2 != 0 {
            tracing::warn!(
                pid,
                errno = std::io::Error::last_os_error().to_string(),
                "failed to forward SIGINT"
            );
        }
    }
}

/// Escalate to SIGKILL after grace period (both process group and direct).
async fn escalate_sigkill(pid: u32) {
    tracing::debug!(pid, "SIGKILL escalation after timeout");
    let _ = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
    let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
}
