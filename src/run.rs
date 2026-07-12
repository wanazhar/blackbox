use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use tokio::sync::mpsc;

use crate::adapters::claude::ClaudeAdapter;
use crate::adapters::codex::CodexAdapter;
use crate::adapters::generic::GenericAdapter;
use crate::adapters::harness::HarnessAdapter;
use crate::adapters::LaunchContext;
use crate::capture::filesystem::FilesystemCapture;
use crate::capture::git::GitCapture;
use crate::capture::process::ProcessCapture;
use crate::capture::pty::PtyCapture;
use crate::capture::{merge_layers, CaptureLayer};
use crate::cli::RunArgs;
use crate::core::checkpoint::Checkpoint;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::run::{Run, RunStatus};
use crate::redaction::environment::EnvironmentRedactor;
use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;
use crate::storage::TraceStore;
use crate::terminal::ansi::AnsiNormalizer;
use crate::terminal::recorder::RawRecorder;
use crate::terminal::TerminalRecorder;

/// Supervises a child process in a PTY and captures trace events.
pub struct RunSupervisor {
    store: Arc<dyn TraceStore>,
}

impl RunSupervisor {
    pub fn new(store: Arc<dyn TraceStore>) -> Self {
        Self { store }
    }

    /// Run a command under observation.
    pub async fn execute(&self, args: &RunArgs) -> anyhow::Result<Run> {
        // Build the Run record early so we can mark it failed on error.
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
                // Ensure we never leave a run stuck in Running after a failure.
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
        // ── Detect harness adapter ────────────────────────────────
        let adapter: Arc<dyn HarnessAdapter> = if ClaudeAdapter::new().detect(&run.command) {
            Arc::new(ClaudeAdapter::new())
        } else if CodexAdapter::new().detect(&run.command) {
            Arc::new(CodexAdapter::new())
        } else {
            Arc::new(GenericAdapter::new())
        };
        let adapter_id = adapter.id();
        tracing::info!(adapter = adapter_id, "detected harness adapter");

        let launch_context = LaunchContext {
            project_dir: run.cwd.clone(),
            environment: std::env::vars().collect(),
            run_id: run.id.clone(),
        };
        if let Some(prepared) = adapter.prepare_launch(&run.command, &launch_context) {
            run.command = prepared.command;
            tracing::debug!(adapter = adapter_id, "applied adapter launch preparation");
        }
        run.notes = Some(format!("adapter:{}", adapter_id));

        self.store
            .insert_run(run)
            .await
            .context("failed to persist run record")?;

        // ── Capture and redact environment variables ───────────────
        let env_redactor = EnvironmentRedactor::new(RedactionConfig::default());
        let env_vars: HashMap<String, String> = std::env::vars().collect();
        let redactions = env_redactor.scan_env(&env_vars);
        let redacted_env = env_redactor.redact_env(&env_vars);

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

        let seq = Arc::new(AtomicU64::new(1));

        let mut env_event = TraceEvent::new(&run.id, EventSource::System, "environment.captured");
        env_event.sequence = seq.fetch_add(1, Ordering::Relaxed);
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
        self.store
            .insert_event(&env_event)
            .await
            .context("failed to persist environment event")?;

        // ── Start Capture Layers ──────────────────────────────────
        let mut pty_capture = PtyCapture::new();
        let mut git_capture = GitCapture::new().with_store(self.store.clone());
        let mut fs_capture = FilesystemCapture::new();
        let mut process_capture = ProcessCapture::new();

        let pty_rx = pty_capture.start(run).await?;
        let git_rx = git_capture.start(run).await?;
        let fs_rx = fs_capture.start(run).await?;
        let process_rx = process_capture.start(run).await?;

        let mut merged_rx = merge_layers(vec![pty_rx, git_rx, fs_rx, process_rx]);
        let run_id = run.id.clone();

        let store_event_writer = self.store.clone();
        let seq_writer = seq.clone();
        let event_writer_handle = tokio::spawn(async move {
            while let Some(mut ev) = merged_rx.recv().await {
                if ev.sequence == 0 {
                    ev.sequence = seq_writer.fetch_add(1, Ordering::Relaxed);
                }
                if let Err(e) = store_event_writer.insert_event(&ev).await {
                    tracing::error!(error = %e, kind = %ev.kind, "failed to persist capture event");
                }
            }
        });

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
        // Use real terminal size when available so interactive apps lay out correctly.
        let (rows, cols) = term_size::dimensions()
            .map(|(w, h)| (h as u16, w as u16))
            .unwrap_or((24, 80));

        let pty_system = NativePtySystem::default();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("failed to open PTY")?;

        let mut cmd = CommandBuilder::new(&run.command[0]);
        for arg in &run.command[1..] {
            cmd.arg(arg);
        }
        cmd.cwd(&run.cwd);

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .context("failed to spawn child process")?;

        // Release the slave handle in the parent — the child owns its end.
        drop(pair.slave);

        let child_pid = child.process_id().unwrap_or(0);
        tracing::info!(pid = child_pid, rows, cols, "child process spawned");

        process_capture.set_pid(child_pid);
        process_capture.emit_spawned().await;

        // portable-pty reader/writer split:
        // - try_clone_reader(): continuous output stream
        // - take_writer(): Drop sends newline+VEOF (Ctrl-D) to the slave,
        //   which is what unblocks programs like `cat` waiting for stdin EOF.
        //   Raw libc::dup does NOT do this — that was the hang.
        let mut reader = pair
            .master
            .try_clone_reader()
            .context("failed to clone PTY reader")?;
        let writer = pair
            .master
            .take_writer()
            .context("failed to take PTY writer")?;

        let stdin_is_tty = std::io::stdin().is_terminal();
        tracing::debug!(stdin_is_tty, "stdin terminal status");

        // ── Channels ──────────────────────────────────────────────
        // None on the stdin channel means "host stdin closed / EOF".
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Option<Vec<u8>>>(256);
        let (pty_out_tx, mut pty_out_rx) = mpsc::channel::<Vec<u8>>(256);

        // Read PTY master output
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
                        // Interrupted reads can happen around signals; retry once
                        if e.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        tracing::debug!(error = %e, "PTY reader closed");
                        break;
                    }
                }
            }
        });

        // Read host stdin and forward (or signal EOF)
        let stdin_handle = tokio::task::spawn_blocking(move || {
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 4096];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => {
                        // Host stdin EOF — tell the writer task to drop the PTY writer
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

        // Write host stdin bytes to PTY; when None arrives (or channel closes),
        // drop the writer so portable-pty sends VEOF to the child.
        let pty_writer_handle = tokio::task::spawn_blocking(move || {
            let mut writer = writer;
            while let Some(msg) = stdin_rx.blocking_recv() {
                match msg {
                    Some(data) => {
                        if let Err(e) = writer.write_all(&data) {
                            tracing::debug!(error = %e, "PTY write failed");
                            break;
                        }
                        let _ = writer.flush();
                    }
                    None => {
                        // Explicit host stdin EOF
                        tracing::debug!("host stdin EOF — closing PTY writer (sends VEOF)");
                        break;
                    }
                }
            }
            // writer dropped here → UnixMasterWriter::drop sends \n + VEOF
            drop(writer);
        });

        // SIGINT → child process group / pid
        let signal_child_pid = child_pid;
        let signal_handle = tokio::spawn(async move {
            loop {
                if tokio::signal::ctrl_c().await.is_err() {
                    break;
                }
                if signal_child_pid == 0 {
                    continue;
                }
                tracing::debug!(pid = signal_child_pid, "forwarding SIGINT to child");
                // Prefer process group so shells and their children get the signal.
                // SAFETY: kill is a simple syscall; negative pid = process group.
                let ret = unsafe { libc::kill(-(signal_child_pid as i32), libc::SIGINT) };
                if ret != 0 {
                    // Fallback: signal the process itself
                    let ret2 = unsafe { libc::kill(signal_child_pid as i32, libc::SIGINT) };
                    if ret2 != 0 {
                        tracing::warn!(
                            pid = signal_child_pid,
                            errno = std::io::Error::last_os_error().to_string(),
                            "failed to forward SIGINT"
                        );
                    }
                }
            }
        });

        // Consume PTY output: record, normalize, redact, parse
        let store_writer = self.store.clone();
        let run_id_writer = run_id.clone();
        let adapter_writer = adapter.clone();
        let seq_term = seq.clone();
        let scanner = SecretScanner::new(RedactionConfig::default());
        let ansi_normalizer = AnsiNormalizer::new();
        let output_handle = tokio::spawn(async move {
            let mut recorder = RawRecorder::new();
            if let Err(e) = recorder.start(&run_id_writer).await {
                tracing::error!(error = %e, "failed to start RawRecorder");
            }

            let mut segment_count: u64 = 0;
            let mut line_buf = String::new();

            while let Some(data) = pty_out_rx.recv().await {
                segment_count += 1;

                if let Err(e) = recorder.record_output(&data).await {
                    tracing::warn!(error = %e, "RawRecorder.record_output failed");
                }

                let raw_text = String::from_utf8_lossy(&data).to_string();
                let normalized_text = ansi_normalizer.normalize(&data);

                let redactions = scanner.scan(
                    &normalized_text,
                    &format!("terminal:{}", segment_count),
                    None,
                );
                let redacted_text = if redactions.is_empty() {
                    normalized_text.clone()
                } else {
                    tracing::warn!(
                        count = redactions.len(),
                        segment = segment_count,
                        "redacted secrets in terminal output"
                    );
                    scanner.redact(&normalized_text)
                };

                let mut ev =
                    TraceEvent::new(&run_id_writer, EventSource::Terminal, "terminal.output");
                ev.sequence = seq_term.fetch_add(1, Ordering::Relaxed);
                ev.status = EventStatus::Success;
                ev.metadata
                    .insert("bytes".to_string(), serde_json::json!(data.len()));
                ev.metadata
                    .insert("raw".to_string(), serde_json::json!(raw_text));
                ev.metadata
                    .insert("normalized".to_string(), serde_json::json!(redacted_text));
                if !redactions.is_empty() {
                    ev.metadata.insert(
                        "redactions".to_string(),
                        serde_json::json!(redactions.len()),
                    );
                }
                if let Err(e) = store_writer.insert_event(&ev).await {
                    tracing::error!(error = %e, "failed to persist terminal event");
                }

                // Line-buffered adapter parse (\r\n and \n)
                line_buf.push_str(&redacted_text.replace('\r', ""));
                while let Some(pos) = line_buf.find('\n') {
                    let line = line_buf[..pos].to_string();
                    line_buf = line_buf[pos + 1..].to_string();
                    if line.trim().is_empty() {
                        continue;
                    }
                    for mut parsed in adapter_writer.parse_output(&run_id_writer, line.as_bytes()) {
                        parsed.sequence = seq_term.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = store_writer.insert_event(&parsed).await {
                            tracing::error!(
                                error = %e,
                                kind = %parsed.kind,
                                "failed to persist adapter event"
                            );
                        }
                    }
                }
            }

            if !line_buf.trim().is_empty() {
                for mut parsed in
                    adapter_writer.parse_output(&run_id_writer, line_buf.as_bytes())
                {
                    parsed.sequence = seq_term.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = store_writer.insert_event(&parsed).await {
                        tracing::error!(error = %e, "failed to persist trailing adapter event");
                    }
                }
            }

            match recorder.stop().await {
                Ok(summary_events) => {
                    for mut ev in summary_events {
                        ev.sequence = seq_term.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = store_writer.insert_event(&ev).await {
                            tracing::error!(error = %e, "failed to persist recorder summary");
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "RawRecorder.stop failed"),
            }

            segment_count
        });

        // ── Wait for child, with a safety timeout for deadlocks ───
        // Primary path: child exits after stdin EOF → writer drop → VEOF.
        // Safety: if something still hangs, we don't block forever.
        let wait_handle = tokio::task::spawn_blocking(move || child.wait());

        let exit_status = tokio::select! {
            result = wait_handle => {
                result.context("wait task panicked")?
                    .context("failed to wait for child process")?
            }
            // Extreme safety net (interactive sessions can be long; 24h)
            _ = tokio::time::sleep(Duration::from_secs(24 * 60 * 60)) => {
                anyhow::bail!("child process wait timed out after 24h");
            }
        };

        // Child is gone — tear down I/O and signals
        signal_handle.abort();

        // Abort stdin forwarding if still blocked on a TTY read
        stdin_handle.abort();
        // Writer task: either already finished (stdin EOF) or will get channel closed
        // Give it a brief moment to drop the writer cleanly, then abort.
        let _ = tokio::time::timeout(Duration::from_millis(200), pty_writer_handle).await;

        // Drain reader / output pipeline
        let _ = tokio::time::timeout(Duration::from_secs(2), reader_handle).await;
        let segments = match tokio::time::timeout(Duration::from_secs(2), output_handle).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };

        // Drop master last (after I/O tasks), as recommended by portable-pty
        drop(pair.master);

        // Stop capture layers (after-run snapshots)
        let _ = pty_capture.stop().await;
        let _ = git_capture.stop().await;
        let _ = fs_capture.stop().await;
        let _ = process_capture.stop().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), event_writer_handle).await;

        tracing::info!(
            exit_code = exit_status.exit_code(),
            success = exit_status.success(),
            segments = segments,
            "child process exited"
        );

        // ── End event + checkpoint ────────────────────────────────
        let end_event_id = {
            let mut end_ev = TraceEvent::new(&run.id, EventSource::System, "run.completed");
            end_ev.sequence = seq.fetch_add(1, Ordering::Relaxed);
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
            self.store
                .insert_event(&end_ev)
                .await
                .context("failed to persist completion event")?;
            end_ev.id.clone()
        };

        let all_events = self.store.get_events(&run.id).await.unwrap_or_default();
        let session_id = adapter.discover_session_id(&all_events);
        if let Some(ref sid) = session_id {
            tracing::info!(session_id = %sid, "discovered harness session");
        }

        let mut end_checkpoint = Checkpoint::new(&run.id, &end_event_id, &run.cwd);
        end_checkpoint.environment_blob = Some(env_blob.key);
        end_checkpoint.git_commit = git_capture.commit_hash().map(str::to_string);
        end_checkpoint.git_diff_blob = git_capture.before_diff_blob_key().map(str::to_string);
        end_checkpoint.harness_session_id = session_id;
        self.store
            .insert_checkpoint(&end_checkpoint)
            .await
            .context("failed to persist end checkpoint")?;
        tracing::debug!(checkpoint_id = %end_checkpoint.id, "end checkpoint created");

        // ── Finalize ──────────────────────────────────────────────
        run.finish(exit_status.exit_code() as i32);
        run.next_sequence = seq.load(Ordering::Relaxed);
        self.store
            .update_run(run)
            .await
            .context("failed to update run record")?;

        let _ = args; // silence if unused fields
        let _ = stdin_is_tty;
        Ok(())
    }
}
