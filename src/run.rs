use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use tokio::sync::mpsc;

use crate::capture::git::GitCapture;
use crate::capture::pty::PtyCapture;
use crate::capture::{CaptureLayer, merge_layers};
use crate::cli::RunArgs;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::run::{Run, RunStatus};
use crate::redaction::environment::EnvironmentRedactor;
use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;
use crate::storage::TraceStore;
use crate::terminal::ansi::AnsiNormalizer;

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
        // ── 1. Build the Run record ──────────────────────────────
        let cwd = args
            .project
            .clone()
            .or_else(|| std::env::current_dir().ok().map(|p| p.to_string_lossy().to_string()))
            .unwrap_or_else(|| ".".to_string());

        let mut run = Run::new(args.command.clone(), cwd);
        run.name = args.name.clone();
        run.tags = args.tag.clone();
        run.status = RunStatus::Running;

        self.store
            .insert_run(&run)
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

        // Store environment as event metadata
        let mut env_event = TraceEvent::new(&run.id, EventSource::System, "environment.captured");
        env_event.status = EventStatus::Success;
        env_event.metadata.insert(
            "environment".to_string(),
            serde_json::json!(redacted_env),
        );
        if !redactions.is_empty() {
            env_event.metadata.insert(
                "redactions".to_string(),
                serde_json::json!(redactions.len()),
            );
        }
        self.store.insert_event(&env_event).await.context("failed to persist environment event")?;

        tracing::info!(run_id = %run.id, command = ?run.command, "run started");

        // ── 2. Spawn the child in a PTY ─────────────────────────
        let pty_system = NativePtySystem::default();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
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

        let child_pid = child.process_id().unwrap_or(0);
        tracing::info!(pid = child_pid, "child process spawned");

        // Get the master's raw fd, then dup it for our reader.
        let master_fd = pair
            .master
            .as_raw_fd()
            .context("failed to get master fd")?;
        let reader_fd = unsafe { libc::dup(master_fd) };
        if reader_fd < 0 {
            anyhow::bail!("failed to dup master fd");
        }

        // Drop pair — closes slave and master fds in parent.
        drop(pair);

        // ── 3. Start Capture Layers ───────────────────────────────
        let mut pty_capture = PtyCapture::new();
        let mut git_capture = GitCapture::new();

        let pty_rx = pty_capture.start(&run).await?;
        let git_rx = git_capture.start(&run).await?;

        // Merge all capture layer channels into a single event stream
        let mut merged_rx = merge_layers(vec![pty_rx, git_rx]);

        let run_id = run.id.clone();

        // Task: store merged events from all capture layers
        let store_event_writer = self.store.clone();
        let event_writer_handle = tokio::spawn(async move {
            while let Some(ev) = merged_rx.recv().await {
                if let Err(e) = store_event_writer.insert_event(&ev).await {
                    tracing::error!(error = %e, "failed to persist capture event");
                }
            }
        });

        // Set up a channel for PTY output bytes
        let (pty_out_tx, mut pty_out_rx) = mpsc::channel::<Vec<u8>>(256);

        // Blocking task: read PTY master output
        let reader_handle = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 8192];
            loop {
                let n = unsafe {
                    libc::read(reader_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n <= 0 {
                    break;
                }
                let data = buf[..n as usize].to_vec();
                if pty_out_tx.blocking_send(data).is_err() {
                    break;
                }
            }
        });

        // Task: consume PTY output, normalize ANSI, scan for secrets, and persist events
        let store_writer = self.store.clone();
        let run_id_writer = run_id.clone();
        let scanner = SecretScanner::new(RedactionConfig::default());
        let ansi_normalizer = AnsiNormalizer::new();
        let writer_handle = tokio::spawn(async move {
            let mut segment_count: u64 = 0;
            while let Some(data) = pty_out_rx.recv().await {
                segment_count += 1;
                let raw_text = String::from_utf8_lossy(&data).to_string();

                // Normalize ANSI sequences
                let normalized_text = ansi_normalizer.normalize(&data);

                // Scan for secrets in the normalized output
                let redactions = scanner.scan(&normalized_text, &format!("terminal:{}", segment_count), None);
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
                ev.sequence = segment_count;
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
            }
            segment_count
        });

        // ── 4. Wait for child to exit ────────────────────────────
        let exit_status = tokio::task::spawn_blocking(move || child.wait())
            .await
            .context("wait task panicked")?
            .context("failed to wait for child process")?;

        // Wait for reader task to drain
        let _ = reader_handle.await;

        // Signal capture layers to stop
        let _ = pty_capture.stop().await;
        let _ = git_capture.stop().await;

        // Wait for event writer to finish
        let _ = event_writer_handle.await;

        // Wait for writer task to finish
        let segments = writer_handle.await.unwrap_or(0);

        tracing::info!(
            exit_code = exit_status.exit_code(),
            success = exit_status.success(),
            segments = segments,
            "child process exited"
        );

        // ── 5. Finalize the Run ──────────────────────────────────
        run.finish(exit_status.exit_code() as i32);
        self.store
            .update_run(&run)
            .await
            .context("failed to update run record")?;

        Ok(run)
    }
}
