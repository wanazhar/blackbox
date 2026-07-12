use std::sync::Arc;

use anyhow::Context;
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use tokio::sync::mpsc;

use crate::capture::pty::PtyCapture;
use crate::capture::CaptureLayer;
use crate::cli::RunArgs;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::run::{Run, RunStatus};
use crate::storage::TraceStore;

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
        // We dup BEFORE dropping pair so the slave fd is still valid
        // during the dup.
        let master_fd = pair
            .master
            .as_raw_fd()
            .context("failed to get master fd")?;
        let reader_fd = unsafe { libc::dup(master_fd) };
        if reader_fd < 0 {
            anyhow::bail!("failed to dup master fd");
        }

        // Drop pair now — closes both slave and master fds in the parent.
        // The child still has its own copies of the slave fds.
        // Our reader_fd is an independent copy of the master.
        drop(pair);

        // ── 3. Start PtyCapture ──────────────────────────────────
        let mut pty_capture = PtyCapture::new();
        let mut event_rx = pty_capture.start(&run).await?;

        let run_id = run.id.clone();

        // Set up a channel for PTY output bytes
        let (pty_out_tx, mut pty_out_rx) = mpsc::channel::<Vec<u8>>(256);

        // Blocking task: read PTY master output using raw libc::read
        let reader_handle = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 8192];
            loop {
                let n = unsafe {
                    libc::read(reader_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n <= 0 {
                    break; // EOF or error
                }
                let data = buf[..n as usize].to_vec();
                if pty_out_tx.blocking_send(data).is_err() {
                    break;
                }
            }
        });

        // Task: consume PTY output and persist events
        let store_writer = self.store.clone();
        let run_id_writer = run_id.clone();
        let writer_handle = tokio::spawn(async move {
            let mut segment_count: u64 = 0;
            while let Some(data) = pty_out_rx.recv().await {
                segment_count += 1;
                let mut ev =
                    TraceEvent::new(&run_id_writer, EventSource::Terminal, "terminal.output");
                ev.sequence = segment_count;
                ev.status = EventStatus::Success;
                ev.metadata
                    .insert("bytes".to_string(), serde_json::json!(data.len()));
                ev.metadata.insert(
                    "raw".to_string(),
                    serde_json::json!(String::from_utf8_lossy(&data).to_string()),
                );
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

        // Wait for reader task to drain and finish.
        // With pair dropped, once the child exits, all slave-side fds
        // are closed, and the master side will get EIO → read returns 0.
        let _ = reader_handle.await;

        // Signal PtyCapture to stop
        let _ = pty_capture.stop().await;

        // Drain any remaining events from PtyCapture
        while let Ok(ev) = event_rx.try_recv() {
            let _ = self.store.insert_event(&ev).await;
        }

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
