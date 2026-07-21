//! Child shutdown coordination (1.5 U1).
//!
//! Soft-stop → grace → hard-kill helpers used when the supervised child
//! times out or the operator interrupts. Kept separate from the PTY pump so
//! kill policy is unit-testable without a full session.

use std::time::Duration;

use anyhow::Context;

/// Grace period after soft interrupt before escalating to hard kill.
pub const SIGGRACE: Duration = Duration::from_millis(5000);

/// Soft-stop the supervised child (SIGINT on Unix; taskkill without /F on Windows).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `forward_sigint` — see module docs for full workflow.
/// ```
pub async fn forward_sigint(pid: u32) {
    if pid == 0 {
        return;
    }
    tracing::debug!(pid, "forwarding interrupt to child");
    #[cfg(unix)]
    {
        // SAFETY: pid from PTY spawn; negative PID targets process group.
        let ret = unsafe { libc::kill(-(pid as i32), libc::SIGINT) };
        if ret != 0 {
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
    #[cfg(windows)]
    {
        // Best-effort soft stop: taskkill without /F asks the process to exit.
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Hard-kill after grace (SIGKILL / taskkill /F).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `escalate_sigkill` — see module docs for full workflow.
/// ```
pub async fn escalate_sigkill(pid: u32) {
    if pid == 0 {
        return;
    }
    tracing::debug!(pid, "kill escalation after timeout");
    #[cfg(unix)]
    {
        let _ = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
        let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Timeout escalation: soft interrupt then hard kill, then wait for exit.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `timeout_kill_and_wait` — see module docs for full workflow.
/// ```
pub async fn timeout_kill_and_wait(child_pid: u32) -> anyhow::Result<portable_pty::ExitStatus> {
    tracing::warn!(pid = child_pid, "child wait timed out; escalating kill");
    forward_sigint(child_pid).await;
    tokio::time::sleep(SIGGRACE).await;
    escalate_sigkill(child_pid).await;

    #[cfg(unix)]
    {
        tokio::task::spawn_blocking(move || {
            let mut status: libc::c_int = 0;
            loop {
                let ret = unsafe { libc::waitpid(child_pid as i32, &mut status, 0) };
                if ret > 0 || ret == -1 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            use std::os::unix::process::ExitStatusExt;
            let std_status = std::process::ExitStatus::from_raw(status);
            portable_pty::ExitStatus::with_exit_code(std_status.code().unwrap_or(137) as u32)
        })
        .await
        .context("wait task panicked after kill")
    }
    #[cfg(not(unix))]
    {
        // On Windows, waitpid is unavailable; report a synthetic timeout exit.
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(portable_pty::ExitStatus::with_exit_code(1))
    }
}

/// Drain order for end-of-run cleanup (documentation + tests).
///
/// The orchestrator should stop layers in this order so merged channels close
/// before the output collector is awaited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainStep {
    /// `AbortSignalHandlers` variant.
    AbortSignalHandlers,
    /// `StopNativeLogPoller` variant.
    StopNativeLogPoller,
    /// `DropPtyMaster` variant.
    DropPtyMaster,
    /// `StopCaptureLayers` variant.
    StopCaptureLayers,
    /// `AwaitOutputCollector` variant.
    AwaitOutputCollector,
    /// `AwaitEventWriter` variant.
    AwaitEventWriter,
    /// `FlushBatchIngest` variant.
    FlushBatchIngest,
    /// `WriterShutdown` variant.
    WriterShutdown,
}

impl DrainStep {
    /// Sequence.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `sequence` — see module docs for full workflow.
    /// ```
    pub fn sequence() -> &'static [DrainStep] {
        &[
            Self::AbortSignalHandlers,
            Self::StopNativeLogPoller,
            Self::DropPtyMaster,
            Self::StopCaptureLayers,
            Self::AwaitOutputCollector,
            Self::AwaitEventWriter,
            Self::FlushBatchIngest,
            Self::WriterShutdown,
        ]
    }

    /// View as str.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `as_str` — see module docs for full workflow.
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AbortSignalHandlers => "abort_signal_handlers",
            Self::StopNativeLogPoller => "stop_native_log_poller",
            Self::DropPtyMaster => "drop_pty_master",
            Self::StopCaptureLayers => "stop_capture_layers",
            Self::AwaitOutputCollector => "await_output_collector",
            Self::AwaitEventWriter => "await_event_writer",
            Self::FlushBatchIngest => "flush_batch_ingest",
            Self::WriterShutdown => "writer_shutdown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_sequence_starts_with_signals_and_ends_with_writer() {
        let steps = DrainStep::sequence();
        assert_eq!(steps.first().copied(), Some(DrainStep::AbortSignalHandlers));
        assert_eq!(steps.last().copied(), Some(DrainStep::WriterShutdown));
        assert!(steps.len() >= 6);
    }

    #[test]
    fn forward_sigint_noop_on_pid_zero() {
        // Must not panic.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(forward_sigint(0));
        rt.block_on(escalate_sigkill(0));
    }
}
