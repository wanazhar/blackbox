pub mod coverage;
/// Filesystem module.
pub mod filesystem;
/// Git module.
pub mod git;
pub mod health;
/// Process module.
pub mod process;
/// Pty module.
pub mod pty;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::core::event::TraceEvent;
use crate::core::run::Run;

/// A capture layer observes one dimension of harness activity.
///
/// Each layer is independent and emits `TraceEvent` values into
/// a shared channel. Layers can be enabled or disabled per run.
#[async_trait::async_trait]
pub trait CaptureLayer: Send + 'static {
    /// Human-readable name of this capture layer.
    fn name(&self) -> &'static str;

    /// Start capturing events from the given run.
    ///
    /// Returns a receiver that yields events as they occur.
    async fn start(&mut self, run: &Run)
        -> anyhow::Result<tokio::sync::mpsc::Receiver<TraceEvent>>;

    /// Stop capturing and clean up resources.
    async fn stop(&mut self) -> anyhow::Result<()>;
}

/// Shared backpressure counters for merge_layers / PTY paths (1.4 Phase D).
///
/// Policy: **events are not silently dropped** on the merge path. Prolonged
/// `send` waits count as **lag samples**; closed-channel failures count as
/// **send_failures**. Consumers must treat both as honesty signals, not as
/// free license to discard terminal/tool events.
#[derive(Debug, Default)]
pub struct BackpressureStats {
    /// Times a merge `send` blocked ≥ 50ms (lag samples — not dropped events).
    pub lag_samples: AtomicU64,
    /// Merge channel closed / send failed (event not delivered downstream).
    pub send_failures: AtomicU64,
    /// Peak depth hint.
    pub peak_depth_hint: AtomicU64,
}

impl BackpressureStats {
    /// `(lag_samples, send_failures)`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `snapshot` — see module docs for full workflow.
    /// ```
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.lag_samples.load(Ordering::Relaxed),
            self.send_failures.load(Ordering::Relaxed),
        )
    }

    /// Record lag sample.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `record_lag_sample` — see module docs for full workflow.
    /// ```
    pub fn record_lag_sample(&self) {
        self.lag_samples.fetch_add(1, Ordering::Relaxed);
    }
}

/// Merge multiple capture layer receivers into a single event stream.
///
/// Returns the merged receiver, join handles, and shared backpressure stats.
/// Events are never silently discarded under normal operation; prolonged
/// `send` wait counts as lag pressure so doctor/coverage can surface capture
/// falling behind. A closed downstream channel increments `send_failures`.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `merge_layers` — see module docs for full workflow.
/// ```
pub fn merge_layers(
    receivers: Vec<tokio::sync::mpsc::Receiver<TraceEvent>>,
) -> (
    tokio::sync::mpsc::Receiver<TraceEvent>,
    Vec<tokio::task::JoinHandle<()>>,
    Arc<BackpressureStats>,
) {
    let stats = Arc::new(BackpressureStats::default());
    let (merged_tx, merged_rx) = tokio::sync::mpsc::channel(2048);
    let mut handles = Vec::with_capacity(receivers.len());

    for mut rx in receivers {
        let tx = merged_tx.clone();
        let stats = stats.clone();
        let handle = tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                let t0 = std::time::Instant::now();
                if tx.send(ev).await.is_err() {
                    stats.send_failures.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                let waited = t0.elapsed();
                if waited >= std::time::Duration::from_millis(50) {
                    stats.record_lag_sample();
                    tracing::warn!(
                        wait_ms = waited.as_millis() as u64,
                        "capture merge channel lag: event send blocked (event still delivered)"
                    );
                }
            }
        });
        handles.push(handle);
    }

    (merged_rx, handles, stats)
}
