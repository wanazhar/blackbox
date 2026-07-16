pub mod coverage;
pub mod filesystem;
pub mod git;
pub mod health;
pub mod process;
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

/// Shared backpressure counters for merge_layers / PTY paths.
#[derive(Debug, Default)]
pub struct BackpressureStats {
    pub dropped: AtomicU64,
    pub send_failures: AtomicU64,
    pub peak_depth_hint: AtomicU64,
}

impl BackpressureStats {
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.dropped.load(Ordering::Relaxed),
            self.send_failures.load(Ordering::Relaxed),
        )
    }
}

/// Merge multiple capture layer receivers into a single event stream.
///
/// Returns the merged receiver, join handles, and shared backpressure stats.
/// Events are never dropped; prolonged `send` wait counts as lag pressure so
/// doctor/coverage can surface capture falling behind.
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
                    stats.dropped.fetch_add(1, Ordering::Relaxed); // lag samples (not drops)
                    tracing::warn!(
                        wait_ms = waited.as_millis() as u64,
                        "capture merge channel lag: event send blocked"
                    );
                }
            }
        });
        handles.push(handle);
    }

    (merged_rx, handles, stats)
}
