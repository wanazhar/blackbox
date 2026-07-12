pub mod pty;
pub mod process;
pub mod filesystem;
pub mod git;

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
    async fn start(&mut self, run: &Run) -> anyhow::Result<tokio::sync::mpsc::Receiver<TraceEvent>>;

    /// Stop capturing and clean up resources.
    async fn stop(&mut self) -> anyhow::Result<()>;
}

/// Merge multiple capture layer receivers into a single event stream.
pub fn merge_layers(
    receivers: Vec<tokio::sync::mpsc::Receiver<TraceEvent>>,
) -> tokio::sync::mpsc::Receiver<TraceEvent> {
    let (merged_tx, merged_rx) = tokio::sync::mpsc::channel(1024);

    for mut rx in receivers {
        let tx = merged_tx.clone();
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                if tx.send(ev).await.is_err() {
                    break;
                }
            }
        });
    }

    merged_rx
}
