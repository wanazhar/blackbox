use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, TraceEvent};
use crate::core::run::Run;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// Git-aware change tracker.
///
/// Captures repository state before and after each action:
/// - Initial commit or tree hash
/// - Working tree state before the run
/// - Working tree state after meaningful actions
/// - Generated patch/diff for review
pub struct GitCapture;

#[async_trait]
impl CaptureLayer for GitCapture {
    fn name(&self) -> &'static str {
        "git"
    }

    async fn start(&mut self, run: &Run) -> anyhow::Result<mpsc::Receiver<TraceEvent>> {
        let (tx, rx) = mpsc::channel(1024);

        let ev = TraceEvent::new(&run.id, EventSource::Git, "git.observer.started");
        tx.send(ev).await?;

        drop(tx);
        Ok(rx)
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
