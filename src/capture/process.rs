use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, TraceEvent};
use crate::core::run::Run;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// Process-tree observer.
///
/// Tracks commands launched by the harness:
/// - Executable and arguments
/// - Working directory
/// - Parent-child relationships
/// - Start/end times and exit status
/// - CPU time and peak memory (when measurable)
///
/// Initial implementation uses process supervision and `/proc`
/// inspection on Linux.
pub struct ProcessCapture;

#[async_trait]
impl CaptureLayer for ProcessCapture {
    fn name(&self) -> &'static str {
        "process"
    }

    async fn start(&mut self, run: &Run) -> anyhow::Result<mpsc::Receiver<TraceEvent>> {
        let (tx, rx) = mpsc::channel(1024);

        let ev = TraceEvent::new(&run.id, EventSource::Process, "process.observer.started");
        tx.send(ev).await?;

        drop(tx);
        Ok(rx)
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
