use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::run::Run;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// PTY supervisor — the universal capture layer.
///
/// Emits lifecycle events for PTY start/stop. Actual PTY I/O is handled
/// by `RunSupervisor` which owns the portable-pty pair, but this layer
/// participates in the CaptureLayer merge so the event stream is uniform.
pub struct PtyCapture {
    event_tx: Option<mpsc::Sender<TraceEvent>>,
    run_id: Option<String>,
}

impl PtyCapture {
    pub fn new() -> Self {
        Self {
            event_tx: None,
            run_id: None,
        }
    }
}

impl Default for PtyCapture {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CaptureLayer for PtyCapture {
    fn name(&self) -> &'static str {
        "pty"
    }

    async fn start(&mut self, run: &Run) -> anyhow::Result<mpsc::Receiver<TraceEvent>> {
        let (tx, rx) = mpsc::channel(1024);

        let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "pty.started");
        ev.status = EventStatus::Success;
        tx.send(ev).await?;

        self.run_id = Some(run.id.clone());
        self.event_tx = Some(tx);
        Ok(rx)
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.event_tx.take() {
            let run_id = self.run_id.as_deref().unwrap_or("");
            // Only emit if we have a real run_id (avoids FK violations)
            if !run_id.is_empty() {
                let mut ev = TraceEvent::new(run_id, EventSource::Terminal, "pty.stopped");
                ev.status = EventStatus::Success;
                let _ = tx.send(ev).await;
            }
        }
        Ok(())
    }
}
