use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::run::Run;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// PTY supervisor — the universal capture layer.
///
/// Launches the harness inside a pseudoterminal and records:
/// - User keystrokes or submitted messages
/// - Standard output and error
/// - ANSI terminal state
/// - Process start and exit
/// - Window resize events
/// - Interactive approvals
/// - Interrupt signals
pub struct PtyCapture {
    event_tx: Option<mpsc::Sender<TraceEvent>>,
}

impl PtyCapture {
    pub fn new() -> Self {
        Self { event_tx: None }
    }
}

#[async_trait]
impl CaptureLayer for PtyCapture {
    fn name(&self) -> &'static str {
        "pty"
    }

    async fn start(&mut self, run: &Run) -> anyhow::Result<mpsc::Receiver<TraceEvent>> {
        let (tx, rx) = mpsc::channel(1024);

        let ev = TraceEvent::new(&run.id, EventSource::Terminal, "pty.started");
        tx.send(ev).await?;

        self.event_tx = Some(tx);
        Ok(rx)
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.event_tx.take() {
            let mut ev = TraceEvent::new("", EventSource::Terminal, "pty.stopped");
            ev.status = EventStatus::Success;
            let _ = tx.send(ev).await;
        }
        Ok(())
    }
}
