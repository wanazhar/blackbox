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
#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::run::Run;

    #[tokio::test]
    async fn start_emits_pty_started_event() {
        let mut cap = PtyCapture::new();
        let run = Run::new(vec!["bash".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.kind, "pty.started");
        assert_eq!(ev.source, EventSource::Terminal);
    }

    #[tokio::test]
    async fn stop_emits_pty_stopped_event() {
        let mut cap = PtyCapture::new();
        let run = Run::new(vec!["bash".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let _start = rx.try_recv().unwrap();
        cap.stop().await.unwrap();
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.kind, "pty.stopped");
        assert_eq!(ev.source, EventSource::Terminal);
    }

    #[tokio::test]
    async fn stop_without_start_does_nothing() {
        let mut cap = PtyCapture::new();
        assert!(cap.stop().await.is_ok());
    }

    #[tokio::test]
    async fn double_stop_is_safe() {
        let mut cap = PtyCapture::new();
        let run = Run::new(vec!["bash".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let _start = rx.try_recv().unwrap();
        cap.stop().await.unwrap();
        // Second stop should not panic
        cap.stop().await.unwrap();
    }

    #[tokio::test]
    async fn start_returns_unique_receiver() {
        let mut cap = PtyCapture::new();
        let run = Run::new(vec!["bash".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.kind, "pty.started");
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            format!("{:?}", PtyCapture::default()),
            format!("{:?}", PtyCapture::new())
        );
    }

    #[test]
    fn new_creates_empty_state() {
        let cap = PtyCapture::new();
        assert!(cap.event_tx.is_none());
        assert!(cap.run_id.is_none());
    }
}
