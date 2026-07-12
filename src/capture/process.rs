use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::run::Run;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// Process-tree observer.
///
/// Tracks the supervised process lifecycle and records basic
/// process metadata. Full `/proc` inspection is a later enhancement.
pub struct ProcessCapture {
    event_tx: Option<mpsc::Sender<TraceEvent>>,
    run_id: Option<String>,
    child_pid: Option<u32>,
}

impl ProcessCapture {
    pub fn new() -> Self {
        Self {
            event_tx: None,
            run_id: None,
            child_pid: None,
        }
    }

    /// Record the child PID once the process is spawned.
    pub fn set_pid(&mut self, pid: u32) {
        self.child_pid = Some(pid);
    }

    /// Emit a process.spawned event if the channel is still open.
    pub async fn emit_spawned(&self) {
        if let (Some(tx), Some(run_id), Some(pid)) =
            (&self.event_tx, &self.run_id, self.child_pid)
        {
            let mut ev = TraceEvent::new(run_id, EventSource::Process, "process.spawned");
            ev.status = EventStatus::Success;
            ev.metadata
                .insert("pid".to_string(), serde_json::json!(pid));
            let _ = tx.send(ev).await;
        }
    }
}

impl Default for ProcessCapture {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CaptureLayer for ProcessCapture {
    fn name(&self) -> &'static str {
        "process"
    }

    async fn start(&mut self, run: &Run) -> anyhow::Result<mpsc::Receiver<TraceEvent>> {
        let (tx, rx) = mpsc::channel(1024);

        let mut ev =
            TraceEvent::new(&run.id, EventSource::Process, "process.observer.started");
        ev.status = EventStatus::Success;
        ev.metadata.insert(
            "command".to_string(),
            serde_json::json!(run.command.join(" ")),
        );
        tx.send(ev).await?;

        self.run_id = Some(run.id.clone());
        self.event_tx = Some(tx);
        Ok(rx)
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.event_tx.take() {
            if let Some(run_id) = &self.run_id {
                let mut ev =
                    TraceEvent::new(run_id, EventSource::Process, "process.observer.stopped");
                ev.status = EventStatus::Success;
                if let Some(pid) = self.child_pid {
                    ev.metadata
                        .insert("pid".to_string(), serde_json::json!(pid));
                }
                let _ = tx.send(ev).await;
            }
        }
        Ok(())
    }
}
