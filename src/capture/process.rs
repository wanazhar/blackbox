use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, EventStatus, TraceEvent};
use crate::core::run::Run;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// Process-tree observer.
///
/// Tracks the supervised process lifecycle and records basic
/// process metadata. Full `/proc` inspection is a later enhancement.
#[derive(Debug)]
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
        if let (Some(tx), Some(run_id), Some(pid)) = (&self.event_tx, &self.run_id, self.child_pid)
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

        let mut ev = TraceEvent::new(&run.id, EventSource::Process, "process.observer.started");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::run::Run;

    #[tokio::test]
    async fn start_emits_spawn_event() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.kind, "process.observer.started");
        assert_eq!(ev.source, EventSource::Process);
    }

    #[tokio::test]
    async fn stop_without_start_does_nothing() {
        let mut cap = ProcessCapture::new();
        assert!(cap.stop().await.is_ok());
    }

    #[tokio::test]
    async fn stop_emits_stopped_event() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["test".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let _start = rx.try_recv().unwrap();
        cap.stop().await.unwrap();
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.kind, "process.observer.stopped");
    }

    #[tokio::test]
    async fn set_pid_and_emit_spawned() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["sleep".into(), "1".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let _start = rx.try_recv().unwrap();
        cap.set_pid(42);
        cap.emit_spawned().await;
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.kind, "process.spawned");
        assert_eq!(ev.metadata.get("pid").and_then(|v| v.as_u64()), Some(42));
    }

    #[tokio::test]
    async fn emit_spawned_without_pid_is_noop() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["true".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let _start = rx.try_recv().unwrap();
        cap.emit_spawned().await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn start_metadata_includes_command() {
        let mut cap = ProcessCapture::new();
        let run = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
        let mut rx = cap.start(&run).await.unwrap();
        let ev = rx.try_recv().unwrap();
        let cmd = ev.metadata.get("command").and_then(|v| v.as_str());
        assert_eq!(cmd, Some("echo hi"));
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            format!("{:?}", ProcessCapture::default()),
            format!("{:?}", ProcessCapture::new())
        );
    }

    #[test]
    fn new_creates_empty_state() {
        let cap = ProcessCapture::new();
        assert!(cap.event_tx.is_none());
        assert!(cap.run_id.is_none());
        assert!(cap.child_pid.is_none());
    }
}
