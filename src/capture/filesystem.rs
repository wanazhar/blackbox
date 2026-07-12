use crate::capture::CaptureLayer;
use crate::core::event::{EventSource, TraceEvent};
use crate::core::run::Run;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// Filesystem-change observer.
///
/// Detects file creation, modification, renaming, and deletion
/// within the project directory.
///
/// Two complementary modes:
/// - **Repository mode**: uses Git as the primary change detector
/// - **General mode**: uses OS file notifications (inotify on Linux)
pub struct FilesystemCapture;

#[async_trait]
impl CaptureLayer for FilesystemCapture {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    async fn start(&mut self, run: &Run) -> anyhow::Result<mpsc::Receiver<TraceEvent>> {
        let (tx, rx) = mpsc::channel(1024);

        let ev = TraceEvent::new(&run.id, EventSource::Filesystem, "filesystem.observer.started");
        tx.send(ev).await?;

        drop(tx);
        Ok(rx)
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
