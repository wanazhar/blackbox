//! Local Unix domain socket transport for native ingestion.
//!
//! Each connection speaks the same NDJSON framing as [`super::ndjson`].
//! One malformed producer connection cannot corrupt another run: each
//! connection is isolated and errors are scoped to that stream.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use super::ndjson::NdjsonIngestServer;
use super::recorder::NativeRecorder;

/// Unix socket server configuration.
#[derive(Debug, Clone)]
pub struct UnixIngestServerConfig {
    /// Socket path.
    pub path: PathBuf,
    /// Max concurrent connections.
    pub max_connections: usize,
    /// NDJSON framing limits.
    pub ndjson: NdjsonIngestServer,
}

impl UnixIngestServerConfig {
    /// Build config for a socket path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_connections: 32,
            ndjson: NdjsonIngestServer::default(),
        }
    }
}

/// Unix socket ingest server.
pub struct UnixIngestServer {
    config: UnixIngestServerConfig,
    recorder: Arc<NativeRecorder>,
}

impl UnixIngestServer {
    /// Create a server.
    pub fn new(recorder: Arc<NativeRecorder>, config: UnixIngestServerConfig) -> Self {
        Self { config, recorder }
    }

    /// Socket path.
    pub fn path(&self) -> &Path {
        &self.config.path
    }

    /// Bind and serve until the returned handle is dropped or accept fails.
    ///
    /// Removes a pre-existing socket file at the path when present.
    pub async fn serve(&self) -> anyhow::Result<()> {
        if self.config.path.exists() {
            let _ = std::fs::remove_file(&self.config.path);
        }
        if let Some(parent) = self.config.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(&self.config.path)?;
        let sem = Arc::new(Semaphore::new(self.config.max_connections.max(1)));
        loop {
            let (stream, _addr) = listener.accept().await?;
            let permit = sem.clone().acquire_owned().await?;
            let recorder = self.recorder.clone();
            let ndjson = self.config.ndjson.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_connection(recorder, ndjson, stream).await {
                    tracing::debug!(error = %e, "unix ingest connection ended with error");
                }
            });
        }
    }

    /// Handle a single already-connected stream (tests).
    pub async fn handle_stream(&self, stream: UnixStream) -> anyhow::Result<()> {
        handle_connection(self.recorder.clone(), self.config.ndjson.clone(), stream).await
    }
}

async fn handle_connection(
    recorder: Arc<NativeRecorder>,
    ndjson: NdjsonIngestServer,
    stream: UnixStream,
) -> anyhow::Result<()> {
    let (reader, writer) = stream.into_split();
    ndjson.serve_stream(recorder, reader, writer).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::recorder::NativeRecorder;
    use crate::storage::store::InMemoryStore;
    use crate::storage::TraceStore;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn unix_socket_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ingest.sock");
        let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
        let rec = Arc::new(NativeRecorder::new(store.clone()));
        let server = UnixIngestServer::new(rec.clone(), UnixIngestServerConfig::new(&sock));

        // Bind in background.
        let server_task = {
            let server = UnixIngestServer::new(rec.clone(), UnixIngestServerConfig::new(&sock));
            tokio::spawn(async move {
                let _ = server.serve().await;
            })
        };

        // Wait for socket file.
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(sock.exists(), "socket not created");

        let mut stream = UnixStream::connect(&sock).await.unwrap();
        let frame = r#"{"schema":"blackbox.native.ingest/v1","op":"start_run","idempotency_key":"u1","payload":{"cwd":"/tmp","name":"via-socket"}}"#;
        stream.write_all(frame.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let ack: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(ack["duplicate"], false);
        let run_id = ack["run_id"].as_str().unwrap();
        assert!(store.get_run(run_id).await.unwrap().is_some());

        server_task.abort();
        let _ = server;
    }

    #[tokio::test]
    async fn isolated_connections() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("ingest2.sock");
        let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
        let rec = Arc::new(NativeRecorder::new(store.clone()));

        let server_task = {
            let rec = rec.clone();
            let sock = sock.clone();
            tokio::spawn(async move {
                let server = UnixIngestServer::new(rec, UnixIngestServerConfig::new(sock));
                let _ = server.serve().await;
            })
        };
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Bad producer.
        let mut bad = UnixStream::connect(&sock).await.unwrap();
        bad.write_all(b"{{{{not json\n").await.unwrap();
        let mut bad_r = BufReader::new(bad);
        let mut line = String::new();
        bad_r.read_line(&mut line).await.unwrap();
        assert!(line.contains("malformed") || line.contains("error") || line.contains("code"));

        // Good producer still works.
        let mut good = UnixStream::connect(&sock).await.unwrap();
        good.write_all(br#"{"schema":"blackbox.native.ingest/v1","op":"start_run","idempotency_key":"good","payload":{"cwd":"/tmp"}}"#).await.unwrap();
        good.write_all(b"\n").await.unwrap();
        let mut good_r = BufReader::new(good);
        line.clear();
        good_r.read_line(&mut line).await.unwrap();
        let ack: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(ack["duplicate"], false);
        assert_eq!(store.list_runs().await.unwrap().len(), 1);

        server_task.abort();
    }
}
