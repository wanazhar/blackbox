//! Bounded NDJSON transport for native ingestion.
//!
//! Frame format: one JSON object per line ending in `\n`. Partial lines are
//! buffered and never committed. Max line length is enforced for backpressure
//! and memory safety. Malformed lines yield an error ack and do not poison
//! other runs.

use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Semaphore;

use super::envelope::{IngestError, NativeIngestEnvelope};
use super::recorder::NativeRecorder;

/// Errors specific to NDJSON framing.
#[derive(Debug, Clone)]
pub enum NdjsonIngestError {
    /// Line exceeded max bytes before newline.
    LineTooLong {
        /// Limit.
        max: usize,
    },
    /// JSON parse failure.
    MalformedJson {
        /// Detail.
        message: String,
    },
    /// Envelope decode failure.
    BadEnvelope {
        /// Detail.
        message: String,
    },
}

impl std::fmt::Display for NdjsonIngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LineTooLong { max } => write!(f, "NDJSON line exceeds max {max} bytes"),
            Self::MalformedJson { message } => write!(f, "malformed JSON: {message}"),
            Self::BadEnvelope { message } => write!(f, "bad envelope: {message}"),
        }
    }
}

impl std::error::Error for NdjsonIngestError {}

/// NDJSON ingest server parameters.
#[derive(Debug, Clone)]
pub struct NdjsonIngestServer {
    /// Max bytes per line (default 1 MiB).
    pub max_line_bytes: usize,
    /// Max concurrent in-flight envelopes.
    pub max_in_flight: usize,
}

impl Default for NdjsonIngestServer {
    fn default() -> Self {
        Self {
            max_line_bytes: 1024 * 1024,
            max_in_flight: 64,
        }
    }
}

impl NdjsonIngestServer {
    /// Process a complete buffer of NDJSON text, returning ack/error lines.
    pub async fn process_buffer(
        &self,
        recorder: &NativeRecorder,
        input: &str,
    ) -> Vec<Value> {
        let mut outputs = Vec::new();
        let mut partial = String::new();
        for chunk in input.split_inclusive('\n') {
            if !chunk.ends_with('\n') {
                partial.push_str(chunk);
                if partial.len() > self.max_line_bytes {
                    outputs.push(error_value(IngestError::new(
                        "line_too_long",
                        format!("partial line exceeded {}", self.max_line_bytes),
                        false,
                    )));
                    partial.clear();
                }
                continue;
            }
            let mut line = partial;
            partial = String::new();
            line.push_str(chunk.trim_end_matches(['\n', '\r']));
            if line.is_empty() {
                continue;
            }
            if line.len() > self.max_line_bytes {
                outputs.push(error_value(IngestError::new(
                    "line_too_long",
                    format!("line exceeded {}", self.max_line_bytes),
                    false,
                )));
                continue;
            }
            match process_line(recorder, &line).await {
                Ok(v) => outputs.push(v),
                Err(e) => outputs.push(error_value(e)),
            }
        }
        // Trailing partial without newline is NOT committed.
        let _ = partial;
        outputs
    }

    /// Read from an async reader until EOF, writing acks to the writer.
    pub async fn serve_stream<R, W>(
        &self,
        recorder: Arc<NativeRecorder>,
        reader: R,
        mut writer: W,
    ) -> anyhow::Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut lines = BufReader::new(reader).lines();
        let sem = Arc::new(Semaphore::new(self.max_in_flight.max(1)));
        while let Some(line) = lines.next_line().await? {
            if line.is_empty() {
                continue;
            }
            if line.len() > self.max_line_bytes {
                let err = IngestError::new(
                    "line_too_long",
                    format!("line exceeded {}", self.max_line_bytes),
                    false,
                );
                let bytes = serde_json::to_vec(&err)?;
                writer.write_all(&bytes).await?;
                writer.write_all(b"\n").await?;
                continue;
            }
            let _permit = sem.acquire().await?;
            let out = match process_line(&recorder, &line).await {
                Ok(v) => v,
                Err(e) => error_value(e),
            };
            let bytes = serde_json::to_vec(&out)?;
            writer.write_all(&bytes).await?;
            writer.write_all(b"\n").await?;
        }
        Ok(())
    }
}

async fn process_line(recorder: &NativeRecorder, line: &str) -> Result<Value, IngestError> {
    let env: NativeIngestEnvelope = serde_json::from_str(line).map_err(|e| {
        IngestError::new("malformed_json", e.to_string(), false)
    })?;
    match recorder.apply_envelope(env).await {
        Ok(ack) => Ok(serde_json::to_value(ack).unwrap_or(Value::Null)),
        Err(e) => Err(e),
    }
}

fn error_value(e: IngestError) -> Value {
    serde_json::to_value(e).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::recorder::NativeRecorder;
    use crate::storage::store::InMemoryStore;
    use crate::storage::TraceStore;
    use serde_json::json;

    #[tokio::test]
    async fn partial_line_not_committed() {
        let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
        let rec = NativeRecorder::new(store.clone());
        let server = NdjsonIngestServer::default();
        // Incomplete JSON — no trailing newline commit of partial.
        let outs = server
            .process_buffer(
                &rec,
                r#"{"schema":"blackbox.native.ingest/v1","op":"start_run","idempotency_key":"s1","payload":{"cwd":"/tmp"}"#,
            )
            .await;
        assert!(outs.is_empty(), "partial frame must not commit: {outs:?}");
        assert!(store.list_runs().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn complete_ndjson_run() {
        let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
        let rec = NativeRecorder::new(store.clone());
        let server = NdjsonIngestServer::default();
        let input = concat!(
            r#"{"schema":"blackbox.native.ingest/v1","op":"start_run","idempotency_key":"s1","payload":{"cwd":"/tmp","command":["agent"]}}"#,
            "\n"
        );
        let outs = server.process_buffer(&rec, input).await;
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0]["duplicate"], false);
        let run_id = outs[0]["run_id"].as_str().unwrap().to_string();

        let tool = format!(
            r#"{{"schema":"blackbox.native.ingest/v1","op":"record_tool","idempotency_key":"t1","run_id":"{run_id}","payload":{{"tool_name":"bash"}}}}"#
        ) + "\n";
        let outs = server.process_buffer(&rec, &tool).await;
        assert_eq!(outs[0]["duplicate"], false);

        let fin = format!(
            r#"{{"schema":"blackbox.native.ingest/v1","op":"finish_run","idempotency_key":"f1","run_id":"{run_id}","payload":{{"exit_code":0}}}}"#
        ) + "\n";
        let _ = server.process_buffer(&rec, &fin).await;

        let run = store.get_run(&run_id).await.unwrap().unwrap();
        assert_eq!(
            format!("{:?}", run.status).to_lowercase().contains("succeed"),
            true
        );
        let events = store.get_events(&run_id).await.unwrap();
        assert!(events.iter().any(|e| e.kind == "tool.call"));
    }

    #[tokio::test]
    async fn malformed_line_does_not_poison_next() {
        let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
        let rec = NativeRecorder::new(store.clone());
        let server = NdjsonIngestServer::default();
        let input = format!(
            "{}\n{}\n",
            "not-json!!!",
            r#"{"schema":"blackbox.native.ingest/v1","op":"start_run","idempotency_key":"ok","payload":{"cwd":"/tmp"}}"#
        );
        let outs = server.process_buffer(&rec, &input).await;
        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0]["code"], "malformed_json");
        assert_eq!(outs[1]["duplicate"], false);
        assert_eq!(store.list_runs().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn retry_after_ack_is_duplicate() {
        let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
        let rec = NativeRecorder::new(store.clone());
        let server = NdjsonIngestServer::default();
        let line = r#"{"schema":"blackbox.native.ingest/v1","op":"start_run","idempotency_key":"retry-1","payload":{"cwd":"/tmp"}}"#;
        let input = format!("{line}\n{line}\n");
        let outs = server.process_buffer(&rec, &input).await;
        assert!(!outs[0]["duplicate"].as_bool().unwrap());
        assert!(outs[1]["duplicate"].as_bool().unwrap());
        assert_eq!(outs[0]["run_id"], outs[1]["run_id"]);
        assert_eq!(store.list_runs().await.unwrap().len(), 1);
        let _ = json!({});
    }
}
