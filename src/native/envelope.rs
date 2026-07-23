//! Wire envelopes for native ingestion (`blackbox.native.ingest/v1`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema id for native ingest frames.
pub const NATIVE_INGEST_SCHEMA: &str = "blackbox.native.ingest/v1";

/// Supported native ingest operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestOp {
    /// Create a run and mark it running.
    StartRun,
    /// Record a generic trace event.
    RecordEvent,
    /// Record a tool.call / tool.result pair or single tool event.
    RecordTool,
    /// Record a model/completion event.
    RecordModel,
    /// Record a handoff / session transfer.
    RecordHandoff,
    /// Record a human or policy approval.
    RecordApproval,
    /// Record an external security decision.
    RecordSecurityDecision,
    /// Attach external evidence to a run.
    AttachEvidence,
    /// Finish a run with exit status.
    FinishRun,
    /// Explicit acknowledgement (transport).
    Ack,
}

impl IngestOp {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StartRun => "start_run",
            Self::RecordEvent => "record_event",
            Self::RecordTool => "record_tool",
            Self::RecordModel => "record_model",
            Self::RecordHandoff => "record_handoff",
            Self::RecordApproval => "record_approval",
            Self::RecordSecurityDecision => "record_security_decision",
            Self::AttachEvidence => "attach_evidence",
            Self::FinishRun => "finish_run",
            Self::Ack => "ack",
        }
    }
}

/// Single NDJSON / socket frame for native ingestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeIngestEnvelope {
    /// Schema id.
    pub schema: String,
    /// Operation.
    pub op: IngestOp,
    /// Client-chosen key for at-least-once retry dedup.
    pub idempotency_key: String,
    /// Target run id (required for most ops after start).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Operation-specific payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// Producer name (harness id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer: Option<String>,
    /// Optional client-local sequence (ordering hint only; not trusted as
    /// recorder sequence).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_seq: Option<u64>,
}

impl NativeIngestEnvelope {
    /// Build a typed envelope.
    pub fn new(op: IngestOp, idempotency_key: impl Into<String>) -> Self {
        Self {
            schema: NATIVE_INGEST_SCHEMA.into(),
            op,
            idempotency_key: idempotency_key.into(),
            run_id: None,
            payload: None,
            producer: None,
            client_seq: None,
        }
    }

    /// Attach run id.
    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }

    /// Attach payload object.
    pub fn with_payload(mut self, payload: Value) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Attach producer name.
    pub fn with_producer(mut self, producer: impl Into<String>) -> Self {
        self.producer = Some(producer.into());
        self
    }
}

/// Successful ack returned to producers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestAck {
    /// Schema for ack objects.
    pub schema: String,
    /// Always `ack`.
    pub op: String,
    /// Echoed idempotency key.
    pub idempotency_key: String,
    /// Run id when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Event id when an event was created or replayed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// True when this key was already committed (retry).
    pub duplicate: bool,
    /// Recorder-assigned sequence when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
}

impl IngestAck {
    /// Build an ack.
    pub fn new(idempotency_key: impl Into<String>, duplicate: bool) -> Self {
        Self {
            schema: NATIVE_INGEST_SCHEMA.into(),
            op: "ack".into(),
            idempotency_key: idempotency_key.into(),
            run_id: None,
            event_id: None,
            duplicate,
            sequence: None,
        }
    }
}

/// Ingest failure (malformed, unknown run, backpressure, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestError {
    /// Schema.
    pub schema: String,
    /// Error code.
    pub code: String,
    /// Human message.
    pub message: String,
    /// Idempotency key when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Whether the producer may retry safely.
    pub retryable: bool,
}

impl IngestError {
    /// Construct an error.
    pub fn new(code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            schema: NATIVE_INGEST_SCHEMA.into(),
            code: code.into(),
            message: message.into(),
            idempotency_key: None,
            retryable,
        }
    }
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for IngestError {}
