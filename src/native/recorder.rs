//! In-process native recorder API.
//!
//! Exit gate: a test harness can produce a complete Blackbox run without
//! invoking `blackbox run` or using a PTY.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::core::event::{EventSource, EventStatus, SideEffect, TraceEvent};
use crate::core::run::{Run, RunStatus};
use crate::pipeline::EventWriter;
use crate::storage::TraceStore;

use super::envelope::{
    IngestAck, IngestError, IngestOp, NativeIngestEnvelope, NATIVE_INGEST_SCHEMA,
};

/// Configuration for a [`NativeRecorder`].
#[derive(Debug, Clone)]
pub struct NativeRecorderConfig {
    /// Max retained idempotency keys (LRU).
    pub max_idempotency_keys: usize,
    /// Default producer tag stored on events.
    pub default_producer: Option<String>,
    /// Max pending uncommitted envelopes when used as a queue (backpressure).
    pub max_pending: usize,
}

impl Default for NativeRecorderConfig {
    fn default() -> Self {
        Self {
            max_idempotency_keys: 50_000,
            default_producer: None,
            max_pending: 10_000,
        }
    }
}

/// Options for starting a native run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StartRunOpts {
    /// Optional fixed run id (else UUID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Human label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Logical command argv (may be empty for pure in-process agents).
    #[serde(default)]
    pub command: Vec<String>,
    /// Working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Project directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_dir: Option<String>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Adapter / harness id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
    /// Session id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Parent run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_run_id: Option<String>,
}

/// Options for recording an event.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecordEventOpts {
    /// Event kind (e.g. `tool.call`).
    pub kind: String,
    /// Capture source (default Harness).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Side effect class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub side_effect: Option<String>,
    /// Parent event id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_event_id: Option<String>,
    /// Structured metadata.
    #[serde(default)]
    pub metadata: HashMap<String, Value>,
    /// Optional fixed event id (for deterministic tests / retries).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Client wall-clock hint (never trusted as sequence order).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_timestamp: Option<String>,
}

/// Options for finishing a run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FinishRunOpts {
    /// Process-style exit code (0 = success).
    #[serde(default)]
    pub exit_code: i32,
    /// Optional status override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Clone)]
struct IdempotentResult {
    run_id: Option<String>,
    event_id: Option<String>,
    sequence: Option<u64>,
}

/// Native in-process recorder backed by a [`TraceStore`].
pub struct NativeRecorder {
    store: Arc<dyn TraceStore>,
    config: NativeRecorderConfig,
    /// run_id → EventWriter
    writers: Mutex<HashMap<String, EventWriter>>,
    /// idempotency_key → prior result (LRU via VecDeque)
    idempotency: Mutex<IdempotencyCache>,
    /// Current pending count for backpressure accounting.
    pending: Mutex<usize>,
}

struct IdempotencyCache {
    map: HashMap<String, IdempotentResult>,
    order: VecDeque<String>,
    max: usize,
}

impl IdempotencyCache {
    fn new(max: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            max: max.max(1),
        }
    }

    fn get(&self, key: &str) -> Option<IdempotentResult> {
        self.map.get(key).cloned()
    }

    fn insert(&mut self, key: String, result: IdempotentResult) {
        if self.map.contains_key(&key) {
            self.map.insert(key, result);
            return;
        }
        while self.order.len() >= self.max {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, result);
    }
}

impl NativeRecorder {
    /// Create a recorder over an existing store.
    pub fn new(store: Arc<dyn TraceStore>) -> Self {
        Self::with_config(store, NativeRecorderConfig::default())
    }

    /// Create with config.
    pub fn with_config(store: Arc<dyn TraceStore>, config: NativeRecorderConfig) -> Self {
        let max = config.max_idempotency_keys;
        Self {
            store,
            config,
            writers: Mutex::new(HashMap::new()),
            idempotency: Mutex::new(IdempotencyCache::new(max)),
            pending: Mutex::new(0),
        }
    }

    /// Access underlying store.
    pub fn store(&self) -> &Arc<dyn TraceStore> {
        &self.store
    }

    /// Apply a wire envelope (shared by NDJSON / Unix transports).
    pub async fn apply_envelope(
        &self,
        env: NativeIngestEnvelope,
    ) -> Result<IngestAck, IngestError> {
        if env.schema != NATIVE_INGEST_SCHEMA {
            return Err(IngestError::new(
                "bad_schema",
                format!("expected {NATIVE_INGEST_SCHEMA}, got {}", env.schema),
                false,
            ));
        }
        if env.idempotency_key.is_empty() {
            return Err(IngestError::new(
                "missing_idempotency_key",
                "idempotency_key is required",
                false,
            ));
        }

        // Duplicate short-circuit.
        {
            let cache = self.idempotency.lock().await;
            if let Some(prev) = cache.get(&env.idempotency_key) {
                let mut ack = IngestAck::new(&env.idempotency_key, true);
                ack.run_id = prev.run_id.clone().or(env.run_id.clone());
                ack.event_id = prev.event_id.clone();
                ack.sequence = prev.sequence;
                return Ok(ack);
            }
        }

        // Backpressure: refuse when too many concurrent applies.
        {
            let mut p = self.pending.lock().await;
            if *p >= self.config.max_pending {
                return Err(IngestError::new(
                    "backpressure",
                    format!("pending operations at limit {}", self.config.max_pending),
                    true,
                ));
            }
            *p += 1;
        }

        let result = self.apply_envelope_inner(env).await;

        {
            let mut p = self.pending.lock().await;
            *p = p.saturating_sub(1);
        }

        result
    }

    async fn apply_envelope_inner(
        &self,
        env: NativeIngestEnvelope,
    ) -> Result<IngestAck, IngestError> {
        let payload = env.payload.clone().unwrap_or_else(|| json!({}));
        match env.op {
            IngestOp::StartRun => {
                let opts: StartRunOpts = serde_json::from_value(payload).map_err(|e| {
                    IngestError::new("bad_payload", e.to_string(), false)
                })?;
                let run = self.start_run(opts).await.map_err(store_err)?;
                self.remember(
                    &env.idempotency_key,
                    IdempotentResult {
                        run_id: Some(run.id.clone()),
                        event_id: None,
                        sequence: None,
                    },
                )
                .await;
                let mut ack = IngestAck::new(&env.idempotency_key, false);
                ack.run_id = Some(run.id);
                Ok(ack)
            }
            IngestOp::FinishRun => {
                let run_id = require_run_id(&env)?;
                let opts: FinishRunOpts = serde_json::from_value(payload).map_err(|e| {
                    IngestError::new("bad_payload", e.to_string(), false)
                })?;
                self.finish_run(&run_id, opts).await.map_err(store_err)?;
                self.remember(
                    &env.idempotency_key,
                    IdempotentResult {
                        run_id: Some(run_id.clone()),
                        event_id: None,
                        sequence: None,
                    },
                )
                .await;
                let mut ack = IngestAck::new(&env.idempotency_key, false);
                ack.run_id = Some(run_id);
                Ok(ack)
            }
            IngestOp::RecordEvent
            | IngestOp::RecordTool
            | IngestOp::RecordModel
            | IngestOp::RecordHandoff
            | IngestOp::RecordApproval
            | IngestOp::RecordSecurityDecision
            | IngestOp::AttachEvidence => {
                let run_id = require_run_id(&env)?;
                let mut opts = event_opts_from_op(env.op, payload)?;
                if let Some(ref producer) = env.producer.or_else(|| self.config.default_producer.clone())
                {
                    opts.metadata
                        .entry("native.producer".into())
                        .or_insert_with(|| Value::String(producer.clone()));
                }
                if let Some(cs) = env.client_seq {
                    opts.metadata
                        .insert("native.client_seq".into(), json!(cs));
                }
                // Harness timestamps are hints only — never drive sequence.
                if let Some(ts) = opts.metadata.remove("client_timestamp") {
                    opts.metadata
                        .insert("native.client_timestamp".into(), ts);
                }
                let (event_id, sequence) = self
                    .record_event(&run_id, opts)
                    .await
                    .map_err(store_err)?;
                self.remember(
                    &env.idempotency_key,
                    IdempotentResult {
                        run_id: Some(run_id.clone()),
                        event_id: Some(event_id.clone()),
                        sequence: Some(sequence),
                    },
                )
                .await;
                let mut ack = IngestAck::new(&env.idempotency_key, false);
                ack.run_id = Some(run_id);
                ack.event_id = Some(event_id);
                ack.sequence = Some(sequence);
                Ok(ack)
            }
            IngestOp::Ack => Ok(IngestAck::new(&env.idempotency_key, false)),
        }
    }

    async fn remember(&self, key: &str, result: IdempotentResult) {
        let mut cache = self.idempotency.lock().await;
        cache.insert(key.to_string(), result);
    }

    /// Start a new run and mark it Running.
    pub async fn start_run(&self, opts: StartRunOpts) -> anyhow::Result<Run> {
        let cwd = opts
            .cwd
            .unwrap_or_else(|| std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_else(|_| "/".into()));
        let mut run = Run::new(
            if opts.command.is_empty() {
                vec!["<native>".into()]
            } else {
                opts.command
            },
            cwd,
        );
        if let Some(id) = opts.run_id {
            run.id = id;
        }
        run.name = opts.name;
        if let Some(pd) = opts.project_dir {
            run.project_dir = pd;
        }
        run.tags = opts.tags;
        run.adapter = opts.adapter.or_else(|| Some("native".into()));
        run.session_id = opts.session_id;
        run.parent_run_id = opts.parent_run_id;
        run.status = RunStatus::Running;

        self.store.insert_run(&run).await?;

        let writer = EventWriter::new(self.store.clone(), run.id.clone());
        // Seed writer sequence from run.
        // EventWriter starts at 0; first write allocates 0.
        self.writers.lock().await.insert(run.id.clone(), writer);

        // Bookkeeping event.
        let mut started = TraceEvent::new(&run.id, EventSource::System, "run.started");
        started.status = EventStatus::Success;
        started.side_effect = SideEffect::None;
        started
            .metadata
            .insert("native".into(), json!(true));
        self.write_event(&run.id, started).await?;

        Ok(run)
    }

    /// Record a structured event on an existing run.
    pub async fn record_event(
        &self,
        run_id: &str,
        opts: RecordEventOpts,
    ) -> anyhow::Result<(String, u64)> {
        if self.store.get_run(run_id).await?.is_none() {
            anyhow::bail!("unknown run_id: {run_id}");
        }
        let source = parse_source(opts.source.as_deref().unwrap_or("harness"));
        let mut ev = TraceEvent::new(run_id, source, &opts.kind);
        if let Some(id) = opts.event_id {
            ev.id = id;
        }
        ev.parent_event_id = opts.parent_event_id;
        if let Some(st) = opts.status.as_deref() {
            ev.status = parse_status(st);
        } else {
            ev.status = EventStatus::Success;
        }
        if let Some(se) = opts.side_effect.as_deref() {
            ev.side_effect = parse_side_effect(se);
        }
        for (k, v) in opts.metadata {
            ev.metadata.insert(k, v);
        }
        if let Some(ts) = opts.client_timestamp {
            ev.metadata
                .insert("native.client_timestamp".into(), Value::String(ts));
        }
        let sequence = self.write_event(run_id, ev.clone()).await?;
        Ok((ev.id, sequence))
    }

    /// Convenience: tool call event.
    pub async fn record_tool(
        &self,
        run_id: &str,
        tool_name: &str,
        input: Option<Value>,
        output: Option<Value>,
        status: EventStatus,
    ) -> anyhow::Result<(String, u64)> {
        let mut metadata = HashMap::new();
        metadata.insert("tool_name".into(), json!(tool_name));
        if let Some(i) = input {
            metadata.insert("input".into(), i);
        }
        if let Some(o) = output {
            metadata.insert("output".into(), o);
        }
        self.record_event(
            run_id,
            RecordEventOpts {
                kind: "tool.call".into(),
                source: Some("tool".into()),
                status: Some(status_str(status).into()),
                side_effect: Some("unknown".into()),
                metadata,
                ..Default::default()
            },
        )
        .await
    }

    /// Convenience: model / completion event.
    pub async fn record_model(
        &self,
        run_id: &str,
        model: Option<&str>,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
    ) -> anyhow::Result<(String, u64)> {
        let mut metadata = HashMap::new();
        if let Some(m) = model {
            metadata.insert("model".into(), json!(m));
        }
        if let Some(i) = input_tokens {
            metadata.insert("input_tokens".into(), json!(i));
        }
        if let Some(o) = output_tokens {
            metadata.insert("output_tokens".into(), json!(o));
        }
        self.record_event(
            run_id,
            RecordEventOpts {
                kind: "model.completion".into(),
                source: Some("harness".into()),
                status: Some("success".into()),
                side_effect: Some("none".into()),
                metadata,
                ..Default::default()
            },
        )
        .await
    }

    /// Record a handoff event.
    pub async fn record_handoff(
        &self,
        run_id: &str,
        summary: Option<&str>,
    ) -> anyhow::Result<(String, u64)> {
        let mut metadata = HashMap::new();
        if let Some(s) = summary {
            metadata.insert("summary".into(), json!(s));
        }
        self.record_event(
            run_id,
            RecordEventOpts {
                kind: "session.handoff".into(),
                source: Some("harness".into()),
                status: Some("success".into()),
                side_effect: Some("none".into()),
                metadata,
                ..Default::default()
            },
        )
        .await
    }

    /// Record an approval event.
    pub async fn record_approval(
        &self,
        run_id: &str,
        approved: bool,
        actor: Option<&str>,
    ) -> anyhow::Result<(String, u64)> {
        let mut metadata = HashMap::new();
        metadata.insert("approved".into(), json!(approved));
        if let Some(a) = actor {
            metadata.insert("actor".into(), json!(a));
        }
        self.record_event(
            run_id,
            RecordEventOpts {
                kind: "approval".into(),
                source: Some("human".into()),
                status: Some("success".into()),
                side_effect: Some("none".into()),
                metadata,
                ..Default::default()
            },
        )
        .await
    }

    /// Record a security decision as a trace event (payload holds decision object).
    pub async fn record_security_decision(
        &self,
        run_id: &str,
        decision: Value,
    ) -> anyhow::Result<(String, u64)> {
        let mut metadata = HashMap::new();
        metadata.insert("decision".into(), decision);
        self.record_event(
            run_id,
            RecordEventOpts {
                kind: "security.decision".into(),
                source: Some("system".into()),
                status: Some("success".into()),
                side_effect: Some("none".into()),
                metadata,
                ..Default::default()
            },
        )
        .await
    }

    /// Attach external evidence reference (metadata pointer; full import via evidence module).
    pub async fn attach_evidence(
        &self,
        run_id: &str,
        evidence_id: &str,
        source: Option<&str>,
    ) -> anyhow::Result<(String, u64)> {
        let mut metadata = HashMap::new();
        metadata.insert("evidence_id".into(), json!(evidence_id));
        if let Some(s) = source {
            metadata.insert("evidence_source".into(), json!(s));
        }
        self.record_event(
            run_id,
            RecordEventOpts {
                kind: "evidence.attached".into(),
                source: Some("system".into()),
                status: Some("success".into()),
                side_effect: Some("none".into()),
                metadata,
                ..Default::default()
            },
        )
        .await
    }

    /// Finish a run.
    pub async fn finish_run(&self, run_id: &str, opts: FinishRunOpts) -> anyhow::Result<Run> {
        let mut run = self
            .store
            .get_run(run_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("unknown run_id: {run_id}"))?;

        // Emit run.ended before status update so sequence includes it.
        let mut ended = TraceEvent::new(run_id, EventSource::System, "run.ended");
        ended.status = if opts.exit_code == 0 {
            EventStatus::Success
        } else {
            EventStatus::Error
        };
        ended.side_effect = SideEffect::None;
        ended
            .metadata
            .insert("exit_code".into(), json!(opts.exit_code));
        self.write_event(run_id, ended).await?;

        run.finish(opts.exit_code);
        if let Some(st) = opts.status.as_deref() {
            run.status = parse_run_status(st);
        }
        if let Some(notes) = opts.notes {
            run.notes = Some(notes);
        }
        // Refresh next_sequence from writer if present.
        if let Some(w) = self.writers.lock().await.get(run_id) {
            // next sequence is events_written when using simple writer; best-effort
            let health = w.health_snapshot();
            run.next_sequence = health.events_written;
        }
        self.store.update_run(&run).await?;
        self.writers.lock().await.remove(run_id);
        Ok(run)
    }

    async fn write_event(&self, run_id: &str, event: TraceEvent) -> anyhow::Result<u64> {
        // Ensure writer exists (run may have been started earlier in process).
        let written = {
            let mut writers = self.writers.lock().await;
            if !writers.contains_key(run_id) {
                writers.insert(
                    run_id.to_string(),
                    EventWriter::new(self.store.clone(), run_id.to_string()),
                );
            }
            let writer = writers.get_mut(run_id).expect("writer just inserted");
            writer.write(event).await?
        };
        Ok(written.sequence)
    }
}

fn require_run_id(env: &NativeIngestEnvelope) -> Result<String, IngestError> {
    env.run_id
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| IngestError::new("missing_run_id", "run_id is required for this op", false))
}

fn store_err(e: anyhow::Error) -> IngestError {
    let msg = e.to_string();
    let retryable = msg.contains("backpressure") || msg.contains("locked");
    IngestError::new("store_error", msg, retryable)
}

fn event_opts_from_op(op: IngestOp, payload: Value) -> Result<RecordEventOpts, IngestError> {
    match op {
        IngestOp::RecordEvent => serde_json::from_value(payload)
            .map_err(|e| IngestError::new("bad_payload", e.to_string(), false)),
        IngestOp::RecordTool => {
            let tool_name = payload
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let mut metadata = HashMap::new();
            metadata.insert("tool_name".into(), json!(tool_name));
            if let Some(i) = payload.get("input") {
                metadata.insert("input".into(), i.clone());
            }
            if let Some(o) = payload.get("output") {
                metadata.insert("output".into(), o.clone());
            }
            Ok(RecordEventOpts {
                kind: payload
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("tool.call")
                    .into(),
                source: Some("tool".into()),
                status: payload
                    .get("status")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                metadata,
                event_id: payload
                    .get("event_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                ..Default::default()
            })
        }
        IngestOp::RecordModel => {
            let mut metadata = HashMap::new();
            if let Some(m) = payload.get("model") {
                metadata.insert("model".into(), m.clone());
            }
            if let Some(i) = payload.get("input_tokens") {
                metadata.insert("input_tokens".into(), i.clone());
            }
            if let Some(o) = payload.get("output_tokens") {
                metadata.insert("output_tokens".into(), o.clone());
            }
            Ok(RecordEventOpts {
                kind: "model.completion".into(),
                source: Some("harness".into()),
                status: Some("success".into()),
                side_effect: Some("none".into()),
                metadata,
                ..Default::default()
            })
        }
        IngestOp::RecordHandoff => {
            let mut metadata = HashMap::new();
            if let Some(s) = payload.get("summary") {
                metadata.insert("summary".into(), s.clone());
            }
            Ok(RecordEventOpts {
                kind: "session.handoff".into(),
                source: Some("harness".into()),
                status: Some("success".into()),
                metadata,
                ..Default::default()
            })
        }
        IngestOp::RecordApproval => {
            let mut metadata = HashMap::new();
            if let Some(a) = payload.get("approved") {
                metadata.insert("approved".into(), a.clone());
            }
            if let Some(a) = payload.get("actor") {
                metadata.insert("actor".into(), a.clone());
            }
            Ok(RecordEventOpts {
                kind: "approval".into(),
                source: Some("human".into()),
                status: Some("success".into()),
                metadata,
                ..Default::default()
            })
        }
        IngestOp::RecordSecurityDecision => {
            let mut metadata = HashMap::new();
            metadata.insert("decision".into(), payload);
            Ok(RecordEventOpts {
                kind: "security.decision".into(),
                source: Some("system".into()),
                status: Some("success".into()),
                side_effect: Some("none".into()),
                metadata,
                ..Default::default()
            })
        }
        IngestOp::AttachEvidence => {
            let mut metadata = HashMap::new();
            if let Some(id) = payload.get("evidence_id") {
                metadata.insert("evidence_id".into(), id.clone());
            } else {
                metadata.insert("evidence_id".into(), json!(Uuid::new_v4().to_string()));
            }
            if let Some(s) = payload.get("source") {
                metadata.insert("evidence_source".into(), s.clone());
            }
            Ok(RecordEventOpts {
                kind: "evidence.attached".into(),
                source: Some("system".into()),
                status: Some("success".into()),
                metadata,
                ..Default::default()
            })
        }
        _ => Err(IngestError::new(
            "bad_op",
            "operation is not an event record op",
            false,
        )),
    }
}

fn parse_source(s: &str) -> EventSource {
    match s.to_ascii_lowercase().as_str() {
        "human" => EventSource::Human,
        "harness" => EventSource::Harness,
        "terminal" => EventSource::Terminal,
        "process" => EventSource::Process,
        "filesystem" | "fs" => EventSource::Filesystem,
        "git" => EventSource::Git,
        "tool" => EventSource::Tool,
        "network" => EventSource::Network,
        "browser" => EventSource::Browser,
        "system" => EventSource::System,
        _ => EventSource::Harness,
    }
}

fn parse_status(s: &str) -> EventStatus {
    match s.to_ascii_lowercase().as_str() {
        "pending" => EventStatus::Pending,
        "running" => EventStatus::Running,
        "success" | "succeeded" | "ok" => EventStatus::Success,
        "error" | "failed" | "fail" => EventStatus::Error,
        "cancelled" | "canceled" => EventStatus::Cancelled,
        _ => EventStatus::Unknown,
    }
}

fn parse_side_effect(s: &str) -> SideEffect {
    match s.to_ascii_lowercase().as_str() {
        "none" => SideEffect::None,
        "read" => SideEffect::Read,
        "local-write" | "local_write" => SideEffect::LocalWrite,
        "external-write" | "external_write" => SideEffect::ExternalWrite,
        "destructive" => SideEffect::Destructive,
        _ => SideEffect::Unknown,
    }
}

fn parse_run_status(s: &str) -> RunStatus {
    match s.to_ascii_lowercase().as_str() {
        "pending" => RunStatus::Pending,
        "running" => RunStatus::Running,
        "succeeded" | "success" => RunStatus::Succeeded,
        "failed" | "fail" | "error" => RunStatus::Failed,
        "cancelled" | "canceled" => RunStatus::Cancelled,
        _ => RunStatus::Unknown,
    }
}

fn status_str(s: EventStatus) -> &'static str {
    match s {
        EventStatus::Pending => "pending",
        EventStatus::Running => "running",
        EventStatus::Success => "success",
        EventStatus::Error => "error",
        EventStatus::Cancelled => "cancelled",
        EventStatus::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::store::InMemoryStore;

    #[tokio::test]
    async fn complete_run_without_pty() {
        let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
        let rec = NativeRecorder::new(store.clone());
        let run = rec
            .start_run(StartRunOpts {
                name: Some("native-test".into()),
                command: vec!["agent".into()],
                cwd: Some("/tmp".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        rec.record_tool(&run.id, "bash", Some(json!({"cmd": "ls"})), None, EventStatus::Success)
            .await
            .unwrap();
        rec.record_model(&run.id, Some("test-model"), Some(10), Some(20))
            .await
            .unwrap();
        rec.record_approval(&run.id, true, Some("user"))
            .await
            .unwrap();
        let finished = rec
            .finish_run(
                &run.id,
                FinishRunOpts {
                    exit_code: 0,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(finished.status, RunStatus::Succeeded);
        let events = store.get_events(&run.id).await.unwrap();
        assert!(events.len() >= 5, "got {} events", events.len());
        assert!(events.iter().any(|e| e.kind == "run.started"));
        assert!(events.iter().any(|e| e.kind == "tool.call"));
        assert!(events.iter().any(|e| e.kind == "run.ended"));
        // Sequences are monotonic (EventWriter starts at 1).
        let seqs: Vec<u64> = events.iter().map(|e| e.sequence).collect();
        let mut sorted = seqs.clone();
        sorted.sort();
        assert_eq!(seqs, sorted);
        assert_eq!(seqs[0], 1);
    }

    #[tokio::test]
    async fn idempotent_retry() {
        let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
        let rec = NativeRecorder::new(store.clone());
        let start = NativeIngestEnvelope::new(IngestOp::StartRun, "start-1")
            .with_payload(json!({"cwd": "/tmp", "command": ["x"]}));
        let a1 = rec.apply_envelope(start.clone()).await.unwrap();
        let a2 = rec.apply_envelope(start).await.unwrap();
        assert!(!a1.duplicate);
        assert!(a2.duplicate);
        assert_eq!(a1.run_id, a2.run_id);
        assert_eq!(store.list_runs().await.unwrap().len(), 1);

        let run_id = a1.run_id.unwrap();
        let env = NativeIngestEnvelope::new(IngestOp::RecordTool, "tool-1")
            .with_run_id(&run_id)
            .with_payload(json!({"tool_name": "read", "input": {"path": "a"}}));
        let e1 = rec.apply_envelope(env.clone()).await.unwrap();
        let e2 = rec.apply_envelope(env).await.unwrap();
        assert!(!e1.duplicate && e2.duplicate);
        assert_eq!(e1.event_id, e2.event_id);
        // Only one tool event (+ run.started).
        let events = store.get_events(&run_id).await.unwrap();
        assert_eq!(
            events.iter().filter(|e| e.kind == "tool.call").count(),
            1
        );
    }

    #[tokio::test]
    async fn client_timestamp_does_not_reorder_sequence() {
        let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
        let rec = NativeRecorder::new(store.clone());
        let run = rec
            .start_run(StartRunOpts {
                cwd: Some("/tmp".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        // Later client timestamp first.
        rec.record_event(
            &run.id,
            RecordEventOpts {
                kind: "a".into(),
                client_timestamp: Some("2099-01-01T00:00:00Z".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        rec.record_event(
            &run.id,
            RecordEventOpts {
                kind: "b".into(),
                client_timestamp: Some("2000-01-01T00:00:00Z".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let events = store.get_events(&run.id).await.unwrap();
        let a = events.iter().find(|e| e.kind == "a").unwrap();
        let b = events.iter().find(|e| e.kind == "b").unwrap();
        assert!(a.sequence < b.sequence);
    }
}
