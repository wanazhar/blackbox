# Blackbox Architecture

> **Contributor / deep-dive documentation.** Operators: [../guide/README.md](../guide/README.md). System model without module names: [../guide/concepts.md](../guide/concepts.md).

How modules connect, where events are sequenced, how the store is shaped, and where continuity sits relative to capture.

**Blackbox** is a Rust flight recorder and debugger for AI-agent runs. It launches agent commands (Claude, Codex, or generic), captures terminal output and structured events via PTY supervision, stores traces in SQLite + content-addressed blobs, and provides CLI, TUI, and a local web dashboard for inspection.

| | |
|---|---|
| Source | <https://github.com/wanazhar/blackbox> |
| crates.io | `blackbox-recorder` (binary/lib path: `blackbox`) |
| Edition | 2021, stable Rust |

### Map to other internals

| Question | Doc |
|---|---|
| How do layers merge and redact? | [capture-pipeline.md](capture-pipeline.md) |
| SQLite schema / blobs / FTS / GC? | [storage.md](storage.md) |
| Sticky state, MEMORY, claims, inject? | [continuity-plane.md](continuity-plane.md) |
| Repo conventions for PRs? | [AGENTS.md](https://github.com/wanazhar/blackbox/blob/master/AGENTS.md) |

---

## 1. High-Level Architecture

Blackbox is a layered event pipeline: **capture → sequence → persist → analyze → serve**. The universal data model is `TraceEvent`.


```
┌─────────────────────────────────────────────────────────────────────────┐
│                              CLI (clap)                                 │
│   run │ runs │ show │ timeline │ inspect │ export │ import │ replay    │
│   fork │ analyze │ scrub │ search │ serve │ sync │ status │ handoff    │
└───────────────────────┬─────────────────────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         RunSupervisor                                    │
│  ┌──────────────┐  ┌──────────┐  ┌────────────┐  ┌──────────────────┐  │
│  │  PTY Capture  │  │ Git      │  │ Filesystem │  │  Process         │  │
│  │  (portable-   │  │ Capture  │  │ Capture    │  │  Capture         │  │
│  │   pty)        │  │          │  │ (notify)   │  │                  │  │
│  └──────┬───────┘  └────┬─────┘  └─────┬──────┘  └───────┬──────────┘  │
│         │               │              │                  │             │
│         └───────────────┴──────────────┴──────────────────┘             │
│                                    │                                    │
│                            merge_layers()                               │
│                                    │                                    │
│                                    ▼                                    │
│                    ┌───────────────────────────┐                        │
│                    │    EventWriter             │                       │
│                    │   · monotonic sequence     │                       │
│                    │   · dedup (tool.call/rsp)  │                       │
│                    │   · persist to store       │                       │
│                    └───────────┬───────────────┘                        │
│                                │                                        │
│                    ┌───────────▼───────────────┐                        │
│                    │     SqliteStore            │                       │
│                    │   · SQLite metadata        │                       │
│                    │   · FTS5 full-text search  │                       │
│                    │   · Content-addressed      │                       │
│                    │     blobs (.blackbox/blobs) │                      │
│                    └───────────────────────────┘                        │
└──────────────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼────────────────────┐
          │                   │                    │
          ▼                   ▼                    ▼
┌─────────────────┐  ┌──────────────┐  ┌─────────────────────┐
│  Analysis Passes│  │  Axum Serve  │  │  Sync Engine        │
│ · ErrorDetector │  │ · Dashboard  │  │ · Directory (files) │
│ · SideEffectCls │  │ · JSON API   │  │ · HTTP (serve peer) │
│ · EventCorrelat │  │ · SSE streams│  │ · S3 (object store) │
└─────────────────┘  └──────────────┘  └─────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                      Continuity Plane (1.2)                              │
│  ┌─────────┐  ┌──────────────┐  ┌───────────┐  ┌────────────────────┐  │
│  │ Sticky  │  │ ProjectState │  │ Project   │  │ ResumeInject       │  │
│  │ State   │  │ · intent     │  │ MemoryPack│  │ · env vars         │  │
│  │ (state. │  │ · claims     │  │ (blackbox │  │ · prompt prepend   │  │
│  │ lock)   │  │ · attention  │  │ .memory/  │  │ · parent_run_id    │  │
│  └─────────┘  └──────────────┘  │ v1)       │  └────────────────────┘  │
│                                 └───────────┘                          │
└──────────────────────────────────────────────────────────────────────────┘
```



### Data Flow (Record Mode)

```
CLI parse → open store → RunSupervisor.execute()
     │
     ├── 1. Create Run (status=Running), persist to store
     ├── 2. Start capture layers (PTY, Git, FS, Process)
     │        Each layer opens an mpsc::channel
     ├── 3. merge_layers() → single merged receiver
     ├── 4. Create EventWriter (per-run seq counter)
     ├── 5. Fork reader task: drain merged receiver → EventWriter.write()
     ├── 6. Spawn child process in portable_pty::PtyPair
     ├── 7. Reader loop:
     │        PTY stdout → RawRecorder → AnsiNormalizer
     │          → redaction → blob → adapter parse → EventWriter
     ├── 8. On exit:
     │        Stop layers → flush remaining events
     │        → write Checkpoint (git diff, fs manifest, env)
     │        → update Run (status, exit_code, duration)
     │        → apply state outcome → refresh memory files
     │        → print handoff hint
     └── 9. Return Run to caller
```

### Data Flow (Maybe-Run / Ambient Mode)

```
Shell wrapper → `blackbox maybe-run -- <command>`
     │
     ├── decide(): check BLACKBOX_OFF, BLACKBOX_ACTIVE_RUN,
     │             project config enabled, basename in wrap list
     │
     ├── Passthrough → exec() the bare command (no store touched)
     └── Record → build RunArgs → RunSupervisor.execute() (same flow as above)
```

---

## 2. Core Data Model

All data lives in four primary structs defined in `src/core/`.

### 2.1 TraceEvent

The universal trace substrate. Every observable thing that happens during a run becomes a `TraceEvent`.

| Field | Type | Description |
|---|---|---|
| `id` | `String` | UUID v4 |
| `run_id` | `String` | Foreign key to `Run` |
| `parent_event_id` | `Option<String>` | For causal chains (tool.call → tool.result) |
| `sequence` | `u64` | Monotonic per-run, assigned by `EventWriter` |
| `source` | `EventSource` | Enum: `Human`, `Harness`, `Terminal`, `Process`, `Filesystem`, `Git`, `Tool`, `Network`, `Browser`, `System` |
| `kind` | `String` | Event type string, e.g. `"tool.call"`, `"tool.result"`, `"terminal.output"`, `"filesystem.write"` |
| `status` | `EventStatus` | Enum: `Pending`, `Running`, `Success`, `Error`, `Cancelled`, `Unknown` |
| `timestamp` | `DateTime<Utc>` | Creation timestamp |
| `metadata` | `HashMap<String, Value>` | Flexible key-value bag; holds previews, tool names, paths, etc. |
| `output` | `Option<String>` | Short preview only; large payloads use `output_blob` |
| `input_blob` | `Option<String>` | Blob key for large input payloads (schema v6) |
| `output_blob` | `Option<String>` | Blob key for large output payloads (terminal raw, tool results) |
| `error_blob` | `Option<String>` | Blob key for error payloads (schema v6) |
| `error` | `Option<String>` | Error text if applicable |
| `side_effect` | `SideEffect` | Enum: `None`, `Read`, `LocalWrite`, `ExternalWrite`, `Destructive`, `Unknown` |
| `started_at` | `Option<DateTime<Utc>>` | When the event started (for spans) |
| `ended_at` | `Option<DateTime<Utc>>` | When the event ended |
| `duration_ms` | `Option<u64>` | Wall-clock duration |
| `total_redactions` | `Option<u32>` | Count of redactions applied |
| `redacted_ranges` | `Option<Vec<[u64; 2]>>` | Byte ranges redacted (for audit) |
| `confidence` | `Option<Confidence>` | Parsing confidence when inferred from PTY |

**Key design rules:**

- Large payloads always go through `output_blob` / `input_blob` / `error_blob` (SHA-256 content-addressed keys). The `output` field holds only short previews.
- The `kind` field is an open string, not an enum. This allows adapters and analysis passes to introduce new event kinds without changing the core model.
- `metadata` is the extensibility point — every subsystem can attach structured data here.




### 2.2 Run

One recorded session. Created at launch, finalized on exit.

| Field | Type | Description |
|---|---|---|
| `id` | `String` | UUID v4 |
| `name` | `Option<String>` | Human-readable label |
| `command` | `Vec<String>` | Command and arguments (redacted at rest by default) |
| `cwd` | `String` | Working directory at launch |
| `project_dir` | `String` | Project root (may differ from cwd with `--project`) |
| `tags` | `Vec<String>` | Free-form tags for filtering |
| `notes` | `Option<String>` | Structured notes (`"; "`-joined segments, e.g. `adapter:claude; session:sess-1`) |
| `status` | `RunStatus` | Enum: `Pending`, `Running`, `Succeeded`, `Failed`, `Cancelled`, `Unknown` |
| `started_at` | `DateTime<Utc>` | Launch time |
| `ended_at` | `Option<DateTime<Utc>>` | Finish time |
| `exit_code` | `Option<i32>` | Process exit code |
| `parent_run_id` | `Option<String>` | Parent run if forked |
| `next_sequence` | `u64` | Monotonic event sequence counter |
| `duration_ms` | `Option<u64>` | Wall-clock duration (schema v6) |
| `adapter` | `Option<String>` | Detected harness: `"claude"`, `"codex"`, `"generic"` |
| `session_id` | `Option<String>` | Harness session identifier |
| `input_tokens` | `Option<u64>` | Total prompt tokens consumed |
| `output_tokens` | `Option<u64>` | Total completion tokens produced |
| `total_tokens` | `Option<u64>` | Sum of input + output |
| `estimated_cost_usd` | `Option<f64>` | Estimated cost (requires explicit pricing config) |
| `model` | `Option<String>` | Model identifier (e.g. `"claude-sonnet-4-20250514"`) |

### 2.3 Checkpoint

A point-in-time snapshot of observable state. Created at meaningful boundaries: before harness starts, before side effects, after file modification batches, at agent completion, and before forks.

| Field | Type | Description |
|---|---|---|
| `id` | `String` | UUID v4 |
| `run_id` | `String` | Foreign key to Run |
| `event_id` | `String` | Event that triggered this checkpoint |
| `git_commit` | `Option<String>` | Git commit hash at checkpoint time |
| `git_diff_blob` | `Option<String>` | Blob key for uncommitted diff |
| `filesystem_manifest_blob` | `Option<String>` | Blob key for file listing |
| `cwd` | `String` | Working directory |
| `environment_blob` | `Option<String>` | Blob key for environment snapshot |
| `transcript_blob` | `Option<String>` | Blob key for terminal transcript |
| `harness_session_id` | `Option<String>` | Adapter session identifier |
| `created_at` | `DateTime<Utc>` | Timestamp |

### 2.4 BlobReference

Content-addressed reference to a stored payload.

| Field | Type | Description |
|---|---|---|
| `key` | `String` | SHA-256 hex digest |
| `size` | `u64` | Uncompressed size in bytes |
| `compressed` | `bool` | Whether stored compressed |
| `content_type` | `Option<String>` | MIME type hint |

Blobs are stored as individual files at `.blackbox/blobs/<sha256_hex>`. The SHA-256 hash provides deduplication (identical content maps to the same key) and integrity verification.



---

## 3. Capture Pipeline

The capture pipeline converts raw PTY output and system observations into structured `TraceEvent` values.

### 3.1 CaptureLayer Trait

```rust
#[async_trait]
pub trait CaptureLayer: Send + 'static {
    fn name(&self) -> &'static str;
    async fn start(&mut self, run: &Run) -> Result<mpsc::Receiver<TraceEvent>>;
    async fn stop(&mut self) -> Result<()>;
}
```

Each layer is independent. They are started in `RunSupervisor` and their channels merged via `merge_layers()`.

#### Implementations

| Layer | File | Purpose |
|---|---|---|
| `PtyCapture` | `src/capture/pty.rs` | PTY lifecycle events (`pty.started`, `pty.stopped`) |
| `GitCapture` | `src/capture/git.rs` | Pre/post-run git commit + diff snapshots |
| `FilesystemCapture` | `src/capture/filesystem.rs` | Live `notify` watcher; creates/modified/deleted events + manifest snapshots |
| `ProcessCapture` | `src/capture/process.rs` | Process lifecycle events (`process.spawned`, `process.observer.started/stopped`) |

### 3.2 Terminal I/O Pipeline (PTY)

The most complex pipeline. Within `RunSupervisor.execute_inner()`:

```
portable_pty::PtyPair
    │ reader (stdout)
    ▼
RawRecorder (src/terminal/recorder.rs)
    │ Captures raw byte stream with timing
    ▼
AnsiNormalizer (src/terminal/ansi.rs)
    │ Strips ANSI escape sequences, produces clean text
    ▼
TerminalCoalescer (src/terminal/coalesce.rs)
    │ Merges rapid-fire output into bounded segments
    │ (CoalescePolicy: max_lines, max_bytes, max_interval_ms)
    ▼
Redaction (SecretScanner)
    │ Scans for API keys, tokens, credentials, etc.
    │ Configurable via RedactionConfig (enabled by default)
    ▼
Blob storage (SqliteStore.store_blob)
    │ Large payloads → SHA-256 content-addressed blob file
    │ Short preview → event.metadata["preview"]
    ▼
Adapter parser (HarnessAdapter::parse_event)
    │ Claude/Codex/Generic: parse structured tool calls from terminal output
    ▼
EventWriter.write()
    │ Assigns sequence → inserts into store
```

### 3.3 Native Log Pollers

In addition to PTY parsing, each adapter may poll native log files that the harness writes independently. This provides a second source of structured events that enables deduplication in `EventWriter`.

- **Claude:** polls `~/.claude/logs/*.jsonl`
- **Codex:** polls Codex session files
- **Generic:** not applicable

### 3.4 Adapter Harness Detection

`HarnessAdapter::detect(run)` inspects the command to identify the harness type.

| Adapter | Module | Detection | Parse Strategy |
|---|---|---|---|
| `ClaudeAdapter` | `src/adapters/claude/` | Command contains `claude` | Parse tool_use blocks from terminal output |
| `CodexAdapter` | `src/adapters/codex/` | Command contains `codex` | Parse Codex structured output |
| `GenericAdapter` | `src/adapters/generic/` | Fallback | Pass-through terminal output only |

---

## 4. Storage Layer

### 4.1 Architecture

```
.blackbox/
├── config.toml          # Project configuration (optional)
├── state.json           # Sticky project state (v2)
├── state.lock           # flock-based exclusive lock
├── MEMORY.json          # Project memory pack (1.2)
├── RESUME.md            # Resume context markdown (1.1 compat)
├── blackbox.db          # SQLite database (metadata + FTS)
├── blackbox.db-wal      # SQLite WAL journal
├── blackbox.db-shm      # SQLite shared memory
└── blobs/               # Content-addressed blob store
    └── <sha256_hex>     # Individual blob files
```

### 4.2 TraceStore Trait

```rust
#[async_trait]
pub trait TraceStore: Send + Sync + 'static {
    // Runs
    async fn insert_run(&self, run: &Run) -> Result<()>;
    async fn update_run(&self, run: &Run) -> Result<()>;
    async fn get_run(&self, run_id: &str) -> Result<Option<Run>>;
    async fn list_runs(&self) -> Result<Vec<Run>>;
    async fn delete_run(&self, run_id: &str) -> Result<bool>;

    // Events
    async fn insert_event(&self, event: &TraceEvent) -> Result<()>;
    async fn get_events(&self, run_id: &str) -> Result<Vec<TraceEvent>>;
    async fn get_events_limited(&self, run_id: &str, limit: usize) -> Result<(Vec<TraceEvent>, bool)>;
    async fn get_event(&self, event_id: &str) -> Result<Option<TraceEvent>>;
    async fn update_event(&self, event: &TraceEvent) -> Result<()>;
    async fn count_events(&self, run_id: &str) -> Result<usize>;
    async fn insert_events_batch(&self, events: &[TraceEvent]) -> Result<()>;

    // Checkpoints
    async fn insert_checkpoint(&self, cp: &Checkpoint) -> Result<()>;
    async fn get_checkpoints(&self, run_id: &str) -> Result<Vec<Checkpoint>>;

    // Blobs
    async fn store_blob(&self, data: &[u8]) -> Result<BlobReference>;
    async fn load_blob(&self, reference: &BlobReference) -> Result<Vec<u8>>;
    async fn move_blob(&self, from_key: &str, to_key: &str) -> Result<()>;

    // Search
    async fn fts_event_ids(&self, query: &str, limit: usize) -> Result<Option<Vec<(String, String, f64)>>>;

    // GC
    async fn all_blob_keys(&self) -> Result<Vec<String>>;
    async fn delete_blob_keys(&self, keys: &[String]) -> Result<usize>;
}
```

### 4.3 SqliteStore

The primary implementation (`src/storage/sqlite.rs`). Current schema version: **6**.

**Implementation details:**

- **Concurrency:** Single `parking_lot::Mutex<Connection>` serializes all SQLite access. This avoids `SQLITE_BUSY` races without connection pooling. Acceptable for CLI + single-user dashboard.
- **WAL mode:** `PRAGMA journal_mode=WAL` for concurrent reads during writes.
- **Atomics:** `unchecked_transaction()` wraps multi-step operations.
- **FTS5:** Full-text search over events using a virtual FTS5 table. Queries use BM25 ranking.
- **Blobs:** Files stored at `.blackbox/blobs/<sha256_hex>`. `store_blob` hashes content, checks for existing file (dedup), writes if missing, records in `blobs` metadata table.

**Schema (simplified):**

```sql
CREATE TABLE runs (
    id TEXT PRIMARY KEY,
    name TEXT, command TEXT NOT NULL, cwd TEXT NOT NULL,
    project_dir TEXT NOT NULL, tags TEXT NOT NULL DEFAULT '[]',
    notes TEXT, status TEXT NOT NULL,
    started_at TEXT NOT NULL, ended_at TEXT,
    exit_code INTEGER, parent_run_id TEXT,
    next_sequence INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER, adapter TEXT, session_id TEXT,
    input_tokens INTEGER, output_tokens INTEGER,
    total_tokens INTEGER, estimated_cost_usd REAL, model TEXT
);

CREATE TABLE events (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    parent_event_id TEXT, sequence INTEGER NOT NULL,
    source TEXT NOT NULL, kind TEXT NOT NULL,
    started_at TEXT NOT NULL, ended_at TEXT, duration_ms INTEGER,
    status TEXT NOT NULL, side_effect TEXT NOT NULL,
    input_blob TEXT, output_blob TEXT, error_blob TEXT,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE checkpoints (
    id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
    event_id TEXT NOT NULL, git_commit TEXT, git_diff_blob TEXT,
    filesystem_manifest_blob TEXT, cwd TEXT NOT NULL,
    environment_blob TEXT, transcript_blob TEXT,
    harness_session_id TEXT, created_at TEXT NOT NULL
);

CREATE TABLE blobs (
    key TEXT PRIMARY KEY, size INTEGER NOT NULL,
    compressed INTEGER NOT NULL DEFAULT 0, content_type TEXT
);

CREATE VIRTUAL TABLE events_fts USING fts5(
    run_id, event_id, kind, metadata, status, side_effect,
    content='events', content_rowid='rowid'
);
```

### 4.4 Store Recovery

Opening the store recovers abandoned `Running` runs:

1. On `SqliteStore::open()`, query all runs with `status = 'Running'`
2. For each, set `status = 'Failed'`, `ended_at = now()`, append recovery note
3. Log each recovered run at `WARN` level

This ensures crash-consistency — a killed `blackbox run` always produces a visible (failed) record.

### 4.5 Search

Full-text search (`src/search.rs`) has two backends:

1. **FTS5 (preferred):** Queries the `events_fts` virtual table for BM25-ranked results
2. **Linear scan (fallback):** Scans events in memory when FTS5 is unavailable

Run-level search always uses a linear scan of run metadata (command, name, tags, notes).

### 4.6 GC / Scrubbing

- **Scrub (`src/scrub.rs`):** Re-applies redaction to all historical events and blobs. Used for at-rest security cleanup. Rewrites blobs when secrets are found.
- **Blob GC (`gc_unreferenced_blobs`):** Removes blob files and metadata rows that are no longer referenced by any event or checkpoint. Called by `scrub` and `purge` operations.



---

## 5. Continuity Plane (1.2 Agent Memory Bus)

The continuity plane is a set of mechanisms that enable agents to maintain context across runs. It is the primary feature of version 1.2.

> **Note:** This section provides a high-level overview. The full design is documented in `docs/plan/agent-memory-bus-1.2.md` and the implementation is spread across `src/state.rs`, `src/memory.rs`, `src/resume_inject.rs`, and `src/status.rs`.

### 5.1 Sticky State (`src/state.rs`)

Persistent project state written after each run at `.blackbox/state.json` (schema `blackbox.state/v2`).

| Component | Description |
|---|---|
| `last_run` | `RunPointer` for the most recent run |
| `last_failure` | `RunPointer` for the most recent failed run |
| `intent` | `IntentState` — current goal, plan summary, open items, do-not-retry list |
| `attention_level` | `AttentionLevel` enum: `None`, `Info`, `Continue`, `Blocked` |
| `attention_reason` | Human-readable reason for attention |
| `unresolved_failure_id` | Run ID of the last failure that hasn't been addressed |
| `active_claim` | `ClaimPointer` for the current agent holding the project lock |

**State lock:** A `flock`-based exclusive lock (`state.lock`) serializes all read-modify-write operations on `state.json`. This prevents race conditions when multiple agent processes operate in the same project.

**Claims:** Exclusive agent claims prevent concurrent agent sessions. Acquire (`claim_acquire`) is exclusive per project; release (`claim_release`) frees the lock. A claim has a holder, holder kind (e.g., "claude", "codex"), expiry, and optional goal/run association.

### 5.2 Project Memory Pack (`src/memory.rs`)

A self-contained, token-bounded JSON document (schema `blackbox.memory/v1`) that captures:

- Project intent (goal, plan, open items)
- Last run(s) with status and outcomes
- Git branch, dirty state, head commit
- Files touched and destructive paths
- Failed tools with error details
- Side effect summary
- Secret redaction count
- Transcript tail (terminal output preview)
- Summary and tool call history
- Claims information
- Resume command

Key properties:
- **Bounded:** Hard-cap at `max_tokens` (default 4000), with priority-based shrinking (transcript drops first, then side effects, then failed tools)
- **Degradable:** Git porcelain has a 500ms timeout; total build degrades after 2000ms
- **Designed for injection:** The pack is written to `.blackbox/MEMORY.json` and injected into the next agent's prompt

### 5.3 Resume Injection (`src/resume_inject.rs`)

On the next `blackbox run -- <command>`, the system:

1. Checks the `ContinuityMode` (Off, Attention, Always)
2. Builds a `ProjectMemoryPack` from sticky state + store
3. Prepares a `ResumeInjection` with memory file path + preamble text
4. Injects via:
   - **Environment variables:** `BLACKBOX_MEMORY_FILE`, `BLACKBOX_RESUME_FILE`, `BLACKBOX_RESUME_RUN_ID`, `BLACKBOX_CONTINUITY`
   - **Prompt prepending:** For Claude (`-p` flag), Codex (`exec` command), Aider/Gemini/Grok (last argument)

The `parent_run_id` is set when attention ≥ Continue, enabling the agent to trace the chain of runs.

### 5.4 Continuity Modes

| Mode | Behavior |
|---|---|
| `Off` | No memory injection, no state tracking |
| `Attention` | Inject only when attention ≥ Continue (failure or WIP) |
| `Always` | Inject memory on every launch |



---

## 6. Key Traits and Design Patterns

### 6.1 Traits

| Trait | File | Purpose | Methods |
|---|---|---|---|
| `CaptureLayer` | `src/capture/mod.rs` | Observed dimension of harness activity | `name()`, `start()`, `stop()` |
| `TraceStore` | `src/storage/mod.rs` | Storage backend abstraction | Runs, Events, Checkpoints, Blobs, FTS, GC |
| `AnalysisPass` | `src/analysis/mod.rs` | Post-hoc event analysis | `name()`, `analyze()` |
| `ReplayEngine` | `src/replay/mod.rs` | Run replay strategy | `name()`, `start()` |
| `HarnessAdapter` | `src/adapters/harness.rs` | Agent harness detection + parsing | `detect()`, `parse_event()`, `launch_command()` |
| `TerminalRecorder` | `src/terminal/mod.rs` | Terminal I/O capture | `start()`, `write_input()`, `record_output()`, `stop()` |
| `Panel` | `src/ui/mod.rs` | TUI renderable panel | `render()`, `handle_input()` |

### 6.2 Design Patterns

| Pattern | Usage |
|---|---|
| **Trait objects with `#[async_trait]`** | All major traits use `dyn Trait` + `#[async_trait]` for polymorphism. `CaptureLayer`, `TraceStore`, `AnalysisPass`, `ReplayEngine`, `HarnessAdapter` are all async trait objects. |
| **mpsc channels for event streaming** | Capture layers produce events into `tokio::sync::mpsc` channels. `merge_layers()` merges multiple channels into one using tokio::spawn forwarding tasks. |
| **Atomic sequence counter** | `EventWriter` uses `AtomicU64` for lock-free monotonic sequence assignment across tasks. |
| **Content-addressed storage** | Blobs are keyed by SHA-256 hash, providing deduplication and integrity verification. |
| **Strategy pattern for adapters** | Each harness (Claude, Codex, Generic) implements `HarnessAdapter` for detect/parse/launch. Detection is tried in priority order. |
| **Layered redaction** | Redaction applies at multiple boundaries: capture, export, serve, and at-rest scrub. Each layer uses `SecretScanner` with configurable patterns. |
| **Read-modify-write with file lock** | `ProjectState` operations use `flock` on `state.lock` for safe concurrent access to project state. |
| **Event deduplication via fingerprint** | `EventWriter` maintains a `HashSet<String>` of tool event fingerprints to handle duplicate delivery from PTY parsing + native log polling. |
| **Budget-bounded pack building** | Both `ContextPackView` and `ProjectMemoryPack` are built with token budgets, shrinking lower-priority fields first when over budget. |



---

## 7. Crate Structure

### 7.1 Module Map

| Module | Path | Purpose |
|---|---|---|
| `core` | `src/core/` | Data model: `TraceEvent`, `Run`, `Checkpoint`, `BlobReference` |
| `capture` | `src/capture/` | `CaptureLayer` trait + PTY/Git/FS/Process implementations |
| `pipeline` | `src/pipeline/` | `EventWriter` — monotonic sequencing, dedup, persistence |
| `storage` | `src/storage/` | `TraceStore` trait + `SqliteStore` implementation + FTS5 |
| `terminal` | `src/terminal/` | `RawRecorder`, `AnsiNormalizer`, `TerminalCoalescer` |
| `analysis` | `src/analysis/` | `AnalysisPass` trait + `ErrorDetector`, `SideEffectClassifier`, `EventCorrelator` |
| `adapters` | `src/adapters/` | `HarnessAdapter` trait + Claude, Codex, Generic parsers + native log pollers + detection |
| `redaction` | `src/redaction/` | `SecretScanner`, `EnvironmentRedactor`, `ExportRedactor`, `RedactionConfig` |
| `replay` | `src/replay/` | `ReplayEngine` trait + Fork, Sandbox, Mock, Timeline engines |
| `export` | `src/export/` | JSONL, HTML, Portable (v1/v2) exporters |
| `ui` | `src/ui/` | ratatui TUI (event list, run list, timeline) |
| `cli.rs` | `src/cli.rs` | Clap CLI (all subcommands + command execution) |
| `config.rs` | `src/config.rs` | Store path resolution, `BlackboxPaths`, `BlackboxConfig`, project discovery |
| `context.rs` | `src/context.rs` | Bounded resume context pack builder (`ContextPackView`) |
| `maybe_run.rs` | `src/maybe_run.rs` | Ambient shell capture gate (`MaybeRunAction` decision) |
| `mcp.rs` | `src/mcp.rs` | MCP (Model Context Protocol) stdio JSON-RPC server |
| `memory.rs` | `src/memory.rs` | `ProjectMemoryPack` builder (blackbox.memory/v1) |
| `state.rs` | `src/state.rs` | Sticky state v2 + state.lock + claims + attention + `ProjectState` |
| `run.rs` | `src/run.rs` | `RunSupervisor` — PTY supervision + capture orchestration |
| `serve.rs` | `src/serve.rs` | Axum web dashboard + JSON/SSE API |
| `sync.rs` | `src/sync.rs` | Directory / HTTP / S3 push-pull sync engine |
| `search.rs` | `src/search.rs` | FTS5-backed full-text search |
| `scrub.rs` | `src/scrub.rs` | At-rest re-redaction + blob GC |
| `resume.rs` | `src/resume.rs` | Fork/resume helpers (adapter detection, session discovery) |
| `resume_inject.rs` | `src/resume_inject.rs` | Continuity / memory launch inject (env vars, prompt prepending) |
| `status.rs` | `src/status.rs` | Status/handoff view builder (`StatusView`) |
| `summary.rs` | `src/summary.rs` | Run summary builder (`SummaryView`) |
| `transcript.rs` | `src/transcript.rs` | Transcript rebuild from events/blobs for CLI output |
| `views.rs` | `src/views.rs` | Serde view types for CLI `--json` + serve API |
| `output.rs` | `src/output.rs` | Output formatting helpers + JSON envelope (`blackbox.cli/v1`) |
| `util.rs` | `src/util.rs` | Misc utilities (truncate, html_escape, short_id, notes merge, redact helpers) |
| `trajectory.rs` | `src/trajectory.rs` | Run diff/trajectory alignment (LCP-based semantic diff) |
| `pricing.rs` | `src/pricing.rs` | Token-to-cost estimation (optional) |
| `retention.rs` | `src/retention.rs` | Policy retention planning (keep N, max age) |
| `shell_install.rs` | `src/shell_install.rs` | Shell wrapper installation (bash/zsh/fish) |

### 7.2 Entry Points

**Binary:** `src/main.rs`
```rust
fn main() -> anyhow::Result<()> {
    // Manual tokio Runtime (not #[tokio::main])
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let cli = Cli::parse();
        cli.execute().await
    })
}
```

**Library:** `src/lib.rs` — re-exports all public modules.

### 7.3 CLI Commands

| Command | Description |
|---|---|
| `run` | Run a command under observation |
| `runs` | List recorded runs |
| `show` | Show run details |
| `timeline` | Display event timeline |
| `inspect` | Inspect a specific event |
| `diff` | Compare two runs (trajectory diff) |
| `export` | Export a run (jsonl, html, portable) |
| `import` | Import a portable archive |
| `replay` | Replay a run (timeline, mock, sandbox, live) |
| `fork` | Fork a new run from recorded context |
| `analyze` | Run analysis passes |
| `scrub` | Re-redact secrets at rest |
| `doctor` | Diagnose store path, schema, environment |
| `rm` | Delete runs |
| `purge` | Purge runs by policy |
| `search` | Full-text search across runs and events |
| `watch` | Live-tail events |
| `tags` | List tags and counts |
| `tag` | Add/remove tags |
| `stats` | Aggregate store statistics |
| `completions` | Generate shell completions |
| `serve` | Start web dashboard |
| `sync` | Sync runs with remote (dir/http/s3) |
| `maybe-run` | Project-gated ambient capture gate |
| `enable` | Enable ambient capture for this project |
| `disable` | Disable ambient capture |
| `status` | Project status / agent handoff |
| `handoff` | Alias for status with memory pack |
| `postmortem` / `summary` | One-command run summary |
| `gc` | Policy retention dry-run/apply |
| `resume` | Bounded resumption context for failed runs |



---

## 8. Design Decisions

| Decision | Rationale | Trade-offs |
|---|---|---|
| **SQLite + filesystem blobs** | Zero-dependency storage for a single-user CLI tool. SQLite provides ACID transactions, FTS5 full-text search, and simple deployment. | Not suitable for multi-user concurrent access. No built-in replication. |
| **Content-addressed blobs (SHA-256)** | Automatic deduplication of identical payloads. Integrity verification via hash. Filesystem-native, no additional database bloat. | Blob files cannot be renamed without breaking references. GC required to reclaim orphaned blobs. |
| **Universal `TraceEvent` with open `kind` string** | Extensible without core schema changes. Adapters can introduce new event kinds. | No compiler-enforced validation of event kinds. Requires documentation conventions. |
| **`parking_lot::Mutex<Connection>` for SQLite** | Simplest correct approach for single-user CLI + dashboard. Avoids `SQLITE_BUSY` races. | Blocks tokio worker threads during SQLite calls. Not suitable for concurrent write-heavy serve workloads. |
| **Redact-before-write by default** | Secrets never at rest unless explicitly opted out. `--insecure-raw` and `--no-redact` are explicit danger flags. | Slightly higher write latency. Some non-sensitive data may be conservatively redacted. |
| **PTY parsing + native log polling** | Redundant capture increases reliability. Native logs provide structured events; PTY provides exact terminal output. Dedup handles duplicates. | More complex pipeline. Duplicate events must be identified and filtered. |
| **mpsc channels for event streaming** | Decoupled, async-safe communication between capture layers and the event writer. Each layer is independently startable/stopable. | Fixed channel capacity (1024). Backpressure on slow consumers. |
| **EventWriter as single sequencer** | Guarantees monotonic, gap-free sequence numbers per run. Single point of persistence. | All events must funnel through one writer — potential bottleneck under very high event rates. |
| **Sticky state with `flock` locking** | Safe concurrent state updates from multiple agent processes. Prevents lost updates and claim conflicts. | File lock semantics vary across platforms. Lock files can be left behind on crash. |
| **Token-bounded memory packs** | Predictable injection sizes for LLM context windows. Priority-based shrinking ensures critical signal survives. | May lose context on very large runs. Sequential shrinking order is a heuristic. |
| **Content-addressed blobs with import key rename** | Portable export preserves blob integrity by using SHA-256 keys; imports can remap keys when the expected hash doesn't match on-disk content. | Adds complexity to the import path. `move_blob` is a compatibility layer. |
| **Manual tokio Runtime** | Explicit lifecycle control. Avoids `#[tokio::main]` macro overhead. Consistent with library-first design (binaries own the runtime). | Slightly more boilerplate in `main.rs`. |
| **`async_trait` for all major traits** | Enables trait objects (`dyn TraceStore`, `dyn CaptureLayer`) for testability and backend swapping. | Heap allocation per call. Slightly larger generated code. |
| **Structured notes (`"; "`-joined segments)** | Extensible metadata on `Run` without schema changes. Used for `adapter:`, `session:`, `auto_resume:`, `claim:` segments. | String parsing needed to extract segments. Not type-safe. |

---

## 9. Version History

| Version | Focus | Key Changes |
|---|---|---|
| 1.0.0 | Capability daily-driver | Core PTY capture, SQLite store, event pipeline, CLI commands, basic export |
| 1.1.0 | Adoption bar | Ambient contract (`maybe-run`, shell wrappers), redaction gate, adapter detection (Claude/Codex/Generic), CI/eval support, shell soak, legacy db migration |
| 1.2.0 | Agent Memory Bus | Continuity plane (`state.rs` v2, claims, attention), `ProjectMemoryPack` (blackbox.memory/v1), resume injection (env vars + prompt prepending), MCP server, trajectory diff |

---

## 10. References

- **`AGENTS.md`** — Repository guidelines, conventions, and development commands
- **`docs/ROADMAP.md`** — Quality bar and remaining work
- **`docs/plan/agent-memory-bus-1.2.md`** — 1.2 design: memory bus, continuity, claims
- **`docs/plan/adoption-1.1.md`** — 1.1 design: ambient, redaction, resume, cost
- **`docs/ambient-contract.md`** — Normative ambient shell + maybe-run contract
- **`docs/agent-api.md`** — Agent-facing API documentation (status, handoff, search)
- **`docs/PUBLISH.md`** — crates.io publish checklist

