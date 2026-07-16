# Capture Pipeline

> **Contributor / deep-dive.** Operator overview: [../guide/what-is-blackbox.md](../guide/what-is-blackbox.md) · [../guide/concepts.md](../guide/concepts.md).

**Answers:** How PTY/git/fs/process layers start, how streams merge, where redaction and adapters run, and how `EventWriter` assigns sequence numbers.

How blackbox observes harness activity through independent capture layers, merges their event streams, and persists a consistent ordered trace.

## 1. Overview

Blackbox captures agent harness activity through multiple independent
**capture layers**, each observing one dimension of the running system.
Layers emit [`TraceEvent`] values into shared `mpsc` channels. These
channels are merged by a [`merge_layers()`] combinator into a single
stream that feeds into the [`EventWriter`] — the single authority for
sequencing, deduplication, and persistence.

```
PTY Layer ──────┐
Git Layer ───────┤
FS Layer  ───────┼── merge_layers() ──► EventWriter ──► SqliteStore
Process Layer ───┘
Native Logs ─────┘   (adapter parse & redact happen per-layer)
```

Traces flow into [`SqliteStore`] (SQLite + content-addressed blobs).
All capture paths funnel through the `EventWriter` to guarantee
monotonic sequence numbers and cross-channel deduplication.

[`TraceEvent`]: ../src/core/event.rs
[`merge_layers()`]: ../src/capture/mod.rs
[`EventWriter`]: ../src/pipeline/event_writer.rs
[`SqliteStore`]: ../src/storage/sqlite.rs

---

## 2. CaptureLayer Trait

Every capture layer implements a single async trait:

```rust
#[async_trait]
pub trait CaptureLayer: Send + 'static {
    /// Human-readable name of this capture layer.
    fn name(&self) -> &'static str;

    /// Start capturing events from the given run.
    /// Returns a receiver that yields events as they occur.
    async fn start(&mut self, run: &Run)
        -> anyhow::Result<mpsc::Receiver<TraceEvent>>;

    /// Stop capturing and clean up resources.
    async fn stop(&mut self) -> anyhow::Result<()>;
}
```

**Lifecycle:** `start()` is called once when the run begins. The returned
`Receiver` is fed into `merge_layers()`. `stop()` is called during
teardown, after the child process exits. Each layer sends lifecycle
bookend events (e.g. `pty.started` / `pty.stopped`).

**Convention:** Layers that need no special cleanup return `Ok(())` from
`stop()`. Double-stopping is safe — layers store their sender in an
`Option` and `take()` it on stop.

---

## 3. The Four Capture Layers

### 3.1 PTY Layer (`src/capture/pty.rs`)

**Source:** `EventSource::Terminal`
**Events:** `pty.started`, `pty.stopped`

The PTY layer is a lightweight coordinator. It emits bookend lifecycle
events so the trace has clear start/stop markers for the terminal
session. Actual PTY I/O is managed by the `RunSupervisor`, which owns
the `portable-pty` pair and drives the normalize → redact → blob →
adapter pipeline (see §4).

```rust
pub struct PtyCapture {
    event_tx: Option<mpsc::Sender<TraceEvent>>,
    run_id: Option<String>,
}

// On start: emits "pty.started"
// On stop:  emits "pty.stopped"
```

Terminal resizes (SIGWINCH) are forwarded to the PTY master via a
dedicated tokio signal handler, but do not produce their own events.

### 3.2 Git Layer (`src/capture/git.rs`)

**Source:** `EventSource::Git`
**Events:** `git.snapshot.before`, `git.snapshot.after`, `git.diff`

Captures repository state at run start and end:

- **Before run:** current commit hash, working-tree diff (unstaged +
  staged changes, truncated at 1 MiB)
- **After run:** post-run commit hash, post-run diff
- Diffs are persisted as content-addressed blobs via `TraceStore`
- Non-git directories fall back to a simple file listing

Git commands are run inside `spawn_blocking` to avoid starving the async
runtime (R2-M19). Results feed into the run's start/end checkpoints.

```rust
TraceEvent {
    kind: "git.diff",
    source: EventSource::Git,
    output_blob: Some("sha256hex..."),
    metadata: {
        "commit_before": "abc123...",
        "commit_after":  "def456...",
        "diff_type":     "before",
    },
}
```

### 3.3 Filesystem Layer (`src/capture/filesystem.rs`)

**Source:** `EventSource::Filesystem`
**Events:** `filesystem.snapshot`, `filesystem.created`,
`filesystem.modified`, `filesystem.removed`, `filesystem.renamed`,
`filesystem.observer.started`, `filesystem.observer.stopped`

Uses the `notify` crate for OS-level filesystem watching. During the run
it emits live events for file changes. At start and stop it takes a
recursive snapshot (up to 4 levels deep) of the working directory.

**Noise filtering:** The layer ignores high-churn directories:

```rust
const IGNORE_COMPONENTS: &[&str] = &[
    ".git", "target", "node_modules", ".blackbox",
    ".cargo", "__pycache__", ".tox", "dist", "build",
];
```

It also ignores blackbox database files (`blackbox.db`,
`blackbox.db-wal`, `blackbox.db-shm`) to avoid feedback loops.

The bridge from `notify` (sync) to tokio uses a `std::sync::mpsc`
channel and a `tokio::task::spawn_blocking` forwarder.

### 3.4 Process Layer (`src/capture/process.rs`)

**Source:** `EventSource::Process`
**Events:** `process.observer.started`, `process.spawned`,
`process.observer.stopped`

Tracks the supervised child process lifecycle. The `RunSupervisor` calls
`set_pid()` and `emit_spawned()` after the PTY spawns the child.

```rust
pub struct ProcessCapture {
    event_tx: Option<mpsc::Sender<TraceEvent>>,
    run_id: Option<String>,
    child_pid: Option<u32>,
}
```

The `process.spawned` event includes the PID in metadata. Full
`/proc`-level inspection is reserved for future enhancement.

---

## 4. PTY I/O Pipeline

The PTY output pipeline is the most complex capture path. It runs inside
a `tokio::spawn` task launched by the `RunSupervisor` and processes
every byte the child writes to the pseudo-terminal.

### Flow

```
PTY Reader (spawn_blocking)
    │
    ▼  raw bytes (Vec<u8>)
RawRecorder
    │  stores segments with offset_ms timestamps
    ▼
AnsiNormalizer
    │  strips ANSI escapes → clean text
    ▼
SecretScanner (redaction)
    │  scans for secrets, produces safe_text
    ▼
TerminalCoalescer
    │  buffers chunks, flushes on newline/size
    ▼
store_blob() → EventWriter.write()   ──► terminal.output event
    │
    ▼  (parallel path, same safe_text)
Line buffer → adapter.parse_output() ──► tool.call / tool.result events
```

### Step-by-step

1. **Raw reader** — A `spawn_blocking` task reads from the PTY master
   FD in 8192-byte chunks and sends them over an `mpsc` channel.

2. **RawRecorder** — Records every segment with a monotonic offset from
   run start. Uses a `MAX_SEGMENTS` cap (10,000) to prevent unbounded
   memory growth (M-16). At stop, it emits a `terminal.recording` event
   with segment count and total bytes.

3. **AnsiNormalizer** — Strips ANSI control sequences (CSI, OSC, DCS,
   SOS, APC, PM) while preserving printable UTF-8 content including
   multi-byte characters, CJK, and emoji. Carriage returns are removed;
   newlines and tabs are preserved.

4. **Redaction** — A `SecretScanner` scans the normalized text for
   secrets (API keys, tokens, credentials). The scanner operates on both
   the terminal text and on metadata from adapter-parsed events. When
   redactions occur, a warning is logged with the count and segment
   number. The redacted text (`safe_text`) is what gets persisted.

5. **TerminalCoalescer** — Buffers small chunks into larger segments
   before persistence. Flush triggers:
   - Buffer reaches 4096 bytes (`max_bytes`)
   - 16 raw chunks accumulated (`max_chunks`)
   - A single chunk > 512 bytes (`large_chunk`)
   - A newline is encountered

   When `--insecure-raw` is active, the coalescer also retains the raw
   (unredacted) bytes up to 10 MiB.

6. **Blob storage** — Each coalesced segment's text is stored as a
   content-addressed blob (`store_blob()`). The resulting SHA-256 key
   goes into `output_blob` on the `terminal.output` event. Large
   payloads never reside inline in the SQLite row.

7. **Adapter parsing (parallel)** — The same `safe_text` is fed into a
   line buffer. Complete lines (delimited by `\n`) are passed to the
   adapter's `parse_output()`. Parsed `tool.call`, `tool.result`, and
   `harness.usage` events are written via the `EventWriter`. The line
   buffer is capped at 64 KiB to prevent unbounded growth.

```rust
// Pseudocode of the PTY output loop
while let Some(data) = pty_out_rx.recv().await {
    recorder.record_output(&data).await;
    let normalized = ansi_normalizer.normalize(&data);
    let safe_text = if redact {
        scanner.redact(&normalized)
    } else {
        normalized.clone()
    };
    if let Some(seg) = coalescer.push(&safe_text, &data, redaction_count) {
        emit_terminal(&store, &writer, &run_id, seg, insecure_raw).await;
    }
    // Line-buffered adapter parse
    line_buf.push_str(&safe_text.replace('\r', ""));
    while let Some(pos) = line_buf.find('\n') {
        let line = /* extract line */;
        for event in adapter.parse_output(&run_id, line.as_bytes()) {
            if do_redact {
                redact_json(&mut event.metadata);
            }
            writer.write(event).await?;
        }
    }
}
```

## 5. Adapter Parsers

### 5.1 Detection (`src/adapters/detect.rs`)

When a run starts, `detect_adapter()` checks the command against known
harnesses. Detection order is ordered by specificity:

| Priority | Harness    | Detection clue                    |
|----------|------------|-----------------------------------|
| 1        | claude     | `argv[0]` basename matches `claude` |
| 2        | codex      | `argv[0]` basename matches `codex`  |
| 3        | aider      | `argv[0]` basename matches `aider`  |
| 4        | gemini     | `argv[0]` basename matches `gemini` |
| 5        | cursor     | `argv[0]` basename matches `cursor` or `cursor-agent` |
| 6        | opencode   | `argv[0]` basename matches `opencode` |
| 7        | grok       | `argv[0]` basename matches `grok`    |
| 8        | generic    | Always matches (fallback)           |

```rust
pub fn detect_adapter(command: &[String]) -> Arc<dyn HarnessAdapter> {
    // Iterates candidates; first detect() returning true wins.
}
```

### 5.2 HarnessAdapter Trait (`src/adapters/harness.rs`)

```rust
#[async_trait]
pub trait HarnessAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn detect(&self, command: &[String]) -> bool;
    fn prepare_launch(
        &self, command: &[String], ctx: &LaunchContext
    ) -> Option<PreparedLaunch>;
    fn parse_output(&self, run_id: &str, chunk: &[u8]) -> Vec<TraceEvent>;
    fn discover_session_id(&self, events: &[TraceEvent]) -> Option<String>;
    fn build_resume_command(&self, session_id: &str) -> Option<Vec<String>>;
    fn locate_native_logs(&self, context: &RunContext) -> Vec<String>;
}
```

Each adapter knows how to detect its harness, prepare the launch
environment, parse structured events from the output stream, and locate
native log files.

### 5.3 Parsing (`src/adapters/parse.rs`)

The shared parsing module provides:

- **`parse_claude_json_line()`** — Parses Claude Code's NDJSON protocol
  lines (`tool_call`, `tool_result`, `assistant`, `user`, `usage`,
  `blackbox.response`). Extracts `tool_use_id`, tool names, inputs,
  outputs, and token counts.

- **`parse_blackbox_protocol_line()`** — Parses the generic blackbox
  protocol format with typed messages: `system`, `tool_call`,
  `tool_result`, `usage`.

- **`parse_codex_json_line()`** — Parses Codex CLI's JSON output
  format.

- **`parse_plaintext()`** — Free-text fallback using regex to extract
  session IDs and tool mentions from non-JSON output.

Tool names are classified into side-effect levels:

```rust
pub fn tool_side_effect(name: &str) -> SideEffect {
    match name.to_lowercase().as_str() {
        "read" | "read_file" | "grep" | ... => SideEffect::Read,
        "write" | "edit" | "create" | ... => SideEffect::LocalWrite,
        "bash" | "shell" | "execute" | ... => SideEffect::Unknown,
        "delete" | "remove" | "rm" => SideEffect::Destructive,
        "browser" | "http" | "curl" | ... => SideEffect::ExternalWrite,
        _ => SideEffect::Unknown,
    }
}
```

The adapters also emit `harness.usage` events with token counts and
model information when the harness reports them (e.g. via `usage`-type
NDJSON messages from Claude Code).

---

## 6. Native Log Pollers (`src/adapters/native_logs.rs`)

Many agent CLIs write structured session files (JSONL, markdown) to disk
independently of PTY output. Native log pollers watch these files and
feed their content into the event pipeline as a secondary source.

### Discovery

`discover_log_roots()` returns candidate directories for each harness:

| Harness  | Log locations (project + home)                               |
|----------|--------------------------------------------------------------|
| claude   | `~/.claude/sessions/*.jsonl`, `~/.claude/projects/`          |
| codex    | `~/.codex/sessions/`, `.codex/logs/`                         |
| aider    | `.aider.chat.history.md`, `.aider/`                          |
| gemini   | `~/.gemini/`, `~/.config/gemini/`                            |
| cursor   | `~/.cursor/projects/`, `~/.config/cursor/`                   |
| opencode | `~/.opencode/logs/`                                          |
| grok     | `~/.grok/`, `~/.config/grok/`                                |

Only directories that **already exist** are included in the watch list.

### Polling

A background tokio task polls discovered log files every 2 seconds
during the run. On each cycle:

1. `list_candidate_files()` finds files matching expected patterns
   (`.jsonl`, `.history.md`, etc.)
2. `poll_log_file()` reads new lines since the last observed offset
3. Each new line is passed to the adapter's `parse_output()`
4. Parsed events are redacted and written via `EventWriter`
5. A rate limit of 500 events per cycle prevents flooding

Native log events are tagged with a `native_log` metadata field set to
the source file path. This allows the deduplication logic (see §8) to
match them against PTY-sourced events.

```rust
// Background poller task
let (log_stop_tx, mut log_stop_rx) = watch::channel(false);
tokio::spawn(async move {
    poll_native_logs(
        adapter, writer, native_roots, scanner, log_stop_rx,
    ).await;
});
```

The poller reads files incrementally — it maintains an offset map per
file so it only processes new content on each cycle. When the run ends,
the stop signal triggers one final flush.

---

## 7. EventWriter (`src/pipeline/event_writer.rs`)

The `EventWriter` is the single sequencing and persistence authority
for all capture paths. Every `TraceEvent` that reaches storage passes
through it.

```rust
pub struct EventWriter {
    store: Arc<dyn TraceStore>,
    seq: AtomicU64,
    run_id: String,
    tool_seen: Mutex<HashSet<String>>,
}
```

### Responsibilities

1. **Monotonic sequencing** — The writer owns a per-run `AtomicU64`
   counter. When `write()` receives an event with `sequence == 0`, it
   atomically allocates the next sequence number. This guarantees that
   every persisted event has a unique, monotonically increasing position
   in the trace timeline.

2. **Persistence** — After assigning the sequence, `write()` calls
   `store.insert_event()` on the `TraceStore`. The event's `run_id` is
   set automatically if missing.

3. **Deduplication** — Tool events (`tool.call`, `tool.result`) that
   arrive from both the PTY stream and native logs are deduplicated by
   fingerprint (see §8).

```rust
impl EventWriter {
    pub async fn write(&self, mut event: TraceEvent) -> Result<TraceEvent> {
        // 1. Set run_id if empty
        if event.run_id.is_empty() {
            event.run_id = self.run_id.clone();
        }
        // 2. Deduplicate tool events by fingerprint
        if let Some(fp) = tool_fingerprint(&event) {
            let mut seen = self.tool_seen.lock()
                .unwrap_or_else(|e| e.into_inner());
            if !seen.insert(fp) {
                event.metadata
                    .insert("deduped".into(), json!(true));
                return Ok(event);  // skipped — seq stays 0
            }
        }
        // 3. Assign sequence number
        if event.sequence == 0 {
            event.sequence = self.allocate_sequence();
        }
        // 4. Persist
        self.store.insert_event(&event).await?;
        Ok(event)
    }
}
```

### Helper methods

- `new(store, run_id)` — starts at sequence 1
- `with_start(store, run_id, start)` — continues from a known sequence
  (used during resume)
- `allocate_sequence()` — returns next seq without persisting (for
  checkpoint wiring)
- `next_sequence()` — peek at the next value

---

## 8. Event Merging (`src/capture/mod.rs`)

The `merge_layers()` function combines multiple `mpsc::Receiver<TraceEvent>`
channels into a single merged stream.

```rust
pub fn merge_layers(
    receivers: Vec<mpsc::Receiver<TraceEvent>>,
) -> (mpsc::Receiver<TraceEvent>, Vec<JoinHandle<()>>) {
    let (merged_tx, merged_rx) = mpsc::channel(1024);
    let mut handles = Vec::with_capacity(receivers.len());

    for mut rx in receivers {
        let tx = merged_tx.clone();
        let handle = tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                if tx.send(ev).await.is_err() {
                    break;
                }
            }
        });
        handles.push(handle);
    }

    (merged_rx, handles)
}
```

The returned `JoinHandle` vector allows the caller to detect panics in
forwarder tasks (rather than silently losing events). In `RunSupervisor`,
the merged receiver is consumed by the `event_writer_handle` task which
simply calls `writer.write(ev)` for every incoming event.

The `RunSupervisor` wires this together during `execute_inner()`:

```rust
// Start all capture layers
let (pty_rx, git_rx, fs_rx, proc_rx) = ...;
let (merged_rx, merge_handles) = merge_layers(
    vec![pty_rx, git_rx, fs_rx, proc_rx]
);

// Forward merged events to the writer
let event_writer_handle = tokio::spawn(async move {
    while let Some(ev) = merged_rx.recv().await {
        if let Err(e) = writer.write(ev).await {
            tracing::error!(error = %e, "event write failed");
        }
    }
});
```

---

## 9. Event Deduplication

When the same structured event arrives from both the PTY stream and
native logs (e.g., a tool call that appears in terminal output **and**
in a `.jsonl` session file), the `EventWriter`'s fingerprint set
skips the duplicate.

### Fingerprint computation

```rust
fn tool_fingerprint(event: &TraceEvent) -> Option<String> {
    // Only tool.call and tool.result
    if event.kind != "tool.call" && event.kind != "tool.result" {
        return None;
    }
    // Prefer tool_use_id (most stable identifier)
    let tool_use_id = event.metadata
        .get("tool_use_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !tool_use_id.is_empty() {
        return Some(format!("{}:{}", event.kind, tool_use_id));
    }
    // Fallback: kind + name + input hash (truncated to 120 chars)
    let tool_name = event.metadata
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let input = event.metadata
        .get("input")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let input_key = truncate(&input, 120);
    if tool_name.is_empty() && input_key.is_empty() {
        return None;
    }
    Some(format!("{}:{}:{}", event.kind, tool_name, input_key))
}
```

### Deduplication behavior

- The first occurrence is persisted with its sequence number
- Subsequent duplicates return immediately with `sequence = 0` and
  `metadata["deduped"] = true`
- The `tool_seen` set lives for the duration of the run (cleared when
  the `EventWriter` is created)
- Mutex poison is recovered gracefully — if a prior holder panicked,
  the lock is unwrapped via `into_inner()` (M-09)

### Why both sources?

| Source    | Strength                              | Weakness                          |
|-----------|---------------------------------------|-----------------------------------|
| PTY       | Captures everything the agent outputs | Mixed with UI, harder to parse    |
| Native    | Clean structured JSONL                | May miss in-flight or non-logged  |

Deduplication gives the best of both: rich structure from native logs
without double-counting tools in the timeline.

---

## Summary

```
┌───────────────────────────────────────────────────────────────┐
│                     RunSupervisor                             │
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │ PTY      │  │ Git      │  │ FS       │  │ Process      │  │
│  │ Capture  │  │ Capture  │  │ Capture  │  │ Capture      │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘  │
│       │              │             │                │          │
│       └──────────────┴─────────────┴────────────────┘          │
│                            │                                   │
│                    merge_layers()                               │
│                            │                                   │
│                    EventWriter.write()                         │
│                        ┌────┴─────┐                            │
│                        │  seq     │  (AtomicU64)               │
│                        │  dedupe  │  (HashSet&lt;String&gt;)          │
│                        └────┬─────┘                            │
│                             │                                  │
│                     SqliteStore.insert_event()                  │
│                             │                                  │
│                     ┌───────┴────────┐                         │
│                     │  SQLite table  │  ← events               │
│                     │  Blob store   │  ← large payloads        │
│                     └────────────────┘                         │
│                                                               │
│  ┌──────────────┐   Native Log Poller (background task)       │
│  │ claude.jsonl │──► parse_output() ──► writer.write()         │
│  │ codex.jsonl  │──► (deduped against PTY)                    │
│  └──────────────┘                                             │
└───────────────────────────────────────────────────────────────┘
```
