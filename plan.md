# Phase 1 — Black-box Recorder

Goal: make `blackbox run -- codex` (or any command) actually work — launch it, capture
terminal output, log events to a database, show a basic TUI, diff git state, and export JSONL.

---

## Task 1 — Run supervisor (`RunSupervisor`)

- Implement a `RunSupervisor` struct in a new file `src/run.rs` (or inside `src/capture/`).
- Owns the `Run` state, spawns the child command via `portable-pty`, wires up `PtyCapture`,
  and signals completion.
- `cmd_run()` in `cli.rs` delegates to it.

**Files:** `src/cli.rs`, `src/run.rs` (new), `src/capture/pty.rs` (flesh out),
`src/capture/mod.rs` (maybe).

---

## Task 2 — PTY recording with portable-pty

- Replace the `PtyCapture` stub: spawn the harness process in a PTY fork.
- Stream stdout/stderr through `RawRecorder` → `AnsiNormalizer`, emit `TraceEvent` values
  on a channel.
- Forward stdin (user keystrokes → PTY master).
- Passthrough SIGINT / Ctrl+C.

**Depends on:** Task 1
**Files:** `src/capture/pty.rs`, `src/terminal/recorder.rs`

---

## Task 3 — SQLite trace store

- Replace `InMemoryStore` with a real `SqliteStore` using `rusqlite`.
- Schema: `runs`, `events`, `checkpoints`, `blobs` tables.
- Content-addressed blob storage on disk (`.blackbox/blobs/`).
- Migration runner for schema versioning.

**Files:** `src/storage/sqlite.rs` (new), `src/storage/mod.rs`,
`src/storage/store.rs` (remove / replace)

---

## Task 4 — Git diff capture

- Flesh out `GitCapture`: snapshot `git diff` before and after the run.
- Store the diff as a blob, emit a `git.diff` event.
- Handle non-git directories gracefully (fall back to filesystem manifest).

**Files:** `src/capture/git.rs`

---

## Task 5 — TUI shell (Ratatui)

- Build the main TUI loop with `crossterm` event handling.
- Wire `RunsView`, `TimelineView`, `EventView` panels into a layout.
- Keyboard navigation between panels (j/k, Tab, Enter).
- `blackbox show latest` opens the TUI with the most recent run loaded.

**Files:** `src/ui/mod.rs`, `src/ui/tui.rs` (new app shell), existing panel files

---

## Task 6 — JSONL export

- Implement `cmd_export` for `--format jsonl`: serialize all events + run metadata as
  newline-delimited JSON.
- Integrate `ExportRedactor` when `--redact` flag is set.

**Files:** `src/cli.rs`, `src/export/jsonl.rs` (new), `src/export/mod.rs` (new module)

---

## Task 7 — Secret redaction during capture

- Wire `SecretScanner` and `EnvironmentRedactor` into the capture pipeline.
- Redact captured environment variables before storing.
- Scan terminal output chunks for known secret patterns.

**Files:** `src/redaction/scanner.rs`, `src/redaction/environment.rs`, `src/capture/pty.rs`

---

## Recommended sequence

```
Task 1 ──→ Task 2 (PTY recording)
               │
        Task 3 (SQLite store) ←─ stores all events
               │
Task 4 ───────┤
               │
Task 5 ←──────┤ reads from store
               │
Task 6 ←──────┘ reads from store
               │
Task 7 ────────┤ wired into PTY + env capture
```

Tasks 3 and 4 are independent — can run in parallel.
Task 7 is additive and can be done last or interleaved.

Each task is a single self-contained commit that leaves the project compiling and testable.

---

# Phase 2 — Critical Fixes & Integration

**Status**: Phase 1 scaffold is complete but has critical integration gaps that prevent the app from functioning as specified.

## Critical Issues Found

1. **Capture Layer Architecture Broken**: RunSupervisor manually implements PTY handling instead of using CaptureLayer abstraction
2. **Missing ANSI Normalization**: AnsiNormalizer exists but is never called in PTY pipeline
3. **Harness Adapters Not Integrated**: Adapters exist but RunSupervisor never uses them
4. **Environment Variables Never Captured**: EnvironmentRedactor exists but environment is never captured
5. **Git Diffs Not Stored as Blobs**: GitCapture emits events but doesn't store diffs as content-addressed blobs
6. **No Checkpoint Creation**: Checkpoints are never created during runs
7. **Terminal Recorder Not Integrated**: RawRecorder exists but is not used in capture pipeline
8. **Missing stdin Forwarding**: User keystrokes are not forwarded to PTY master
9. **No Signal Handling**: SIGINT/Ctrl+C passthrough not implemented
10. **Unsafe libc Usage**: Direct unsafe libc calls without proper error handling
11. **TUI Event Selection Stubbed**: select_run() and select_event() are empty placeholders
12. **Analysis Passes Return Empty**: All analysis passes return empty vectors
13. **Replay Engines Mostly Stubbed**: Only TimelineReplay has minimal implementation
14. **Export Formats Incomplete**: Only JSONL works; HTML and Portable formats are stubs
15. **CLI Commands Stubbed**: cmd_timeline, cmd_inspect, cmd_diff, cmd_replay, cmd_fork all bail
16. **No Blob Storage on Disk**: SQLite stores blobs in database, not .blackbox/blobs/

## Phase 2 Tasks

### Task 8 — Fix Capture Layer Integration
- Refactor RunSupervisor to use CaptureLayer abstraction properly
- Wire up GitCapture, FilesystemCapture, ProcessCapture in run pipeline
- Implement proper layer orchestration with multiple concurrent capture layers
- **Files**: `src/run.rs`, `src/capture/mod.rs`

### Task 9 — Integrate ANSI Normalization
- Wire AnsiNormalizer into PTY output pipeline
- Store both raw and normalized terminal output
- Implement proper ANSI sequence parsing (CSI, OSC, DCS)
- **Files**: `src/run.rs`, `src/terminal/ansi.rs`

### Task 10 — Implement Environment Capture
- Capture environment variables at run start
- Apply EnvironmentRedactor before storage
- Store redacted environment as checkpoint metadata
- **Files**: `src/run.rs`, `src/redaction/environment.rs`

### Task 11 — Implement Blob Storage on Disk
- Store blobs in `.blackbox/blobs/` directory instead of SQLite database
- Implement proper file-based blob deduplication
- Update SqliteStore to reference blob files instead of storing BLOB data
- **Files**: `src/storage/sqlite.rs`

### Task 12 — Store Git Diffs as Blobs
- Implement GitCapture to store diffs as content-addressed blobs
- Update checkpoint creation to include git_diff_blob references
- Implement proper blob storage for git snapshots
- **Files**: `src/capture/git.rs`, `src/run.rs`

### Task 13 — Implement Checkpoint Creation
- Create checkpoints at run start and key events
- Include git state, environment, and transcript references
- Wire checkpoint creation into RunSupervisor
- **Files**: `src/run.rs`, `src/core/checkpoint.rs`

### Task 14 — Implement stdin Forwarding
- Add stdin handling to RunSupervisor
- Forward user keystrokes to PTY master
- Handle terminal resize events
- **Files**: `src/run.rs`

### Task 15 — Implement Signal Handling
- Add SIGINT/Ctrl+C passthrough to child process
- Handle other signals (SIGTERM, SIGHUP)
- Ensure clean process cleanup on signals
- **Files**: `src/run.rs`

### Task 16 — Fix Unsafe libc Usage
- Replace unsafe libc calls with portable-pty APIs where possible
- Add proper error handling for remaining libc calls
- Improve portability across platforms
- **Files**: `src/run.rs`

### Task 17 — Implement TUI Event Selection
- Implement select_run() to load events for selected run
- Implement select_event() to show event details
- Add proper state management for TUI navigation
- **Files**: `src/ui/tui.rs`

### Task 18 — Implement Analysis Passes
- Implement ErrorDetector to extract structured errors
- Implement SideEffectClassifier to classify events
- Implement EventCorrelator to find related events
- **Files**: `src/analysis/error_detector.rs`, `src/analysis/classifier.rs`, `src/analysis/correlator.rs`

### Task 19 — Implement Replay Engines
- Implement ForkReplay to resume from checkpoints
- Implement SandboxReplay for safe replay
- Implement MockReplay for tool call mocking
- **Files**: `src/replay/fork.rs`, `src/replay/sandbox.rs`, `src/replay/mock.rs`

### Task 20 — Implement Export Formats
- Implement HTML export with embedded CSS
- Implement Portable export with blob archive
- Add export validation and testing
- **Files**: `src/export/html.rs`, `src/export/portable.rs`, `src/export/mod.rs`

### Task 21 — Implement CLI Commands
- Implement cmd_timeline with event visualization
- Implement cmd_inspect with event detail display
- Implement cmd_diff with run comparison
- Implement cmd_replay with replay engine integration
- Implement cmd_fork with checkpoint resume
- **Files**: `src/cli.rs`

### Task 22 — Integrate Harness Adapters
- Use adapters for command detection in RunSupervisor
- Apply adapter-specific launch preparation
- Parse adapter-specific output for structured events
- **Files**: `src/run.rs`, `src/adapters/claude.rs`, `src/adapters/codex.rs`

## Recommended Sequence

```
Task 8 (Capture Layer Integration) → Task 9 (ANSI Normalization) → Task 10 (Environment Capture)
                                     ↓
Task 11 (Blob Storage on Disk) ←─────┘
                ↓
Task 12 (Git Diffs as Blobs) → Task 13 (Checkpoint Creation)
                ↓
Task 14 (stdin Forwarding) → Task 15 (Signal Handling) → Task 16 (Fix libc Usage)
                ↓
Task 17 (TUI Event Selection) → Task 18 (Analysis Passes)
                ↓
Task 19 (Replay Engines) → Task 20 (Export Formats)
                ↓
Task 21 (CLI Commands) → Task 22 (Harness Adapters)
```

Tasks 11-13 can be done in parallel. Tasks 14-16 should be done sequentially. Tasks 18-20 can be done in parallel.

---

# Phase 3 — Overcome Remaining Intentional Limits

**Status**: Phase 1–2 deliver a working recorder, but three capabilities remain simulation-level.

## Remaining Limits

| # | Limit | Why it matters |
|---|---|---|
| L1 | **FilesystemCapture is snapshot-only** | Misses mid-run creates/modifies/deletes; correlation with tool calls is weak |
| L2 | **Adapters do not parse structured output** | Tool calls, session IDs, and harness semantics never become `TraceEvent`s |
| L3 | **Replay engines only log** | Mock/sandbox/fork do not restore workspaces, re-execute, or create fork runs |

## Phase 3 Tasks

### Task 23 — Live filesystem watching (`notify`)  `[Phase 3A]`

- Replace shallow start/stop snapshots with recursive `notify` watchers.
- Emit per-path events: `filesystem.created`, `filesystem.modified`,
  `filesystem.removed`, `filesystem.renamed`.
- Keep before/after snapshot events as bookends.
- Ignore high-noise paths: `.git/`, `target/`, `node_modules/`, `.blackbox/`.
- Bridge notify's sync channel into the async capture `mpsc` stream.

**Files:** `src/capture/filesystem.rs`  
**Depends on:** none (standalone)  
**Done when:** a run that creates a file mid-execution records a `filesystem.created` event.

---

### Task 24 — Structured harness output parsing  `[Phase 3B]`

- Extend `HarnessAdapter::parse_output(run_id, chunk)` to produce semantic events.
- **Claude adapter**: stream-json / NDJSON tool_use & assistant lines; session IDs;
  tool names (Read, Write, Edit, Bash, Glob, Grep).
- **Codex adapter**: function_call / tool patterns; session discovery; resume commands.
- **Generic**: light heuristics only (exit lines, error banners).
- Wire parsing into `RunSupervisor` PTY pipeline after ANSI normalize + redaction.
- Implement `discover_session_id` and `build_resume_command` for Claude/Codex.

**Files:** `src/adapters/harness.rs`, `claude.rs`, `codex.rs`, `generic.rs`, `src/run.rs`  
**Depends on:** none (can parallelize with 23)  
**Done when:** synthetic tool_use NDJSON in terminal output yields `tool.call` events.

---

### Task 25 — Real replay engines  `[Phase 3C]`

- Enrich `ReplayOutcome` with structured results (mocked counts, sandbox path, forked run id).
- **MockReplay**: index recorded `Tool` events; re-emit recorded outputs without FS mutation;
  print a human-readable mock transcript.
- **SandboxReplay**: create a temp workspace; re-execute allowed process/tool events under
  `ReplayPolicy` (block ExternalWrite/Destructive); capture exit codes.
- **ForkManager**: create a new `Run` with `parent_run_id`, optional name, checkpoint
  context summary persisted; return new run id for follow-on `blackbox run`.
- **TimelineReplay**: print a readable timeline to stdout (not only tracing logs).
- Wire store into fork/sandbox CLI paths where needed.

**Files:** `src/replay/*`, `src/cli.rs`  
**Depends on:** Task 24 preferred (tool events improve mock); works without it  
**Done when:** `blackbox replay --mock-tools` / `--sandbox` / `fork` produce real side
effects (temp dir, new run row, mock transcript) instead of log-only simulation.

## Recommended Sequence

```
Task 23 (Live FS watch)  ──┐
                           ├──→ Task 25 (Real replay)   [tool events + FS history help]
Task 24 (Adapter parse)  ──┘
```

Tasks 23 and 24 are independent and can land as separate commits.
Task 25 should follow so mock/sandbox can consume tool + filesystem events.

Each task is one self-contained commit that leaves the project compiling and testable.
