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
