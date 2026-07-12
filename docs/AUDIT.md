# Blackbox Recorder — Comprehensive Codebase Audit

**Date:** 2026-07-12
**Scope:** Full `src/` tree — 50+ Rust source files, ~4,500 LOC
**Method:** 19 parallel deep-audit agents across all subsystems + cross-cutting concerns
**Baseline:** 75 unit tests + 5 integration tests, all passing

---

## Executive Summary

| Severity | Count | Fix Required |
|----------|-------|-------------|
| CRITICAL | 12 | Yes — data loss, panics, security bypass |
| HIGH | 28 | Yes — correctness, security, reliability |
| MEDIUM | 42 | Recommended — robustness, UX, performance |
| LOW | 30 | Optional — polish, documentation |
| **Total** | **112** | |

**Architecture assessment:** Well-designed with clean module boundaries, consistent `anyhow::Result` error handling, and solid redaction-by-default posture. WAL + busy_timeout SQLite setup is correct. Bounded channels provide natural backpressure. Content-addressed blobs enable deduplication.

**Top 5 most dangerous issues:**
1. **Non-ASCII content erased** by ANSI normalizer — destroys all Unicode terminal output
2. **Byte-index panics** across 12+ locations — crashes on CJK/emoji/accented input
3. **Path traversal** via unvalidated blob keys — escape blob directory
4. **HTML secret leak** in export — metadata secrets bypass redaction
5. **No process group isolation** — zombies, broken signal handling

---

## CRITICAL Findings

### C-01: ANSI Normalizer Drops All Non-ASCII Bytes
- **File:** `src/terminal/ansi.rs:86`
- **Impact:** Every non-ASCII byte (UTF-8 multibyte, CJK, emoji, accented) silently dropped from terminal output. Affects entire production pipeline — all transcripts lose Unicode.
- **Root cause:** `byte.is_ascii_graphic()` only matches ASCII printable. UTF-8 continuation bytes (0x80-0xBF) fail.
- **Fix:** Replace byte-level iteration with char-level: `raw.chars()` then strip escape sequences from the resulting string.

### C-02: Coalescer Preview Panic on Non-Char Boundary
- **File:** `src/terminal/coalesce.rs:89-90`
- **Impact:** `&self.text[..200]` panics if byte 200 falls inside multi-byte UTF-8 char.
- **Fix:** `self.text.floor_char_boundary(200)` or `self.text.chars().take(200).collect::<String>()`.

### C-03: TUI String Slice Panic on Short Run IDs
- **File:** `src/ui/tui.rs:249`, `src/ui/runs.rs:38`
- **Impact:** `&run.id[..8]` panics if `run.id` < 8 bytes. Crashes TUI.
- **Fix:** `run.id.get(..8).unwrap_or(&run.id)`.

### C-04: Git Diff Byte-Boundary Panic
- **File:** `src/capture/git.rs:~160`
- **Impact:** `&diff[..500]` panics when multi-byte UTF-8 straddles byte 500.
- **Fix:** `diff.floor_char_boundary(500)`.

### C-05: Byte-Index String Slicing Panics in CLI (6 locations)
- **File:** `src/cli.rs:664, 679, 985, 1088, 1141, 1157`
- **Impact:** `&label[..47]`, `&tags[..17]`, `&text[..50_000]`, `&p[..50]`, `&text[..2000]`, `&s[..200]` — all panic on multi-byte UTF-8.
- **Fix:** Create `fn trunc(s: &str, max: usize) -> &str` using `floor_char_boundary()`.

### C-06: HTML Secret Leak via event_detail
- **File:** `src/export/html.rs:102-105`
- **Impact:** `event_detail()` reads original `event.metadata` HashMap, not redacted copy. Secrets in `metadata.preview`/`metadata.input` leak into HTML. XSS vector if metadata contains `<script>`.
- **Fix:** Pass redacted JSON into detail extraction.

### C-07: Portable Import Drops parent_event_id Remapping
- **File:** `src/export/portable.rs:167-172`
- **Impact:** When `new_ids=true`, fresh UUIDs assigned but `parent_event_id` references old IDs. Breaks causal chain.
- **Fix:** Build old→new ID map, remap all `parent_event_id`.

### C-08: Non-String JSON Secrets Bypass All Redaction
- **File:** `src/redaction/scanner.rs:136-153`, `src/redaction/export.rs:24-39`
- **Impact:** Both `redact_json()` only scan `Value::String`. Numeric/boolean secrets pass all layers.
- **Fix:** Convert non-string values to string for pattern matching.

### C-09: Sequential Regex Corrupts Redacted Text
- **File:** `src/redaction/scanner.rs:103-119`
- **Impact:** After first `[REDACTED]` replacement, subsequent patterns re-match within replacement text.
- **Fix:** Track match spans, skip overlapping regions; or apply all patterns to original text, merge spans before replacement.

### C-10: No Process Group Isolation
- **File:** `src/run.rs` (CommandBuilder)
- **Impact:** Child shares parent process group. `kill(-child_pid, SIGINT)` ineffective without `setsid`/`setpgid`.
- **Fix:** `pre_exec(|| { libc::setsid(); Ok(()) })` or `process_group(0)`.

### C-11: No Zombie Reaping for Grandchildren
- **File:** `src/run.rs`
- **Impact:** `child.wait()` only reaps direct child. Shell/build subprocesses become zombies.
- **Fix:** Process group + `killpg`, or SIGCHLD reaper task.

### C-12: PTY Master Mutex Poison on Resize
- **File:** `src/run.rs:316-328, 370, 599`
- **Impact:** `master.lock()` in reader/writer setup races with resize_handle. Mutex poison on concurrent drop.
- **Fix:** Extract reader/writer before spawning resize task, or use `try_lock` with retry.

---

## HIGH Findings

### Security

| ID | File | Description |
|----|------|-------------|
| H-01 | `core/blob.rs:25-27` | BlobReference key unvalidated — path traversal via `../` escapes blob_dir |
| H-02 | `serve.rs:176-180` | Stored XSS via `insertAdjacentHTML` — run tags execute arbitrary JS |
| H-03 | `serve.rs:108` | Timing-vulnerable token comparison (`==` not constant-time) |
| H-04 | `serve.rs:833-835` | `urlencoding()` is no-op identity function — future XSS risk |
| H-05 | `serve.rs:88-92` | Dashboard unauthenticated by default |
| H-06 | `redaction/scanner.rs:73-76` | Regex catastrophic backtracking on large inputs (`{16,}` unbounded) |
| H-07 | `redaction/scanner.rs` | Missing patterns: Google AIza, Stripe, Azure, Heroku, Discord, npm, PyPI, Cloudflare |
| H-08 | `export/mod.rs:54-58` | Blob preservation creates redaction gap — secrets in blobs survive export |
| H-09 | `storage/sqlite.rs:694-702` | store_blob TOCTOU race — `exists()` + non-atomic write |

### Correctness

| ID | File | Description |
|----|------|-------------|
| H-10 | `pipeline/event_writer.rs:46-51` | Relaxed atomic ordering on ARM64 — non-monotonic sequences |
| H-11 | `capture/mod.rs:35` | Untracked JoinHandles in merge_layers — lost panics |
| H-12 | `capture/git.rs:~160` | Unbounded diff size — multi-MB diffs stored without limit |
| H-13 | `capture/git.rs` | No git submodule handling — misses submodule changes |
| H-14 | `adapters/parse.rs:90-91` | Byte-slice truncation panics on non-ASCII boundaries |
| H-15 | `adapters/claude.rs:82-86` | Duplicate parse_plaintext — double tool.call/session events |
| H-16 | `analysis/correlator.rs:33-42` | Temporal-only correlation — false positives within 500ms |
| H-17 | `analysis/error_detector.rs:76` | Rust error code extraction off-by-one |
| H-18 | `cli.rs:1428` | Replay doesn't set exit code on failure |
| H-19 | `cli.rs:1590` | Discarded update_run error in analyze --persist |

### Process Lifecycle

| ID | File | Description |
|----|------|-------------|
| H-20 | `run.rs:580-584` | 24h hardcoded timeout — no SIGKILL escalation |
| H-21 | `run.rs:388-396` | No SIGTERM/SIGKILL escalation — only SIGINT |
| H-22 | `run.rs:248-252` | Event merging fixed priority — not temporally ordered |
| H-23 | `run.rs:608-612` | Output handle 2s timeout silently discards events |
| H-24 | `run.rs:619-621` | End checkpoint session_id lost on store failure |
| H-25 | `run.rs:603-607` | Capture layer stop() failures swallowed |

### Concurrency

| ID | File | Description |
|----|------|-------------|
| H-26 | `storage/sqlite.rs:381-710` | std::sync::Mutex blocks tokio worker threads |
| H-27 | `run.rs:639-655` | Capture layers stop AFTER event_writer timeout — event loss |
| H-28 | `serve.rs:521-703` | SSE thundering-herd SQLite contention |

---

## MEDIUM Findings

### Redaction & Analysis (8)
| ID | File | Description |
|----|------|-------------|
| M-01 | `redaction/environment.rs:30-31` | `contains('TOKEN')` over-matches — INPUT_TOKENIZER etc. |
| M-02 | `redaction/scanner.rs:73-76` | OpenAI sk- pattern too broad — matches sk-middleware, sk-learn |
| M-03 | `redaction/scanner.rs:89-92` | SSH pattern only matches BEGIN marker — body not scanned |
| M-04 | `analysis/error_detector.rs:110-126` | Python traceback ignores chained exceptions |
| M-05 | `analysis/error_detector.rs:131-145` | Test failure detection false positives — `contains('FAILED')` unanchored |
| M-06 | `analysis/classifier.rs:65-67` | Destructive detection via substring — `rm -rf` matches echo |
| M-07 | `analysis/correlator.rs:49-58` | System events boost without semantic basis |
| M-08 | `analysis/error_detector.rs:81-95` | JS error detection matches non-error strings |

### Storage & Pipeline (7)
| ID | File | Description |
|----|------|-------------|
| M-09 | `pipeline/event_writer.rs:63-64` | Mutex poison hard-fail — kills all subsequent writes |
| M-10 | `pipeline/event_writer.rs:67-69` | Pre-assigned sequences can overlap auto-assigned |
| M-11 | `config.rs:36` | BLACKBOX_DB empty string treated as unset |
| M-12 | `config.rs:39` | Legacy path TOCTOU — `exists()` + `open()` |
| M-13 | `storage/sqlite.rs` | Missing migration transactions — partial schema on crash |
| M-14 | `storage/sqlite.rs` | No blob GC — orphaned blobs accumulate |
| M-15 | `storage/sqlite.rs:470-490` | delete_run non-atomic — partial delete on crash |

### Terminal & Capture (6)
| ID | File | Description |
|----|------|-------------|
| M-16 | `terminal/recorder.rs:15` | Unbounded segment accumulation — OOM risk |
| M-17 | `terminal/coalesce.rs:59` | Unbounded insecure_raw when store_raw=true |
| M-18 | `capture/filesystem.rs:281-288` | Bridge shutdown race — 100ms grace too tight |
| M-19 | `capture/git.rs` | Blocking sync git commands in async context |
| M-20 | `capture/process.rs` | Entirely a stub — no /proc parsing |
| M-21 | `capture/filesystem.rs` | No event coalescing despite comment |

### Adapters (4)
| ID | File | Description |
|----|------|-------------|
| M-22 | `adapters/native_logs.rs:201-209` | Silent metadata loss on serialization failure |
| M-23 | `adapters/native_logs.rs:147-158` | Rotation detection misses inode change |
| M-24 | `adapters/native_logs.rs:224-226` | Hardcoded 500-event rate limit per file |
| M-25 | `adapters/generic.rs:68-75` | Indented error banners not detected |

### Export & UI (7)
| ID | File | Description |
|----|------|-------------|
| M-26 | `export/mod.rs:72-75` | HTML redactor wraps entire doc as one string |
| M-27 | `export/mod.rs:59` | Portable redact clones entire blob map |
| M-28 | `export/portable.rs:89-94` | Blob hash mismatch creates broken reference |
| M-29 | `ui/tui.rs:301-320` | Event metadata preview no size limit |
| M-30 | `ui/tui.rs:171-188` | select_run silently swallows DB errors |
| M-31 | `ui/tui.rs:337-382` | Terminal cleanup uses `let _ =` — raw mode stuck |
| M-32 | `ui/tui.rs:115-119` | No Event::Resize handling |

### CLI & Run (10)
| ID | File | Description |
|----|------|-------------|
| M-33 | `cli.rs:664,679` | UTF-8 panic in runs label/tags truncation |
| M-34 | `cli.rs:985` | UTF-8 panic in show transcript truncation |
| M-35 | `cli.rs:1141,1157` | UTF-8 panic in inspect blob/metadata |
| M-36 | `cli.rs:1824` | rm single-run delete has no --yes gate |
| M-37 | `cli.rs:1393-1431` | Conflicting replay flags not validated |
| M-38 | `cli.rs:265` | --semantic defaults false in timeline (inconsistent with watch) |
| M-39 | `cli.rs:1755` | Silent --interval-ms floor in watch |
| M-40 | `run.rs:197-201` | Unnecessary env_vars.clone() when redact=false |
| M-41 | `run.rs:341-356` | PTY buffer backpressure stalls child |
| M-42 | `run.rs:390-396` | ESRCH warning fires on normal exit |

---

## LOW Findings

| ID | File | Description |
|----|------|-------------|
| L-01 | `core/event.rs:143-149` | finish() redundant if-let — dead branch |
| L-02 | `core/blob.rs:11,25` | size field always 0 in callers |
| L-03 | `core/checkpoint.rs:37-39` | No validation run_id/event_id non-empty |
| L-04 | `core/run.rs:84-87` | allocate_sequence wraps at u64::MAX |
| L-05 | `core/run.rs:106-109` | RunHandle dead code — exported but unused |
| L-06 | `terminal/transcript.rs` | TranscriptIndexer entirely stub |
| L-07 | `ui/diff.rs`, `ui/process_tree.rs` | Pure stubs — placeholder text |
| L-08 | `ui/mod.rs:10-13` | Panel trait unused — dead abstraction |
| L-09 | `ui/tui.rs:90` | Timeline displays UTC without Z suffix |
| L-10 | `ui/tui.rs:80,180` | Redundant events.clone() on every frame |
| L-11 | `export/jsonl.rs` | No import_jsonl — round-trip impossible |
| L-12 | `export/portable.rs:178-184` | collect_blob_keys heuristic fragile |
| L-13 | `adapters/claude.rs:41-43` | Dead branch in detect() |
| L-14 | `adapters/native_logs.rs:85-112` | Blocking I/O in async poll loop |
| L-15 | `adapters/launch.rs:38-49` | Flag injection assumes POSIX ordering |
| L-16 | `capture/filesystem.rs` | Symlink following in walk_snapshot |
| L-17 | `capture/git.rs` | Inconsistent ignore lists |
| L-18 | `cli.rs:644-650` | Lenient --status substring matching |
| L-19 | `cli.rs:1170-1270` | No warning when diffing run against itself |
| L-20 | `cli.rs:1272-1297` | Export has no --output flag |
| L-21 | `cli.rs:1300-1328` | import --keep-ids conflict not pre-validated |
| L-22 | `cli.rs:1714-1750` | Watch has no initial output cap |
| L-23 | `cli.rs:732-761` | Tag --add/--rm overlap silently resolves to add |
| L-24 | `run.rs:547-550` | line_buf unbounded — no-newline output grows |
| L-25 | `run.rs:271-274` | Terminal size defaults 24×80 silently |
| L-26 | `run.rs:385-386` | child_pid=0 causes kill(0, SIGINT) |
| L-27 | `serve.rs` | SSE ticks_idle double-incremented |
| L-28 | `serve.rs` | Token in URL query string — browser history leak |
| L-29 | `sync.rs` | --no-redact on push with no warning |
| L-30 | `search.rs` | Fallback scan loads all events per run |

---

## Performance Issues

| Priority | File | Description |
|----------|------|-------------|
| P-01 | `storage/sqlite.rs` | Mutex<Connection> serializes all DB access |
| P-02 | `scrub.rs` | N+1: runs→events→blobs with per-run queries |
| P-03 | `search.rs` | N+1: get_event()+get_run() per FTS hit |
| P-04 | `run.rs` | SecretScanner::new() compiles 11+ regexes per run (3+ sites) |
| P-05 | `redaction/scanner.rs` | redact() allocates new String per regex |
| P-06 | `export/portable.rs` | Loads every blob fully + base64 — unbounded memory |
| P-07 | `capture/git.rs` | String::from_utf8_lossy double-allocation per git command |
| P-08 | `capture/filesystem.rs` | Blocking std::fs::metadata in event loop |
| P-09 | `serve.rs` | index() loads all runs; api_events loads all events |
| P-10 | `pipeline/event_writer.rs` | tool_fingerprint allocates serde_json String |

---

## Concurrency Issues

| Priority | File | Description |
|----------|------|-------------|
| CONC-01 | `capture/mod.rs:35` | Untracked JoinHandles — lost panics |
| CONC-02 | `storage/sqlite.rs` | std::sync::Mutex blocks tokio workers |
| CONC-03 | `run.rs:639-655` | Shutdown order wrong — layers stop after writer timeout |
| CONC-04 | `capture/filesystem.rs:281-288` | Bridge abort gap — 100ms grace too tight |
| CONC-05 | `serve.rs:521-703` | SSE thundering-herd SQLite contention |
| CONC-06 | `pipeline/event_writer.rs` | Relaxed atomics on ARM64 |
| CONC-07 | `scrub.rs:173-188` | gc_orphan_blobs blocks tokio worker |
| CONC-08 | `run.rs:384-401` | Stale child PID in signal handler |

---

## Missing Test Coverage

### Zero test modules (critical gaps):
- `core/event.rs`, `core/blob.rs`, `core/checkpoint.rs`, `core/run.rs` — no unit tests
- `terminal/ansi.rs` — no tests for normalize
- `terminal/recorder.rs` — no tests
- `terminal/transcript.rs` — stub, no tests
- `capture/git.rs`, `capture/process.rs`, `capture/pty.rs` — no tests
- `redaction/environment.rs` — no tests
- `redaction/export.rs` — no tests
- `adapters/` — minimal tests (parse.rs only)
- `cli.rs` — zero unit tests (2009 lines, 22 subcommands)
- `ui/` — no tests (TUI rendering)

### Existing tests with gaps:
- `analysis/error_detector.rs` — no chained Python, empty metadata tests
- `analysis/correlator.rs` — no 30s boundary, same-timestamp tests
- `redaction/scanner.rs` — no false positive, large input, unicode tests
- `export/html.rs` — test doesn't verify metadata secret redaction in detail column
- `export/portable.rs` — test doesn't verify parent_event_id remapping

---

## Implementation Plan — Fix Priority

### Phase 1: CRITICAL Fixes (Immediate)
1. **C-01:** Rewrite `AnsiNormalizer::normalize()` to operate on chars, not bytes
2. **C-02/C-04/C-05:** Create `fn char_trunc(s: &str, max: usize) -> &str` helper, replace all `&s[..N]`
3. **C-03:** Fix TUI `&run.id[..8]` to use `.get(..8).unwrap_or()`
4. **C-06:** Fix HTML export to use redacted JSON for detail extraction
5. **C-07:** Fix portable import to remap parent_event_id
6. **C-08:** Fix redact_json to handle non-string values
7. **C-09:** Fix sequential regex to track match spans
8. **C-10/C-11:** Add process group isolation and zombie reaping
9. **C-12:** Fix PTY master mutex race

### Phase 2: HIGH Fixes
1. **H-01:** Validate BlobReference key as hex SHA-256
2. **H-02:** Fix insertAdjacentHTML to use textContent for tags
3. **H-04:** Implement proper urlencoding
4. **H-09:** Fix store_blob with atomic write (write-to-temp + rename)
5. **H-10:** Change atomic ordering to AcqRel/Acquire
6. **H-14:** Fix parse.rs byte-slice truncation
7. **H-15:** Remove duplicate parse_plaintext in Claude/Codex
8. **H-20/H-21:** Add SIGTERM/SIGKILL escalation
9. **H-26:** Consider tokio::sync::Mutex or spawn_blocking wrapper

### Phase 3: MEDIUM Fixes + Tests
1. Fix all M-series findings
2. Add unit tests for all modules with zero coverage
3. Add integration tests for critical paths

### Phase 4: LOW Polish
1. Fix L-series findings
2. Remove dead code (RunHandle, Panel trait, stubs)
3. Document known limitations
