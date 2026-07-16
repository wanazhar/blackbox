# Blackbox Recorder — Comprehensive Codebase Audit

> **Historical audit snapshot (2026-07-12), not product documentation.**  
> Current operator docs: [README.md](README.md) · [guide/README.md](guide/README.md).  
> Current quality bar: [ROADMAP.md](ROADMAP.md). Security model: [guide/security.md](guide/security.md).

**Date:** 2026-07-12  
**Last Updated:** 2026-07-12 (re-verified; residual fixes applied)  
**Scope:** Full `src/` tree at that time  
**Method:** multi-agent audit  
**Baseline then:** unit + integration tests green  

---

## Executive Summary

| Severity | Count | Fix Required | Fixed |
|----------|-------|-------------|-------|
| CRITICAL (Round 1) | 12 | Yes — data loss, panics, security bypass | **12/12** ✅ |
| HIGH (Round 1) | 28 | Yes — correctness, security, reliability | **28/28** ✅ |
| MEDIUM (Round 1) | 42 | Recommended | **42/42** ✅ |
| LOW (Round 1) | 30 | Optional | **28/30** ✅ (L-20, L-22 deferred) |
| CRITICAL (Round 2) | 3 | Yes — data loss, panics, bypass | **3/3** ✅ |
| HIGH (Round 2) | 21 | Yes — correctness, security, reliability | **21/21** ✅ |
| MEDIUM (Round 2) | 20 | Recommended | **20/20** ✅ |
| **Total** | **~156** | | **154/156** ✅ |

**Re-verification notes (post-claim audit):** Most Round 1/2 items were correctly implemented. Two claimed fixes were incomplete and are now corrected:

1. **R2-H3 blob GC was inverted** — `collect_referenced_blobs` treated every `blobs` table key as live, so orphan GC after `delete_run` / scrub rewrites was a no-op (old secret blobs stayed on disk). Fixed: only event/checkpoint/metadata refs are live; GC deletes files **and** prunes metadata rows.
2. **R2-C3 shell block was incomplete** — `is_readonly_command` rejected shells, but allowed Read-tagged shell events skipped that check entirely. Fixed: shell interpreters are blocked under every policy except Live (basename + absolute-path aware).

Also fixed residual UTF-8 byte slice in `pipeline/event_writer.rs` (same class as C-02/H-11).

**Architecture assessment:** Well-designed with clean module boundaries, consistent `anyhow::Result` error handling, and solid redaction-by-default posture. WAL + busy_timeout SQLite setup is correct. Bounded channels provide natural backpressure. Content-addressed blobs enable deduplication.

---

## Round 1 Findings — Status

All 12 CRITICAL, 28 HIGH, 42 MEDIUM — **verified fixed**.
LOW: 28/30 fixed; **L-20** (`export --output`) and **L-22** (watch buffer cap) remain optional deferred TODOs in `cli.rs`.

### Top 5 Most Dangerous Issues (All Fixed ✅)
1. **Non-ASCII content erased** — `is_ascii_graphic` removed; char-level iteration
2. **Byte-index panics** — `floor_char_boundary()` / `util::truncate` across truncate sites
3. **Path traversal** — `BlobReference::try_new()` validates hex keys; `new()` asserts
4. **HTML secret leak** — `event_detail()` uses redacted JSON, no innerHTML
5. **No process group isolation** — portable-pty `setsid()` + `kill(-pid, …)` group signals

### CRITICAL Details (C-01 through C-12)
All 12 verified fixed. Key fixes:
- C-01: `is_ascii_graphic` removed; char-level UTF-8 safe iteration
- C-02: `self.text.floor_char_boundary(200)` in coalescer
- C-03: `.get(..8).unwrap_or(&run.id)` / `short_id` with `min` in TUI/CLI
- C-04: `combined.floor_char_boundary(MAX_DIFF_BYTES)` in git diff
- C-05: Shared `truncate()` in `util.rs` using `floor_char_boundary`
- C-06: `event_detail()` receives redacted `ev_json`; no innerHTML/insertAdjacentHTML
- C-07: old→new ID map remaps all `parent_event_id`
- C-08: `redact_json_inner` recursively visits all JSON types; depth limit 32
- C-09: Span-overlap merging prevents re-redaction of `[REDACTED]`
- C-10: portable-pty `pre_exec` calls `libc::setsid()`; `kill(-child_pid, signal)` targets entire group
- C-11: Process group isolation via setsid
- C-12: `parking_lot::Mutex` — no poison on panic

### HIGH (H-01 through H-28) & MEDIUM (M-01 through M-42) & LOW (L-01 through L-30)
All CRITICAL/HIGH/MEDIUM verified. LOW: L-20 and L-22 intentionally deferred (TODOs remain in `cli.rs`).

---

## Round 2 Findings — Verified Status

### CRITICAL (R2-C1 through R2-C3) — All Fixed ✅

| ID | Description | Fixed By | Status |
|----|-------------|----------|--------|
| R2-C1 | Mutex poisoning recovery | Earlier | ✅ parking_lot doesn't poison; test confirms |
| R2-C2 | Migrations not transactional | Earlier | ✅ Each step wrapped in unchecked_transaction() |
| R2-C3 | Sandbox sh passthrough | **Re-verified + completed** | ✅ Shells blocked for all non-Live policies (not only via is_readonly) |

### HIGH (R2-H1 through R2-H21) — All Fixed ✅

| ID | Description | Fixed By | Status |
|----|-------------|----------|--------|
| R2-H1 | Atomic FTS upsert | Earlier | ✅ Transaction wraps both INSERT + FTS |
| R2-H2 | Batch FTS backfill (OOM) | Earlier | ✅ V4 migration uses batches of 500 |
| R2-H3 | Blob GC reference collection | **Re-fixed** | ✅ Live refs only; GC files + prune metadata |
| R2-H4 | Transactional delete_run | Earlier | ✅ Transactional; test confirms |
| R2-H5 | WAL checkpoint management | Earlier | ✅ pub wal_checkpoint() + post-migration/batch |
| R2-H6 | DCS/APC/SOS/PM stripping | Earlier | ✅ Present in ansi.rs |
| R2-H7 | Unbounded RawRecorder | Earlier | ✅ MAX_SEGMENTS cap with eviction |
| R2-H8 | Duplicate parse_plaintext | Earlier | ✅ Post-loop fallback removed |
| R2-H9 | Codex double-parses | Earlier | ✅ already_has_tool_call guard |
| R2-H10 | innerHTML XSS in serve | Earlier | ✅ textContent throughout |
| R2-H11 | Byte-slicing in git diff | Earlier | ✅ floor_char_boundary at all locations |
| R2-H12 | Unbounded diff allocation | Earlier | ✅ MAX_DIFF_BYTES (1 MiB) |
| R2-H13 | Sandbox sh passthrough | **Re-fixed with R2-C3** | ✅ Same as R2-C3 |
| R2-H14 | Temp dir leak on panic | Earlier | ✅ TempDirGuard with Drop impl |
| R2-H15 | Byte-slicing in mock.rs | Earlier | ✅ floor_char_boundary in truncate |
| R2-H16 | Checksum verification on sync | Earlier | ✅ SHA-256 in manifests; verified on pull |
| R2-H17 | S3 pull checksum | Earlier | ✅ SHA-256 verified on pull |
| R2-H18 | Byte-index in search.rs | Earlier | ✅ floor_char_boundary in truncate |
| R2-H19 | FTS5 query injection | Earlier | ✅ Special chars stripped; sentinel guard |
| R2-H20 | Depth limit on redaction | Earlier | ✅ max_depth: 32 in redact_json_inner |
| R2-H21 | Duration overflow guard | Earlier | ✅ Negative clamped to 0 in event_from_row |

### MEDIUM (R2-M1 through R2-M20)

| ID | Description | Fixed By | Status |
|----|-------------|----------|--------|
| R2-M1 | ON DELETE CASCADE | Earlier | ✅ events use CASCADE; checkpoints SET NULL |
| R2-M2 | serde_json unwrap_or_default() | Earlier | ✅ Pre-serialized; errors propagate |
| R2-M3 | Missing indexes | Earlier | ✅ V5 migration adds both indexes |
| R2-M4 | FTS double-indexes | Earlier | ✅ event_search_body excludes them |
| R2-M5 | Vec<char> allocation per chunk | Earlier | ✅ Byte-offset iteration in ansi.rs |
| R2-M6 | Double normalization | Earlier | ✅ No longer present |
| R2-M7 | line_buf unbounded | Earlier | ✅ MAX_SEGMENTS cap |
| R2-M8 | ends_with detection | Earlier | ✅ Exact basename match |
| R2-M9 | Resume flag missing -- | Earlier | ✅ --resume in both adapters |
| R2-M10 | harness.result hardcoded | Earlier | ✅ Checks is_error field |
| R2-M11 | Body size limit | Earlier | ✅ 10MB MAX_SYNC_BODY |
| R2-M12 | AppError always 500 | Earlier | ✅ 4 differentiated error types |
| R2-M13 | Blob hash mismatch | Earlier | ✅ try_new in all external paths |
| R2-M14 | find_parent O(n) | Earlier | ✅ BTreeMap index for batch path |
| R2-M15 | rm without flags | Earlier | ✅ Bare rm → Destructive |
| R2-M16 | Path canonicalization | Earlier | ✅ canonicalize in config.rs |
| R2-M17 | Workspace path injection | Earlier | ✅ sanitize_run_id |
| R2-M18 | Bridge task leak | Earlier | ✅ timeout + abort() |
| R2-M19 | Blocking git in async | Earlier | ✅ spawn_blocking wrapper |
| R2-M20 | Default config | Earlier | ✅ --no-redact; explicit config |

---

## Performance & Concurrency

All 10 performance items (P-01..P-10) are acceptable at current scale.
**CONC-07** (gc_orphan_blobs blocking tokio) fixed via spawn_blocking. Remaining concurrency items are low-risk edge cases.

**Note:** `gc_unreferenced_blobs` should not run concurrently with an active recording that may store blobs not yet linked from events (documented race window).

---

## Test Coverage — Current Status

| Module | Tests | Status |
|--------|-------|--------|
| core/event.rs | 10 | ✅ |
| core/blob.rs | 9 | ✅ |
| core/checkpoint.rs | 3 | ✅ |
| core/run.rs | 7 | ✅ |
| terminal/ansi.rs | 16 | ✅ |
| terminal/coalesce.rs | 5 | ✅ |
| terminal/recorder.rs | 9 | ✅ |
| capture/git.rs | 9 | ✅ |
| capture/process.rs | 8 | ✅ |
| capture/pty.rs | 7 | ✅ |
| redaction/scanner.rs | 12+ | ✅ |
| redaction/environment.rs | 16 | ✅ |
| redaction/export.rs | 8 | ✅ |
| scrub.rs | GC + scrub | ✅ includes orphan reclaim after delete/scrub |
| replay/sandbox.rs | shell block | ✅ R2-C3 unit + integration-style |
| cli.rs | 12 | ✅ |
| ui/ | 0 | ⏳ TUI requires terminal emulator for meaningful tests |

---

## Remaining Work — Final Status

All 12 CRITICAL, 28 HIGH, 42 MEDIUM (Round 1) — **fixed** ✅
LOW (Round 1): **28/30** — L-20 (`export -o`) and L-22 (watch buffer cap) deferred as optional UX polish
All 3 CRITICAL, 21 HIGH, 20 MEDIUM (Round 2) — **fixed** ✅ (R2-H3 and R2-C3 completed correctly on re-verify)

**Performance (P-01..P-10):** All acceptable at current scale for single-user CLI/dashboard.

**Concurrency (CONC-01..08):** All acceptable — fixed or documented edge cases.

| Priority | Area | Status |
|----------|------|--------|
| — | R2-H3 blob GC | **✅ Corrected** — live refs only; file + metadata prune |
| — | R2-C3 shell sandbox | **✅ Corrected** — block shells unless Live |
| — | event_writer UTF-8 slice | **✅ Fixed** — uses util::truncate |
| ⏳ | L-20 export --output | Deferred optional |
| ⏳ | L-22 watch buffer cap | Deferred optional |
| ⏳ | ui/ tests | TUI requires terminal emulator — acceptable gap |

---

## Fix History

| Commit | Items | Author |
|--------|-------|--------|
| `27bebb5` | Round 1 + 91 tests | Previous agent |
| `f034b76` | Round 2 XSS, DCS, duplicates | Previous agent |
| `349dc98` | ~70 fixes across codebase | Previous agent |
| `238c05d` | All CRITICAL + HIGH | Previous agent |
| `c3d0905` | All MEDIUM + LOW | Previous agent |
| `eadaa42` | Rounds 3-40 (65 fixes + 20 tests) | Previous agent |
| `b6bb987` | Batch inserts, SIGTERM, CSP | This session |
| `fc3f377` | R2-H5, H19, C3, H3, H21 | **This session** (H3/C3 incomplete) |
| `824c074` | R2-H16 checksums | **This session** |
| `7d83090` | R2-M2 serde_json | **This session** |
| `b0c9176` | R2-M19 spawn_blocking git | **This session** |
| `0c4c5de` | R2-M3 indexes + CONC-07 | **This session** |
| `c795244` | core::checkpoint + run tests | **This session** |
| `40c026a` | ProcessCapture + PtyCapture tests | **This session** |
| `64ee511` | AUDIT.md coverage update; R2-M5 comment polish | **This session** |
| `97af774` | CLI tests; Vec<char> → byte-offset (R2-M5); AUDIT.md | **This session** |
| `HEAD` | Correct R2-H3 GC + R2-C3 shell block; UTF-8 slice; tests | **Re-verify session** |
