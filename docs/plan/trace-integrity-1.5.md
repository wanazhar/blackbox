# Blackbox 1.5 — Trace Integrity & Scale

| Field | Value |
|---|---|
| **Document** | Product + technical plan for 1.5 |
| **Date** | 2026-07-20 |
| **Status** | **In progress** — Phase A started |
| **Baseline** | 1.4.0 (Trust Proof shipped) |
| **Target tag** | **1.5.0** |
| **Epic** | [Issue #3](https://github.com/wanazhar/blackbox/issues/3) |
| **North star** | Large runs stay factually correct; retries survive; replay states real isolation; imports cannot corrupt the store; capture stays bounded; docs are verified engineering prose |

---

## Why 1.5 exists

| Version | Question answered |
|---|---|
| **1.0–1.2** | Capability, leave-on, project memory |
| **1.3** | When it fails, get a story and jump target fast |
| **1.4** | Prove neutrality, redaction, causality, Unix qualification |
| **1.5** | After trust: does the trace remain **correct at scale**? |

1.4 made the recorder safe to leave on. 1.5 makes continuous use honest under load: long-run totals independent of display windows, safe tool dedupe, contained/reproducible restore, durable imports, bounded capture, and human documentation.

### Release contract

> A large run remains correctly summarized; repeated actions are preserved; replay states and enforces its real isolation level; imports cannot corrupt the content-addressed store; capture remains bounded under load; and the documentation is concise, verified engineering documentation rather than generated-sounding product copy.

### Platform policy (unchanged)

- **Tier 1:** Linux x86_64 / ARM64; macOS Apple Silicon; macOS x86_64 where practical
- **Best effort:** other POSIX
- **Out of scope:** Windows

---

## 1.5 bar (exit criteria)

| Id | Criterion | Intent |
|---|---|---|
| **L1** | Long-run aggregates | Totals and first/last anchors independent of event load caps |
| **L2** | Explicit analysis scope | Summary/postmortem expose `analysis_scope` (loaded vs total, strategy, limitations) |
| **D1** | Safe tool dedupe | ID-less retries preserved; merge only proven cross-source duplicates |
| **O1** | Event clocks / ordering | Source sequences + occurrence vs ingestion order (Phase A/B) |
| **R1** | Replay honesty | Workspace replay renamed; contained Linux backend + capability preflight |
| **W1** | Workspace checkpoints | Binary/untracked restore with completeness report |
| **A1** | Archive atomicity | Hash-validated portable import; no partial permanent state |
| **S1** | Batched storage ingest | Bounded queue + dedicated writer + barriers |
| **C1** | Capture boundaries | Bounded FS/native-log ingest; symlink scope; rotation |
| **H1** | Dashboard auth | Browser session flow + bearer API + optional UDS |
| **P1** | Scale APIs | Cursor pagination, blob compression, streaming portable |
| **Q1** | Tier-1 qualification | macOS runtime gate + Linux full qualify |
| **X1** | Docs truth | Inventory, one source of truth, executable examples, human rewrite |
| **U1** | Supervisor decomposition | Explicit stages; rollup recomputable |

Permanent 1.4 trust gates (N1/N2, S1 holdback, G1, C1–C3, Q1 Unix) remain green.

Full acceptance criteria: [issue #3 comments](https://github.com/wanazhar/blackbox/issues/3).

---

## Workstreams

| WS | Theme | Phase |
|---|---|---|
| 1 | Long-run truth (aggregates + salient load + analysis_scope) | **A** |
| 2 | Event time and ordering | A / later |
| 3 | Safe tool deduplication | **A** |
| 4 | Replay naming and containment | B |
| 5 | Workspace checkpoints | B |
| 6 | Transactional patch restore | B |
| 7 | Portable import integrity | C |
| 8 | Batched storage ingest | C |
| 9 | Filesystem capture boundary | D |
| 10 | Native-log ingest boundary | D |
| 11 | Dashboard authentication | D |
| 12 | Documentation inventory + rewrite | E (inventory early) |
| 13 | Pagination / compression / streaming archives | C |
| 14 | Tier-1 Unix CI / release policy | D / E |
| 15 | Supervisor decomposition | after boundaries stabilize |

---

## Implementation phases

### Phase A — Correct long-run truth

- [x] Plan + roadmap for 1.5
- [x] Incremental recoverable `run_aggregates` (schema v7+)
- [x] Salient-event retrieval (head/tail + errors + human + capture health)
- [x] `analysis_scope` on summary/postmortem JSON
- [x] Tool totals/facts from aggregates, not display windows
- [x] Safe tool dedupe: preserve ID-less retries; LRU/age cache; provenance annotation
- [x] Event clocks / source sequences / occurrence relations (O1)
- [x] Gates: `tests/long_run_integrity.rs`, `tests/tool_dedup.rs`, `tests/event_ordering.rs`

**Exit:** A large-run fixture reports exact totals; early instruction/failure remain visible; `--short`/`--full` alter detail only. **Met for Phase A core on Linux (PR gates).**

### Phase B — Reproducible / contained replay

- [x] Rename workspace-only mode; do not claim kernel isolation (`--workspace`, capability report)
- [x] Path-safe transactional patch restore (stage + promote; no `--unsafe-paths`)
- [x] Workspace manifest + completeness report (`workspace_manifest` + end checkpoint blob)
- [ ] Optional Linux contained backend (bubblewrap/namespaces) + capability preflight
- [x] Gate: `tests/patch_path_safety.rs`
- [x] Gate: `tests/workspace_checkpoint.rs`
- [ ] Gate: `tests/replay_containment_linux.rs`

### Phase C — Durable storage / imports

- [x] Hash-validated atomic portable import (hash match required; batch events; rollback journal)
- [x] Batched SQLite writer + barriers + observability (`BatchIngestor` / `EventWriter::new_batched`)
- [x] Cursor pagination APIs (`list_runs_page`, `get_events_range`, kind pages)
- [x] Blob compression before encryption (BBZC zlib); streaming portable format deferred
- [x] Gate: `tests/portable_import_atomicity.rs`
- [x] Gate: `tests/storage_batch_faults.rs`
- [x] Gate: `tests/pagination_scale.rs`

### Phase D — Capture / platform operations

- [x] Bounded FS watcher + shared ignore policy + symlink scope (C1)
- [x] Native-log rotation / identity tracking + backlog honesty
- [x] Dashboard session auth + bearer API + optional UDS (`--unix-socket`)
- [x] macOS runtime PR gate (`.github/workflows/ci.yml` job `macos`)
- [x] Gate: `tests/filesystem_escape.rs`
- [x] Gate: `tests/native_log_rotation.rs`
- [x] Gate: `tests/dashboard_auth.rs`

### Supervisor decomposition (U1)

- [x] `RunStage` / `ShutdownReason` lifecycle types
- [x] `supervisor::rollup` — coverage recomputable without PTY
- [x] `supervisor::checkpoint` — end checkpoint + workspace manifest builder
- [x] `run.rs` orchestrates stages; PTY pump remains in run for now
- [ ] Full PtyPump / EventIngestor / ShutdownCoordinator extraction (follow-up)

### Phase E — Documentation rewrite + release

- [x] Machine-readable docs inventory (`docs/inventory.json` + `docs/inventory.md`)
- [x] WRITING.md 1.5 rewrite standard
- [ ] Consolidate operator navigation; archive completed plans from primary nav
- [ ] Claim matrix; executable examples; symptom-first troubleshooting
- [ ] Docs CI extensions (duplicate/command gates)
- [ ] Human editorial pass; release notes without marketing copy
- [ ] Cargo **1.5.0** + qualify + tag

---

## Recommended implementation order

1. Long-run aggregates and explicit analysis scope ← **current**
2. Safe tool deduplication ← **current**
3. Portable import hash validation and atomic staging
4. Rename workspace replay and remove unsafe patch paths
5. Batched storage writer
6. Workspace checkpoint completeness
7. Event clocks and bounded reordering
8. Bounded filesystem/native-log ingest
9. Dashboard authentication flow
10. Pagination/compression/streaming archive
11. macOS runtime qualification
12. Supervisor decomposition as boundaries stabilize

Begin documentation inventory early; final rewrite after command names and replay terminology stabilize.

---

## Suggested tests

```text
tests/long_run_integrity.rs
tests/event_ordering.rs
tests/tool_dedup.rs
tests/workspace_checkpoint.rs
tests/replay_containment_linux.rs
tests/patch_path_safety.rs
tests/portable_import_atomicity.rs
tests/storage_batch_faults.rs
tests/filesystem_escape.rs
tests/native_log_rotation.rs
tests/dashboard_auth.rs
tests/pagination_scale.rs
tests/docs_commands.rs
tests/docs_config_contract.rs
tests/docs_json_examples.rs
```

Move expensive scale/storm suites to scheduled or release qualification when unsuitable for every PR.

---

## Non-goals (standing for 1.5)

- Windows support
- Deterministic full LLM re-execution as “replay”
- Multi-tenant hosted SaaS
- Replacing harness session UIs
- Physical secure erase of secrets already written under `--insecure-raw`

---

## Related

- Epic: [issue #3](https://github.com/wanazhar/blackbox/issues/3)
- Prior: [plan/trust-proof-1.4.md](trust-proof-1.4.md)
- Roadmap: [docs/ROADMAP.md](../ROADMAP.md)
- Changelog: [CHANGELOG.md](../../CHANGELOG.md)
