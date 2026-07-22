# Technical claim matrix

High-risk product claims classified by evidence. Update when tests or platforms change.

## Core (1.4–1.5)

| Claim | Class | Evidence / limitation |
|---|---|---|
| Recorder does not inject child-visible `BLACKBOX_*` control env | test-backed | `tests/neutrality_contract.rs`; PTY TTY differences remain |
| Nest guard works without child-visible active-run env | test-backed | Supervisor PID markers; `tests/neutrality_contract.rs` |
| Secrets are redacted before SQLite/blobs by default | test-backed | Holdback stream + store scan; `tests/redaction_*` |
| Physical secure erase of prior raw writes | best-effort | SSD/COW/WAL residuals; scrub is logical |
| Capture coverage is complete for all surfaces | platform-dependent | Process polling loss; native logs optional; `not_applicable` scoring |
| Process observation sees every short-lived child | best-effort | Spawn-storm measures loss; not eBPF |
| Replay is OS process isolation | best-effort / platform-dependent | **Workspace** = temp directory only; **`--contained`** = bubblewrap namespaces when `bwrap` present (fail closed otherwise); not multi-tenant hardened |
| Workspace restore is complete for all files | best-effort | Manifest limits (files/bytes/depth); report lists gaps; fidelity classes in restore report |
| Portable import preserves content-addressed integrity | test-backed | Hash must match; no rename-to-unverified-key; `tests/portable_import_atomicity.rs` |
| Crash recovery never invents success | test-backed | Abandoned `Running` → `Failed`; `tests/fault_recovery.rs` |
| Dashboard auth for browsers without tokens in URLs | test-backed | Session cookie + Bearer; `tests/dashboard_auth.rs` |
| Large-run totals independent of display windows | test-backed | Aggregates + `analysis_scope`; `tests/long_run_integrity.rs` |
| macOS full parity with Linux process backends | platform-dependent | PR runtime gate; full process matrix deferred |
| Windows support | planned / out of scope | Explicit non-goal for Unix-scoped releases |

## 1.6 verified runs & integrity

| Claim | Class | Evidence / limitation |
|---|---|---|
| Workspace capture never follows outside-root symlinks | test-backed | `tests/workspace_symlink_safety.rs`; lstat + O_NOFOLLOW |
| Sanitized restore is never reported as byte-exact | test-backed | `tests/restore_fidelity.rs`; completeness classes |
| Portable v2 rejects unresolved blob refs (empty map does not waive) | test-backed | `tests/portable_v2_references.rs` |
| Filtered run/event pagination applies filters before LIMIT | test-backed | `tests/pagination_filtered_scale.rs` |
| `file_ops` counts filesystem create/modify/rename/remove | test-backed | `tests/aggregate_semantics.rs` |
| Unique process count collapses resource samples | test-backed | `tests/aggregate_semantics.rs` |
| Nested blob refs remapped after scrub redaction | test-backed | `tests/blob_reference_rewrite.rs` |
| `fsck --deep` detects missing/corrupt referenced blobs | test-backed | `tests/fsck_corruption.rs` |
| Acknowledged spool batches survive crash and replay idempotently | test-backed | `tests/ingest_spool_recovery.rs`; CRC torn-write detection |
| Execution success ≠ task verification | test-backed | `tests/verification_receipts.rs`; immutable receipts |
| Experiment gates do not treat unverified success as verified | test-backed | `tests/regression_gate.rs`, `tests/experiment_reports.rs` |
| Capsules state completeness; model replay is not deterministic | test-backed | `tests/capsule_integrity.rs` |
| MCP cassette is experimental and scoped to proxied protocol | test-backed / experimental | `tests/mcp_cassette.rs`; proxy marks mock vs live |
| Budget capabilities never over-claim enforcement | test-backed / platform-dependent | `tests/budget_enforcement_linux.rs`, `tests/budget_cgroup_linux.rs`; wall watchdog + **child** `prlimit` (never supervisor `setrlimit`) + cgroup v2 when delegated; tool/output ceilings **enforced** mid-run via capture-path counters + SIGKILL |
| Domain-confirmed verification required for strict gates | test-backed / code-backed | `verification/domain.rs`; gate prefers `domain_confirmed_rate` |
| Portable import restores experiment meta and receipts | test-backed | portable round-trip unit test in `export/portable.rs` |
| Release publishes only when full matrix builds | code-backed | `.github/workflows/release.yml` fail-closed (`if: success()`, 4 artifacts) |
| Portable v2 rejects duplicate event IDs / sequences | test-backed | `tests/portable_v2_references.rs` |
| Postmortem/summary surfaces latest verification receipt + outcome | test-backed / code-backed | `SummaryView.latest_verification_*` + `outcome` via `list_verification_receipts` |
| MCP cassette live record/replay against a real stdio server | test-backed / experimental | `tests/mcp_record_e2e.rs` + `tests/fixtures/mcp_echo_server.py` |
| 100k-event endurance runs in default CI (not ignored) | test-backed | `tests/endurance_100k.rs`; CI job “Verified-runs gates (1.6)” |
| Multi-project index is metadata-only | test-backed | `tests/multi_project_index.rs` |
| 100k+ event endurance qualification | test-backed (release gate) | `tests/endurance_100k.rs` (`--ignored`); `scripts/release-qualify-unix.sh` |
| Crates.io publication proves runtime qualification | historical / false | Publish is packaging; runtime qualify is the script above |

## 1.7 agent boundary evidence (Phase A)

| Claim | Class | Evidence / limitation |
|---|---|---|
| Governed run can store immutable resolved boundary + policy hash | test-backed | `tests/boundary_contract.rs`; schema `blackbox.boundary/v1` |
| Configured containment is distinct from verified containment | test-backed | Claim states on `ContainmentReceipt`; configured-only fails required gate |
| Missing required evidence is explicit and fail-closed when configured | test-backed | `evaluate_required_evidence`; `gate_failed` only when `fail_closed` |
| Task success does not satisfy a required containment gate | test-backed | Evidence evaluator never consults exit code / verification status |
| Policy hash is stable for the same merged contract | test-backed | SHA-256 of canonical JSON; inheritance unit tests |
| Blackbox enforces sandbox/network policy by default | false / non-goal | Records authorization and evidence; not a firewall or EDR |
| External NDJSON evidence import is idempotent and path-safe | test-backed | `tests/boundary_1_7_full.rs`; rejects `..` / absolute path attrs |
| Trace-id alone never yields confirmed correlation | test-backed | `correlate::tests`; multi-signal required for confirmed without run_id |
| Deterministic detectors emit evidence-linked findings | test-backed | `boundary::detect`; `boundary detect` CLI |
| Correct task answer can fail provenance gate independently | test-backed | `evaluate_provenance` + full pipeline test |
| Multi-run incidents surface earliest signal and technique reuse | test-backed | `incident::graph` tests |
| Forensic packs validate citations and redact secret-like patterns | test-backed | `forensic::pack` tests |
| Blackbox blocks sandbox escapes by default | false / non-goal | Evidence only; no autonomous kill |

**Classes:** `code-backed` · `test-backed` · `platform-dependent` · `best-effort` · `planned` · `historical` · `experimental`.
