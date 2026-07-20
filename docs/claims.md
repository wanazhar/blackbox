# Technical claim matrix

High-risk product claims classified by evidence (1.5 docs truth). Update when
tests or platforms change.

| Claim | Class | Evidence / limitation |
|---|---|---|
| Recorder does not inject child-visible `BLACKBOX_*` control env | test-backed | `tests/neutrality_contract.rs`; PTY TTY differences remain |
| Nest guard works without child-visible active-run env | test-backed | Supervisor PID markers; `tests/neutrality_contract.rs` |
| Secrets are redacted before SQLite/blobs by default | test-backed | Holdback stream + store scan; `tests/redaction_*` |
| Physical secure erase of prior raw writes | best-effort | SSD/COW/WAL residuals; scrub is logical |
| Capture coverage is complete for all surfaces | platform-dependent | Process polling loss; native logs optional; `not_applicable` scoring |
| Process observation sees every short-lived child | best-effort | Spawn-storm measures loss; not eBPF |
| Replay is OS process isolation | best-effort / platform-dependent | **Workspace** = temp directory only; **`--contained`** = bubblewrap namespaces when `bwrap` present (fail closed otherwise); not multi-tenant hardened |
| Workspace restore is complete for all files | best-effort | Manifest limits (files/bytes/depth); report lists gaps |
| Portable import preserves content-addressed integrity | test-backed | Hash must match; no rename-to-unverified-key; `tests/portable_import_atomicity.rs` |
| Crash recovery never invents success | test-backed | Abandoned `Running` → `Failed`; `tests/fault_recovery.rs` |
| Dashboard auth for browsers without tokens in URLs | test-backed | Session cookie + Bearer; `tests/dashboard_auth.rs` |
| Large-run totals independent of display windows | test-backed | Aggregates + `analysis_scope`; `tests/long_run_integrity.rs` |
| macOS full parity with Linux process backends | platform-dependent | PR runtime gate; full process matrix deferred |
| Windows support | planned / out of scope | Explicit non-goal for 1.5 |

**Classes:** `code-backed` · `test-backed` · `platform-dependent` · `best-effort` · `planned` · `historical`.
