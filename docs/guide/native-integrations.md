# Native integrations (1.9)

Record Blackbox-compatible evidence **without** process wrapping. Process wrapping remains available as an independent observation source.

## Native recorder API

In-process Rust:

```rust
use std::sync::Arc;
use blackbox::native::{NativeRecorder, StartRunOpts, FinishRunOpts};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

# async fn demo() -> anyhow::Result<()> {
let store = Arc::new(SqliteStore::open_memory()?) as Arc<dyn TraceStore>;
let rec = NativeRecorder::new(store);
let run = rec.start_run(StartRunOpts {
    command: vec!["agent".into()],
    cwd: Some(".".into()),
    adapter: Some("my-harness".into()),
    ..Default::default()
}).await?;
rec.record_tool(&run.id, "bash", None, None, blackbox::core::event::EventStatus::Success).await?;
rec.finish_run(&run.id, FinishRunOpts { exit_code: 0, ..Default::default() }).await?;
# Ok(())
# }
```

### Transports

| Transport | Use when |
|---|---|
| In-process `NativeRecorder` | Same process as the harness |
| Bounded NDJSON (`blackbox.native.ingest/v1` lines) | Sidecar / pipe |
| Unix domain socket | Local multi-process, same host |

All transports share **idempotency keys**. Retries after acknowledgement are duplicates, not new events. Partial NDJSON frames are never committed.
Wire-operation record IDs are derived from the idempotency key, so a retry
after recorder restart recovers the committed acknowledgement. Reusing a key
for a different request fails with `idempotency_conflict`.

## Claude Code hooks (reference)

The reference adapter maps Claude Code hook payloads to native ingest envelopes.

| Hook | Mapping |
|---|---|
| `SessionStart` | `start_run` |
| `PreToolUse` | `record_tool` (+ optional `record_security_decision`) |
| `PostToolUse` | `record_tool` (`tool.result`) |
| `PermissionRequest` | `record_approval` |
| `SessionEnd` / `Stop` | `finish_run` |

Coverage declaration: `blackbox::integrations::ClaudeHooksAdapter::coverage()`.

Conformance level claimed: **Recorder**.

Unsupported (honest): full PTY terminal bytes, kernel process tree, forensic pack generation on the hook path.

The release qualification fixture records 500 hook events through the
in-process reference path, requires zero dropped events, and records measured
p99 latency (with a deliberately loose 100 ms debug-build ceiling). It also
checks malformed-producer isolation and unknown-hook fallback. This is a local
reference measurement, not a universal production latency guarantee.

## Security decisions

External engines (OPA, Cedar, Falco, harness permissions, MCP gateways, human approval) emit `blackbox.security.decision/v1`. Self-asserted `signed_verified` is demoted without a configured verifier.

Action↔effect reconciliation produces typed outcomes such as `denied_not_executed` vs `denied_but_bypassed`.

## OTLP

Export preserves `blackbox.*` attributes and emits an explicit **loss ledger** for concepts that cannot round-trip. Import treats OTLP as external evidence with `unverified` integrity — attributes cannot self-assert Blackbox integrity levels.

## Conformance

```bash
blackbox conform --profile core
blackbox conform --profile recorder
blackbox conform --profile boundary
blackbox conform --profile forensic
blackbox conform --profile recorder --json
```

Public vectors live under `/test-vectors`. Schemas under `/spec`.

## Integrity honesty

Run commitments prove **record consistency after commitment**, not completeness of observation or external truth.
