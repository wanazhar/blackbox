# Execution budgets and external adapters

## Budgets

```bash
blackbox run \
  --max-wall 1800 \
  --max-processes 64 \
  --max-output 104857600 \
  --max-tool-calls 500 \
  --max-tokens 500000 \
  --contained \
  -- agent …

# Capability report without a run
blackbox budget --max-wall 30 --max-processes 64 --json
```

Each limit is classified independently:

| Capability | Meaning |
|---|---|
| `enforced` | Blackbox will terminate or hard-limit |
| `observed_only` | Measured and reported; not killed on exceed |
| `unavailable` | Requested but not available on this OS |
| `not_applicable` | Not configured |

On Linux, wall-time uses a SIGKILL watchdog; process count uses `RLIMIT_NPROC` plus a `/proc` descendant poller. Token budgets remain observed-only unless a harness enforces them. Unsupported limits **never** appear as `enforced`.

Budget termination emits `run.budget.breach` and is distinguishable from ordinary child failure.

## External adapter protocol

Process-based NDJSON protocol (`blackbox.adapter/v1`) — no Rust dylib ABI.

```toml
# adapter.toml
name = "custom-agent"
protocol = "blackbox.adapter/v1"
command = ["blackbox-adapter-custom"]
detect_basenames = ["custom-agent"]
capabilities = ["session_id", "tool_calls", "usage"]
```

```bash
blackbox adapter validate ./adapter.toml
blackbox adapter test ./adapter.toml --fixtures fixtures/events.ndjson
```

Invalid schemas and oversized events are rejected. Optional adapter failure must not stop core recording.

## Multi-project index

```bash
blackbox projects scan ~
blackbox projects list --query myapp
```

The global index (`~/.blackbox/projects-index.json`) is **metadata only**. Project-local `.blackbox/` stores remain authoritative; transcripts and blobs are never centralized.

## Related

- [configuration.md](configuration.md)
- [claims.md](../claims.md)
