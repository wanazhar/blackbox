# Execution budgets and external adapters

## Budgets

```bash
blackbox run \
  --max-wall 1800 \
  --max-processes 64 \
  --max-output 104857600 \
  --max-tool-calls 500 \
  --max-tokens 500000 \
  --max-memory 8589934592 \
  --max-cpu-percent 100 \
  --contained \
  -- agent …

# Capability report without a run
blackbox budget --max-wall 30 --max-processes 64 --max-output 1024 --json
```

Each limit is classified independently:

| Capability | Meaning |
|---|---|
| `enforced` | Blackbox will terminate or hard-limit the supervised tree |
| `observed_only` | Measured and reported; not killed on exceed |
| `unavailable` | Requested but not available on this OS |
| `not_applicable` | Not configured |

On Linux (when configured):

| Limit | Enforcement |
|---|---|
| Wall time (`--max-wall`) | SIGKILL watchdog |
| Process count | `prlimit` on the **child** + `/proc` poller; cgroup v2 `pids.max` when writable |
| Output bytes (`--max-output`) | Capture-path counter → SIGKILL when exceeded |
| Tool calls (`--max-tool-calls`) | Adapter `tool.call` counter → SIGKILL when exceeded |
| Memory (`--max-memory`) | cgroup v2 `memory.max` when leaf writable; else `RLIMIT_AS` on child |
| CPU percent (`--max-cpu-percent`) | cgroup v2 `cpu.max` when writable |
| Tokens (`--max-tokens`) | Observed-only unless a harness enforces |

Resource limits use **child `prlimit`**, never `setrlimit` on the blackbox
supervisor. Unsupported limits **never** appear as `enforced`.

A `run.budget.capabilities` event records which backend applied. Budget
termination emits `run.budget.breach` and is distinguishable from ordinary
child failure.

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
# Fixture lines and optional live process (command stdout as NDJSON)
blackbox adapter test ./adapter.toml --fixtures fixtures/events.ndjson
```

Invalid schemas and oversized events are rejected. Optional adapter failure
must not stop core recording. Live spawn failures are warnings when the
adapter is fixture-only.

## Multi-project index

```bash
blackbox projects scan ~
blackbox projects list --query myapp
blackbox projects prune              # drop entries whose store file is gone
blackbox projects remove /path/to/proj
```

The global index (`~/.blackbox/projects-index.json`) is **metadata only**.
Project-local `.blackbox/` stores remain authoritative; transcripts and blobs
are never centralized.

## Related

- [configuration.md](configuration.md)
- [claims.md](../claims.md)
