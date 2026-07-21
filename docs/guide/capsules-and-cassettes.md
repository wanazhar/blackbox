# Capsules and MCP cassettes

## Reproducibility capsules

A capsule packages evidence for attempted reproduction and states what could
not be preserved.

```bash
blackbox capsule create latest -o failure.bbx.json
blackbox capsule inspect failure.bbx.json
blackbox capsule verify failure.bbx.json

# Import portable archive into the store (new run id)
blackbox capsule execute failure.bbx.json

# Optional: re-run recorded argv with contained budget preference
blackbox capsule execute failure.bbx.json --rerun --contained
```

| Completeness | Meaning |
|---|---|
| `byte_exact` | Original capture bytes (rare after default redaction) |
| `sanitized_complete` | Content present after secret redaction |
| `partial` | Some files missing or skipped |
| `metadata_only` | Structure only |

**Sanitized capsules never claim byte-exact reproduction.**  
**Model output is not deterministic replay** — the manifest sets
`model_replay_deterministic: false`.

`execute` imports the embedded portable archive (and receipts when present).
`--rerun` starts a new supervised run of the recorded command; it is not
guaranteed to reproduce model behavior.

## MCP cassette (experimental)

Blackbox can own the **MCP stdio** boundary. This does **not** intercept
harness-internal tools.

```bash
# Record (redacts free-form strings by default)
blackbox cassette proxy --record cassette.bbx.json -- my-mcp-server

# Replay (default: fail unknown calls)
blackbox cassette proxy --replay cassette.bbx.json --mode normalized

# Live passthrough for unknowns (explicit)
blackbox cassette proxy --replay cassette.bbx.json --on-unknown live -- my-mcp-server

blackbox cassette inspect cassette.bbx.json
blackbox cassette match cassette.bbx.json request.json --tool tools/call
```

Matching modes: `strict`, `normalized` (ignore JSON-RPC ids), `ordered`,
`allow_extra`.

Replay results mark `result_source: mock|live|deny`. Unmatched or unproxied
tools are reported as unsupported failures, not missing successes.

## Related

- [export-and-sync.md](export-and-sync.md) — portable archives
- [claims.md](../claims.md)
