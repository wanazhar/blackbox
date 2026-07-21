# Capsules and MCP cassettes

## Reproducibility capsules

A capsule packages evidence for attempted reproduction and states what could not be preserved.

```bash
blackbox capsule create latest -o failure.bbx.json
blackbox capsule inspect failure.bbx.json
blackbox capsule verify failure.bbx.json
```

Completeness classes:

| Class | Meaning |
|---|---|
| `byte_exact` | Original capture bytes (rare after default redaction) |
| `sanitized_complete` | All content present after secret redaction |
| `partial` | Some files missing/skipped |
| `metadata_only` | Structure only |

**Sanitized capsules never claim byte-exact reproduction.**  
**Model output is not deterministic replay** — the manifest always sets `model_replay_deterministic: false`.

## MCP cassette (experimental)

Blackbox can own the MCP stdio boundary. This does **not** intercept harness-internal tools.

```bash
# Record
blackbox cassette proxy --record cassette.bbx.json -- my-mcp-server

# Replay (default: fail unknown calls)
blackbox cassette proxy --replay cassette.bbx.json --mode normalized

# Live passthrough for unknowns (explicit)
blackbox cassette proxy --replay cassette.bbx.json --on-unknown live -- my-mcp-server

blackbox cassette inspect cassette.bbx.json
```

Matching modes: `strict`, `normalized` (ignore JSON-RPC ids), `ordered`, `allow_extra`.

Replay results are marked `result_source: mock|live|deny`. Unmatched / unproxied tools are reported as unsupported failures, not missing successes.

## Related

- [export-and-sync.md](export-and-sync.md) — portable archives
- [claims.md](../claims.md)
