# blackbox agent API (0.2–0.3)

Machine-readable contracts for agents and custom harnesses.

## CLI JSON envelope (`blackbox.cli/v1`)

```bash
blackbox --json <command> …
```

Success:

```json
{
  "ok": true,
  "schema": "blackbox.cli/v1",
  "command": "show",
  "data": { }
}
```

Error:

```json
{
  "ok": false,
  "schema": "blackbox.cli/v1",
  "command": "show",
  "error": { "code": "not_found", "message": "…" }
}
```

### Commands with `data` views (0.2+)

`runs`, `show`, `timeline`, `inspect`, `analyze`, `search`, `stats`, `doctor`, `postmortem`/`summary`, `enable`, `disable`, `gc`.

### 0.3 additions

| Command | Notes |
|---|---|
| `diff A B --json` | Trajectory alignment (`common_prefix_len`, `first_divergence`, tails) |
| `diff A B --trajectory` | Human trajectory report |
| `context <run> --for-resume --json` | Bounded resume pack (`--max-tokens`) |

HTTP `blackbox serve` returns **raw views** without the envelope.

---

## blackbox stream protocol v1 (NDJSON)

Generic harnesses (or adapters) may emit **one JSON object per line** on stdout/stderr. The generic/Claude parsers accept these `type` values:

| type | Fields | Event kind |
|---|---|---|
| `tool_call` | `id`, `name`, `input` | `tool.call` |
| `tool_result` | `id` or `tool_use_id`, `output`, `is_error` | `tool.result` |
| `session` | `session_id` | `harness.session` |
| `usage` | `input_tokens`, `output_tokens`, `total_tokens`, `model` | `harness.usage` |
| `message` | `role` (optional), `text` | `harness.assistant` |

Example:

```json
{"type":"session","session_id":"sess_abc"}
{"type":"tool_call","id":"1","name":"Bash","input":{"command":"ls"}}
{"type":"tool_result","id":"1","output":"ok","is_error":false}
{"type":"usage","input_tokens":120,"output_tokens":40,"model":"demo"}
{"type":"message","role":"assistant","text":"done"}
```

On run finish, the **last** `harness.usage` event wins for run-level token columns (`input_tokens`, `output_tokens`, `total_tokens`, `model`). `estimated_cost_usd` stays `null` unless pricing config exists (not in 0.3).

Claude/Codex native stream-json continues to work; nested `usage` objects on `result` lines are also recognized.

---

## Resume packs

```bash
blackbox context latest --for-resume --json --max-tokens 4000
```

Pack includes postmortem summary, failed tools, last tool names, filesystem writes, optional transcript tail, and harness resume command when discoverable. Size is reduced until `approx_tokens ≤ max_tokens`.
