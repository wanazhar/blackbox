# Stream protocol (NDJSON)

**Answers:** How a custom harness can emit structured tool/session/usage events on stdout so blackbox adapters produce `TraceEvent`s instead of opaque terminal-only history.

| Not this doc | See instead |
|---|---|
| Exporting recorded runs as JSONL | [../guide/export-and-sync.md](../guide/export-and-sync.md) |
| Dashboard live SSE | [../guide/everyday-use.md](../guide/everyday-use.md) |
| Portable archive schema | [portable-format.md](portable-format.md) |

Blackbox supports a **one JSON object per line** protocol consumed by the `generic` / related adapters.

---

## 1. Overview

The stream protocol is a **one JSON object per line** format. It is consumed by the `generic` and `claude` adapters to extract tool calls, results, usage metrics, and session information from the harness output.

### When to use

- Writing a custom adapter or harness integration
- Needing structured events that survive redaction (raw terminal output may lose structure)
- Emitting usage/cost data from a custom model

### When NOT to use

- Harnesses that already emit structured events natively (Claude Code's stream-json, Codex's event stream) — blackbox handles those adapters natively

---

## 2. Event types

| `type` | Event kind | Purpose |
|---|---|---|
| `tool_call` | `tool.call` | A tool/function was invoked |
| `tool_result` | `tool.result` | A tool returned a result |
| `session` | `harness.session` | Harness session started |
| `usage` | `harness.usage` | Token usage report |
| `message` | `harness.assistant` | Assistant message content |

### `tool_call`

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | `string` | yes | Must be `"tool_call"` |
| `id` | `string` | yes | Tool call identifier |
| `name` | `string` | yes | Tool name (e.g. `"Bash"`, `"Edit"`, `"Read"`) |
| `input` | `object` | yes | Tool input arguments |

**Example:**
```json
{"type":"tool_call","id":"call_abc123","name":"Bash","input":{"command":"ls -la"}}
```

### `tool_result`

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | `string` | yes | Must be `"tool_result"` |
| `id` | `string` | yes | Matches the `tool_call` id |
| `tool_use_id` | `string` | no | Alternative ID field (Claude API compat) |
| `output` | `string` | yes | Tool output text |
| `is_error` | `bool` | no | Whether the tool returned an error |

**Example:**
```json
{"type":"tool_result","id":"call_abc123","output":"total 42\ndrwxr-xr-x  ...","is_error":false}
```

### `session`

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | `string` | yes | Must be `"session"` |
| `session_id` | `string` | yes | Harness session identifier |

**Example:**
```json
{"type":"session","session_id":"sess_xyz789"}
```

### `usage`

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | `string` | yes | Must be `"usage"` |
| `input_tokens` | `number` | no | Prompt tokens consumed |
| `output_tokens` | `number` | no | Completion tokens generated |
| `total_tokens` | `number` | no | Total tokens |
| `model` | `string` | no | Model identifier (e.g. `"claude-sonnet-4-20250514"`) |

**Example:**
```json
{"type":"usage","input_tokens":120,"output_tokens":40,"total_tokens":160,"model":"claude-sonnet-4-20250514"}
```

On run finish, the **last** `usage` event wins for run-level token columns.

### `message`

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | `string` | yes | Must be `"message"` |
| `role` | `string` | no | `"assistant"` \| `"user"` |
| `text` | `string` | yes | Message content |

**Example:**
```json
{"type":"message","role":"assistant","text":"I've listed the directory contents."}
```

---

## 3. Adapter detection

Blackbox detects harnesses in this order:

1. Examine `argv[0]` (e.g. `claude`, `codex`, `aider`, `gemini`, `cursor`)
2. Check `argv` for known patterns (e.g. `-p`, `exec`, `--message`)
3. Inspect environment variables for harness-specific markers
4. Fall back to `generic` adapter

When a specific adapter is matched, its parser extracts structured events from the output. The `generic` adapter accepts the NDJSON stream protocol directly.

---

## 4. Integration example

```bash
# A custom harness that emits NDJSON events:
cat <<'EOF' | blackbox run -- bash
echo '{"type":"tool_call","id":"1","name":"Bash","input":{"command":"ls"}}'
echo '{"type":"tool_result","id":"1","output":"src\\nREADME.md","is_error":false}'
echo '{"type":"usage","input_tokens":50,"output_tokens":10,"model":"custom-model"}'
EOF
```

## 5. Notes

- Lines that are not valid JSON are treated as terminal output (raw text)
- The protocol is additive — new event types may be added in future versions
- Usage events are cumulative within a run; the last event wins for run metadata
