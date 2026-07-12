# blackbox agent API (1.0 → 1.1)

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

### 0.4 additions

| Command | Notes |
|---|---|
| `status --json` | Project capture status, sticky last run, `attention`, `next_commands` |
| `handoff --json` | Same as status with `resume_pack` attached when attention is needed (`--always` forces) |
| `enable --install-shell` | Idempotent managed shell wrappers; `--uninstall-shell` removes them |
| `run --json` | Includes `attention_needed` + `handoff_hint` after completion |

### 1.0 additions

| Surface | Notes |
|---|---|
| `blackbox mcp` | MCP stdio JSON-RPC tools (see below) |
| Auto-resume | Default on; writes `.blackbox/RESUME.md` + injects into next launch |
| `serve` `/api/status` `/api/handoff` | Dashboard JSON mirrors CLI Views |
| Wrap defaults | claude, codex, aider, cursor, cursor-agent, gemini, opencode, grok |

### 1.1 additions (adoption bar + former backlog)

| Surface | Notes |
|---|---|
| `context --for-resume` pack | Additive fields: `headline`, `next_action`, `attention_reason`, `errors_top` (existing fields unchanged) |
| `doctor --json` | `blob_bytes`, `blob_files`, `total_storage_bytes`, `storage_warning`; retention includes `auto_apply` |
| `stats --json` | `db_bytes`, `total_storage_bytes`, `storage_warning` |
| Ambient contract | See `docs/ambient-contract.md`; tests in `tests/ambient_contract.rs` |
| Redaction gate | `tests/redaction_gate.rs` — structural IDs never scar |
| Adapters | `aider`, `gemini`, `cursor`, `opencode`, `grok` first-class (detect + parse) |
| `run --ci` | Exit with child process code after recording |
| `run --artifact-dir DIR` | Writes `run.json`, `postmortem.json`, `portable.json` |
| `postmortem --fail-on-failure` | Exit 1 if run failed/cancelled/nonzero |
| Cost estimate | `BLACKBOX_ESTIMATE_COST=1` fills `estimated_cost_usd`; optional `BLACKBOX_PRICING` / `.blackbox/pricing.toml` |
| Sandbox restore | Checkpoint `git_commit` via `git archive` + apply `git_diff_blob` when present |
| Shell soak | `tests/shell_soak.rs` exercises real bash install → ambient record |
| Native logs | Per-harness roots/filters; aider plaintext history |
| Windows | `taskkill` soft/hard stop; `--shell powershell` install |

**Agent session start (recommended):**

```bash
blackbox handoff --json
# or MCP tool: blackbox_handoff
```

If `data.attention.needed` is true, use `data.resume_pack` (or `next_commands`) before retrying work. Sticky state lives at `.blackbox/state.json`; human-readable agent notes at `.blackbox/AGENT.md`.

HTTP `blackbox serve` returns **raw views** without the CLI envelope (`/api/status`, `/api/handoff`, `/api/runs`, …).

## MCP tools (`blackbox mcp`)

JSON-RPC 2.0 over stdio. Protocol version `2024-11-05`.

| Tool | Purpose |
|---|---|
| `blackbox_status` | Capture status + optional resume |
| `blackbox_handoff` | Status + resume pack when attention needed |
| `blackbox_postmortem` | Run summary |
| `blackbox_context` | Resume pack |
| `blackbox_runs` | List runs |
| `blackbox_search` | FTS/search |
| `blackbox_doctor` | Store health |

Example Claude Desktop / client config:

```json
{
  "mcpServers": {
    "blackbox": {
      "command": "blackbox",
      "args": ["mcp"]
    }
  }
}
```

## Auto-resume

When `capture.auto_resume = true` (default) or `BLACKBOX_AUTO_RESUME=1`:

1. On launch, if sticky state has a failed/cancelled last run, write `.blackbox/RESUME.md` + `RESUME.json`
2. Set env: `BLACKBOX_RESUME_FILE`, `BLACKBOX_RESUME_RUN_ID`, `BLACKBOX_RESUME_HINT`
3. Prepend a compact resume preamble to Claude `-p` / Codex `exec` prompts when present

Disable: `BLACKBOX_AUTO_RESUME=0`, config `auto_resume = false`, or `blackbox run --no-auto-resume`.

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
