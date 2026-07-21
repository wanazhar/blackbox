# JSON API reference

Shape of `--json` output (`blackbox.cli/v1`), which command produces which view, and the fields automation should parse.

| You want… | Prefer |
|---|---|
| Human debug of one failure | [../guide/debug-a-failure.md](../guide/debug-a-failure.md) |
| Agent session playbook | [../skills/blackbox.md](../skills/blackbox.md) |
| MCP (no CLI envelope) | [mcp.md](mcp.md) |

---

## Quick answers

| Question | Answer |
|---|---|
| How do I get JSON? | Pass global `--json` (before or after subcommand per clap; usually `blackbox <cmd> --json`) |
| Success vs error? | `ok: true` + `data` vs `ok: false` + `error` |
| Schema id? | Always `"blackbox.cli/v1"` in `schema` |
| MCP same envelope? | **No** — MCP returns raw tool payloads inside MCP content |

---

## 1. Envelope

### Success

```json
{
  "ok": true,
  "schema": "blackbox.cli/v1",
  "command": "show",
  "data": { }
}
```

### Error

```json
{
  "ok": false,
  "schema": "blackbox.cli/v1",
  "command": "show",
  "error": {
    "code": "not_found",
    "message": "Run not found: abc123"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `ok` | bool | Success / failure |
| `schema` | string | `"blackbox.cli/v1"` |
| `command` | string | Subcommand name |
| `data` | object | Success payload (view) |
| `error.code` | string | Stable-ish machine code when present |
| `error.message` | string | Human-readable detail |

Pipe-friendly:

```bash
blackbox runs --json | jq '.data'
blackbox postmortem latest --json | jq '.data.headline, .data.next_action'
```

---

## 2. Command → view map

| Command | Typical `data` view | Notes |
|---|---|---|
| `runs` | `RunsView` | List + filters |
| `show` | `ShowView` | Run + events + optional summary |
| `timeline` | `TimelineView` | Filtered events |
| `inspect` | `InspectView` | One event + blob text |
| `diff` | `DiffView` / trajectory fields | Pair of runs |
| `analyze` | `AnalyzeView` | Pass results |
| `search` | `SearchView` | FTS hits |
| `status` | `StatusView` | Project status |
| `handoff` | `HandoffView` | Status + memory + resume |
| `memory show` | memory pack | See [memory-pack.md](memory-pack.md) |
| `claim *` | claim views | acquire/status/release |
| `doctor` | `DoctorView` | Health + tips |
| `stats` | `StatsView` | Aggregates |
| `postmortem` / `summary` | summary / postmortem | headline, evidence, anomalies |
| `context` | context / resume pack | Token-bounded |
| `run` (end) | run-done view | ids, ci/eval flags, artifact dir |

Exact field sets evolve with the binary; treat missing optional fields as absent, not error. Source of truth: `src/views.rs`, `src/summary.rs`, `src/status.rs`.

---

## 3. Core view types

### RunsView

```json
{
  "runs": [
    {
      "id": "uuid-string",
      "short_id": "abc12345",
      "name": "fix-ci",
      "status": "Succeeded",
      "exit_code": 0,
      "command": ["echo", "hello"],
      "cwd": "/home/user/project",
      "started_at": "2026-07-12T12:00:00Z",
      "ended_at": "2026-07-12T12:00:05Z",
      "tags": ["ci"],
      "event_count": 42
    }
  ]
}
```

**When to parse:** dashboards, CI selectors, “pick latest failed.”

### ShowView

| Field | Description |
|---|---|
| `run` | Run metadata |
| `events` | Timeline (may be limited) |
| `summary` | Optional rollup |

### TimelineView

| Field | Description |
|---|---|
| `run_id` | Run id |
| `events` | Sequence-ordered events |
| `truncated` | Hit a limit |
| `filters` | kind/source/semantic flags applied |

### InspectView

| Field | Description |
|---|---|
| `event` | Full event + metadata |
| `blob_content` | Decoded payload when available |

### DiffView

| Field | Description |
|---|---|
| `run_a` / `run_b` | Endpoints |
| `common_prefix_len` | Shared semantic prefix length |
| divergence / only_in_* | Exclusive tails |
| trajectory explanation | Human + structured hints |

### AnalyzeView

Derived errors, side-effect samples, correlations (pass-dependent).

### StatusView / HandoffView

| Field | Description |
|---|---|
| `enabled` | Project capture on |
| `store_path` | DB path |
| `last_run` | Pointer |
| `attention` | level + reason |
| `project_memory` | Pack when available |
| `next_commands` | Suggested CLI |
| `resume_pack` | Handoff only — when attention / always |

### DoctorView / StatsView

Store path, schema, counts, byte sizes, warnings, daily-driver notes (doctor). Use for ops automation and install verification.

### Postmortem / Summary

Prefer these fields for agents:

| Field | Why |
|---|---|
| `headline` | One-line story |
| `next_action` | What to do next |
| `evidence` | `event_id` / `sequence` anchors |
| `anomalies` | Structured markers |
| `status` / `exit_code` | Outcome |

### SearchView

| Field | Description |
|---|---|
| `query` | Input |
| `results` / hits | Ranked event/run matches |
| `total` | Count when present |

### Memory / Claim

- Memory: full [blackbox.memory/v1](memory-pack.md)
- Claim: active pointer, path claims, conflicts

---

## 4. TraceEvent (common shape)

Events in timelines share a family of fields (names may serialize with serde defaults):

| Field | Meaning |
|---|---|
| `id` | Event UUID |
| `run_id` | Parent run |
| `sequence` | Monotonic index |
| `kind` | e.g. `tool.call`, `terminal.output` |
| `source` | Terminal / Tool / Filesystem / … |
| `status` | Running / Success / Error / … |
| `metadata` | JSON object (tool_name, path, preview, …) |
| `side_effect` | None / LocalWrite / ExternalWrite / Destructive |
| `output_blob` / input keys | Blob references |

Do not assume every kind has every metadata key.

---

## 5. Automation patterns

```bash
# Fail CI if postmortem says the run failed
blackbox postmortem latest --json --fail-on-failure

# Select failed runs
blackbox runs --status failed --json | jq -r '.data.runs[].id'

# Session gate for agents
attn=$(blackbox status --json | jq -r '.data.attention.level // .data.attention // empty')
```

**Idempotency:** JSON schemas are additive when possible; pin blackbox version in CI if you depend on new fields.

---

## 6. Related

- [cli.md](cli.md) — flags producing these views  
- [memory-pack.md](memory-pack.md) — pack schema  
- [stream-protocol.md](stream-protocol.md) — harness NDJSON (different layer)  
