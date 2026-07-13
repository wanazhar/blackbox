# JSON API reference

All blackbox CLI commands accept `--json` to produce a machine-readable envelope (`blackbox.cli/v1`). This document describes the envelope format and every view type.

---

## 1. CLI envelope

### Success

```json
{
  "ok": true,
  "schema": "blackbox.cli/v1",
  "command": "show",
  "data": { /* view-specific payload */ }
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

| Envelope field | Type | Description |
|---|---|---|
| `ok` | `bool` | Success or failure |
| `schema` | `string` | Always `"blackbox.cli/v1"` |
| `command` | `string` | The subcommand name |
| `data` | `object` | Present on success — varies by command |
| `error` | `object` | Present on failure — code + message |

---

## 2. View types

### RunsView

```json
{
  "runs": [
    {
      "id": "uuid-string",
      "short_id": "abc12345",
      "name": "fix-ci",
      "status": "succeeded",
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

Used by: `runs`, `search` (with run context).

### ShowView

Used by: `show <run-id>`. Returns full run details + event timeline + summary.

| Field | Type | Description |
|---|---|---|
| `run` | `RunSummaryView` | Run metadata |
| `events` | `TraceEventView[]` | Event timeline |
| `summary` | `object \| null` | Optional run summary |

### TimelineView

Used by: `timeline <run-id>`. Returns filtered event list.

| Field | Type | Description |
|---|---|---|
| `run_id` | `string` | Run ID |
| `events` | `TraceEventView[]` | Events in sequence order |
| `truncated` | `bool` | Whether the list was truncated |
| `filters` | `object` | Applied filters (source, kind, status) |

### InspectView

Used by: `inspect <event-id>`. Returns full event detail including blob content.

| Field | Type | Description |
|---|---|---|
| `event` | `TraceEventView` | Event with full metadata |
| `blob_content` | `string \| null` | Decoded blob content (if applicable) |

### DiffView

Used by: `diff <run-a> <run-b>`.

| Field | Type | Description |
|---|---|---|
| `run_a` | `RunSummaryView` | First run |
| `run_b` | `RunSummaryView` | Second run |
| `common_prefix_len` | `number` | Number of events before divergence |
| `first_divergence` | ... | First differing event pair |
| `only_in_a` | `TraceEventView[]` | Events unique to run A |
| `only_in_b` | `TraceEventView[]` | Events unique to run B |
| `trajectory` | `string \| null` | Human-readable trajectory report (when `--trajectory`) |

### AnalyzeView

Used by: `analyze <run-id>`.

| Field | Type | Description |
|---|---|---|
| `run_id` | `string` | Run ID |
| `errors` | `ErrorTop[]` | Detected errors |
| `side_effects` | `SideEffectSample[]` | Side-effect classification |
| `correlations` | `Correlation[]` | Causal event correlations |

### StatusView

Used by: `status --json`.

| Field | Type | Description |
|---|---|---|
| `enabled` | `bool` | Whether project capture is enabled |
| `store_path` | `string` | Path to the SQLite database |
| `last_run` | `RunPointer \| null` | Most recent run |
| `attention` | `AttentionView` | Attention level + needed + reason |
| `project_memory` | `object \| null` | Memory pack (when enabled and available) |
| `next_commands` | `string[]` | Suggested next CLI commands |

### HandoffView

Used by: `handoff --json`. Extends StatusView.

| Field | Type | Description |
|---|---|---|
| (all StatusView fields) | ... | ... |
| `resume_pack` | `ContextPackView \| null` | Resume context when attention needed |

### DoctorView

Used by: `doctor --json`.

| Field | Type | Description |
|---|---|---|
| `store_path` | `string` | Database path |
| `schema_version` | `number` | SQLite schema version |
| `run_count` | `number` | Total stored runs |
| `db_bytes` | `number` | SQLite file size |
| `blob_bytes` | `number` | Total blob storage size |
| `blob_files` | `number` | Number of blob files |
| `total_storage_bytes` | `number` | Sum of db + blobs |
| `storage_warning` | `string \| null` | Warning if storage is large |

### StatsView

Used by: `stats --json`.

| Field | Type | Description |
|---|---|---|
| `run_count` | `number` | Total runs |
| `event_count` | `number` | Total events |
| `blob_count` | `number` | Total blobs |
| `db_bytes` | `number` | SQLite size |
| `total_storage_bytes` | `number` | Total storage |
| `storage_warning` | `string \| null` | Warning if applicable |

### PostmortemView

Used by: `postmortem <run-id> --json`.

| Field | Type | Description |
|---|---|---|
| `run` | `RunSummaryView` | Run metadata |
| `headline` | `string` | One-line summary |
| `attention_reason` | `string` | Why attention is needed |
| `failed_tools` | `FailedTool[]` | Failed tool calls |
| `errors_top` | `ErrorTop[]` | Top errors |
| `side_effects` | `SideEffectSample[]` | Side effects |
| `summary` | `object \| null` | Run summary |

### SearchView

Used by: `search <query> --json`.

| Field | Type | Description |
|---|---|---|
| `query` | `string` | The search query |
| `results` | `SearchResult[]` | Ranked matches |
| `total` | `number` | Total matches found |

### MemoryView

Used by: `memory show --json`. Returns the full `blackbox.memory/v1` pack (see [memory-pack.md](memory-pack.md)).

### ClaimView

Used by: `claim status --json`.

| Field | Type | Description |
|---|---|---|
| `active` | `ClaimPointer \| null` | Active claim |
| `holder` | `string \| null` | Current holder |
| `acquired_at` | `string \| null` | When acquired |
| `expires_at` | `string \| null` | When expires |
| `conflicts` | `string[]` | Conflict messages |
