# Memory pack reference (blackbox.memory/v1)

**Schema and field semantics** for `blackbox.memory/v1`. Conceptual overview: [../guide/what-is-blackbox.md](../guide/what-is-blackbox.md). Continuity implementation: [../internals/continuity-plane.md](../internals/continuity-plane.md).

The Project Memory Pack is a bounded snapshot of project-level context delivered on supervised launches when continuity is enabled. It is rebuilt after every run (when continuity ≠ off) and written to `.blackbox/MEMORY.md` + `.blackbox/MEMORY.json`.

---

## 1. Schema (`blackbox.memory/v1`)

### Top-level fields

| Field | Type | Description |
|---|---|---|
| `schema` | `string` | Always `"blackbox.memory/v1"` |
| `purpose` | `string` | `"project-memory"` \| `"for-resume"` \| `"handoff"` |
| `degraded` | `bool` | `true` if built from sticky state only (store unavailable) |
| `project_root` | `string` | Absolute path to project root |
| `store_db` | `string` | Path to the SQLite database |
| `generated_at` | `RFC3339` | When this pack was built |
| `continuity_mode` | `string` | `"always"` \| `"attention"` \| `"off"` |
| `headline` | `string` | **Never dropped under budget.** One-line project state summary |
| `next_action` | `string` | **Never dropped.** What the next agent should do |
| `attention_reason` | `string` | Why attention is needed (failure, dirty WIP, claim conflict) |
| `attention_level` | `string` | `"none"` \| `"info"` \| `"continue"` \| `"blocked"` |
| `approx_tokens` | `number` | Estimated token count of the pack |
| `truncated` | `bool` | `true` if budget shrink dropped fields |
| `build_ms` | `number` | Wall-clock time to build in milliseconds |

### IntentView

| Field | Type | Description |
|---|---|---|
| `goal` | `string \| null` | Current project goal (set via `memory set --goal`) |
| `plan_summary` | `string \| null` | Plan summary (explicit only) |
| `open_items` | `string[]` | Open TODO items (explicit only in MVP), capped at 8 |
| `do_not_retry` | `string[]` | Fingerprints of last 3 failed runs, capped at 5 |

### ClaimsSummaryView

| Field | Type | Description |
|---|---|---|
| `active` | `ClaimPointer \| null` | Current project claim holder |
| `conflicts` | `string[]` | Conflict strings when another agent holds the claim |

### RunPointer

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Full run UUID |
| `short_id` | `string` | First 8 characters of run ID |
| `status` | `string` | `"succeeded"` \| `"failed"` \| `"cancelled"` |
| `exit_code` | `number \| null` | Process exit code |
| `name` | `string \| null` | Human-readable run name |
| `command_preview` | `string` | Truncated command string |
| `ended_at` | `RFC3339 \| null` | When the run finished |
| `adapter` | `string \| null` | Detected harness adapter |

### GitMemoryView

| Field | Type | Description |
|---|---|---|
| `dirty` | `bool` | Whether git porcelain is non-empty (excluding `.blackbox/` paths) |
| `branch` | `string \| null` | Current git branch |
| `head` | `string \| null` | Current commit hash |
| `summary` | `string \| null` | Short description of changes |
| `porcelain_hash` | `string \| null` | Short hash of porcelain text (cache debug) |

### SideEffectSample

| Field | Type | Description |
|---|---|---|
| `kind` | `string` | Effect classification (`destructive`, `local-write`, `external-write`) |
| `path` | `string \| null` | File path (if applicable) |
| `detail` | `string \| null` | Description |
| `count` | `number` | How many times this effect occurred |

### Additional fields

| Field | Type | Cap |
|---|---|---|
| `files_touched` | `string[]` | `"kind:path"` — cap 40 |
| `destructive_paths` | `string[]` | Paths from destructive operations — cap 15 |
| `side_effects_top` | `SideEffectSample[]` | Ranked samples — cap 12 |
| `secret_redaction_events` | `number` | Aggregate count (never values) |
| `failed_tools` | `FailedTool[]` | From focus run |
| `errors_top` | `ErrorTop[]` | From focus run |
| `summary` | `SummaryView \| null` | Run summary if built |
| `last_tools` | `string[]` | Last 25 tool names |
| `transcript_tail` | `string \| null` | Focus run transcript — lowest priority |
| `resume_command` | `string[] \| null` | Resume command for focus |
| `last_run` | `RunPointer \| null` | Most recent run |
| `predecessor_run` | `RunPointer \| null` | Focus predecessor |
| `focus_run_id` | `string \| null` | Focus run ID |

---

## 2. Budget shrink order

Items are dropped in **reverse** priority to stay under `max_tokens` (default 4000):

| Priority | Item | Action if over budget |
|---|---|---|
| 1 (highest) | `headline`, `next_action`, `attention_reason`, `attention_level` | Never dropped |
| 2 | Active claim + conflicts | Never dropped |
| 3 | `intent` | Never dropped (already capped) |
| 4 | `failed_tools` + `errors_top` | Never dropped |
| 5 | `files_touched` + `destructive_paths` + git dirty | Never dropped |
| 6 | `side_effects_top` + `secret_redaction_events` | Truncated |
| 7 | `predecessor_run` pointer | Dropped |
| 8 | `last_tools` | Truncated |
| 9 (lowest) | `transcript_tail` | Dropped first; skipped entirely when `attention_level=none` |

---

## 3. `attention_level` values

| Level | Meaning | Example |
|---|---|---|
| `none` | Clean — no attention needed | Successful clean build, no open items |
| `info` | Informational | Success with dirty tree or files modified |
| `continue` | Active WIP | Unresolved failure, dirty tree + open items |
| `blocked` | Gate blocked | `require_ack` outstanding |

---

## 4. Build process

1. Load sticky state from `.blackbox/state.json`
2. Open store; if fail → build degraded pack from sticky only
3. Load last ≤3 runs (≤2000 events each via `get_events_limited`)
4. Run `live_git_status(project_root)` with 500ms timeout
5. Run `SideEffectClassifier` on events
6. Build focus run summary
7. Rebuild transcript tail for focus run
8. Apply budget shrink if over `max_tokens`
9. Write `MEMORY.md`, `MEMORY.json`, `RESUME.md`, `RESUME.json`
10. Update sticky `memory_updated_at`

**Hard degrade:** If total build exceeds **2 seconds**, return degraded sticky-only pack.

---

## 5. Secret handling

- No secret values in the pack — `secret_redaction_events` is an aggregate count only
- M2a test suite (`tests/memory_pack_quality.rs`) verifies no planted secrets leak
- Structural IDs (run IDs, blob keys, UUIDs) survive redaction

---

## 6. File outputs

| File | Format | Purpose |
|---|---|---|
| `MEMORY.md` | Markdown | Human-readable pack |
| `MEMORY.json` | JSON | Structured machine-readable pack |
| `RESUME.md` | Markdown | Identical copy (1.0 compat) |
| `RESUME.json` | JSON | Identical copy (1.0 compat) |

All written atomically (write to temp, rename) to prevent partial reads.

