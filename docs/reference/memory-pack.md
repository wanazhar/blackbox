# Memory pack reference (blackbox.memory/v1)

What is in the project memory pack, which fields survive budget shrink, how attention levels work, and where files are written.

| Role | Doc |
|---|---|
| Concept | [../guide/concepts.md](../guide/concepts.md) · [../guide/what-is-blackbox.md](../guide/what-is-blackbox.md) |
| Operator use | `memory show` / `handoff` · [../guide/recipes.md](../guide/recipes.md#6-agent-session-start-human-or-llm) |
| Implementation | [../internals/continuity-plane.md](../internals/continuity-plane.md) |

---

## Quick answers

| Question | Answer |
|---|---|
| Files on disk? | `.blackbox/MEMORY.md`, `MEMORY.json` (+ `RESUME.*` copies) |
| Schema id? | `"blackbox.memory/v1"` |
| When rebuilt? | End of run when continuity ≠ `off` |
| When injected? | Explicit `blackbox run` with continuity on and not observe-only |
| Ambient inject? | **Never** |
| Untrusted? | **Yes** — prior context for agents, not system policy |

---

## 1. Top-level fields

| Field | Type | Description |
|---|---|---|
| `schema` | string | `"blackbox.memory/v1"` |
| `purpose` | string | `"project-memory"` \| `"for-resume"` \| `"handoff"` |
| `degraded` | bool | Built from sticky only (store open failed or hard timeout) |
| `project_root` | string | Absolute project root |
| `store_db` | string | SQLite path |
| `generated_at` | RFC3339 | Build time |
| `continuity_mode` | string | `always` \| `attention` \| `off` |
| `headline` | string | **Never dropped under budget** |
| `next_action` | string | **Never dropped** |
| `attention_reason` | string | Why attention is set |
| `attention_level` | string | See §3 |
| `approx_tokens` | number | Estimated size |
| `truncated` | bool | Budget shrink removed lower-priority fields |
| `build_ms` | number | Wall time to build |

### Nested views

**IntentView** — `goal`, `plan_summary`, `open_items` (cap 8), `do_not_retry` fingerprints.

**ClaimsSummaryView** — `active` claim pointer, `conflicts[]`.

**RunPointer** — `id`, `short_id`, `status`, `exit_code`, `name`, `command_preview`, `ended_at`, `adapter`.

**GitMemoryView** — `dirty` (`.blackbox/` filtered), `branch`, `head`, `summary`, porcelain hash.

**SideEffectSample** — `kind`, `path`, `detail`, `count`.

### Additional capped fields

| Field | Cap / notes |
|---|---|
| `files_touched` | `"kind:path"` — cap ~40 |
| `destructive_paths` | cap ~15 |
| `side_effects_top` | cap ~12 |
| `secret_redaction_events` | **count only** — never secret values |
| `failed_tools` / `errors_top` | From focus run |
| `summary` | Nested run summary when built |
| `last_tools` | Last ~25 tool names |
| `transcript_tail` | Lowest priority; often dropped |
| `resume_command` | Optional argv for resume |
| `last_run` / `predecessor_run` / `focus_run_id` | Pointers |

---

## 2. Budget shrink order

Default budget ~4000 tokens (`resume_max_tokens` / `memory_max_tokens`). Drop **lowest** priority first:

| Priority | Item | Over budget |
|---|---|---|
| 1 (keep) | headline, next_action, attention_* | Never dropped |
| 2 | Active claim + conflicts | Never dropped |
| 3 | intent | Capped already |
| 4 | failed_tools + errors_top | Kept |
| 5 | files_touched, destructive_paths, git dirty | Kept |
| 6 | side_effects_top, secret_redaction_events | Truncated |
| 7 | predecessor_run | Dropped |
| 8 | last_tools | Truncated |
| 9 (drop first) | transcript_tail | Dropped; skipped when attention is `none` |

If `truncated=true`, trust headline/next/attention first.

---

## 3. `attention_level`

| Level | Meaning | Example |
|---|---|---|
| `none` | Clean | Green run, no sticky failure |
| `info` | Heads-up | Dirty tree after success |
| `continue` | Follow up | Unresolved failure, open WIP |
| `blocked` | Stop | `require_ack` outstanding |

Unrelated success does not clear unresolved failure — `blackbox resolve`.

---

## 4. Build process (accurate sketch)

1. Load sticky state (`.blackbox/state.json`)
2. Open store; on failure → **degraded** sticky-only pack
3. Load last ≤3 runs (event caps via limited reads)
4. Live `git status --porcelain` (~500ms timeout)
5. Side-effect classification on events
6. Focus-run summary + optional transcript tail
7. Budget shrink
8. Atomic write MEMORY/RESUME md+json
9. Update sticky `memory_updated_at`

**Hard degrade:** total build \> ~2s → sticky-only pack (`degraded=true`).

---

## 5. Secrets

- No secret **values** in the pack by design
- `secret_redaction_events` is an aggregate counter
- Gate: `tests/memory_pack_quality.rs`
- Structural ids (run UUID, blob hashes) survive

---

## 6. Files

| File | Role |
|---|---|
| `MEMORY.md` | Human-readable |
| `MEMORY.json` | Structured (may be sealed when store key present) |
| `RESUME.md` / `RESUME.json` | Compat copies |

Writes are atomic (temp + rename) to avoid half-read packs.

---

## 7. Inject surface (what the child may see)

On eligible explicit runs, blackbox may set e.g.:

- `BLACKBOX_MEMORY_FILE` / `BLACKBOX_MEMORY_SCHEMA`
- `BLACKBOX_RESUME_*` hints
- Optional prompt preamble with an untrusted-memory marker

Harness cooperation required for preamble paths. Ambient never injects.

---

## Related

- [json-api.md](json-api.md) — CLI envelope wrapping memory show/handoff  
- [mcp.md](mcp.md) — `blackbox_memory`, `blackbox_handoff`  
- [../guide/configuration.md](../guide/configuration.md) — continuity knobs  
