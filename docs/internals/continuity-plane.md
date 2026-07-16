# Continuity plane

> **Contributor / deep-dive.** Operator concepts: [../guide/concepts.md](../guide/concepts.md). Schema: [../reference/memory-pack.md](../reference/memory-pack.md). Recipes: [../guide/recipes.md](../guide/recipes.md#6-agent-session-start-human-or-llm).

**Answers:** Sticky state, attention, claims, memory pack build/inject, and gates — and how they intentionally **do not** apply to ambient capture.

The **continuity plane** turns blackbox from a passive flight recorder into an active project memory path. With continuity on, supervised **explicit** launches can **materialize and inject** a bounded project memory pack (files, env, optional preamble) so cooperative agents need not start cold.

> **Honesty:** blackbox delivers memory on supervised paths; it does not force a model to *read* it without vendor cooperation or optional `require_ack` on explicit `blackbox run`.

---

## 1. Core concepts

| Concept | Description |
|---|---|
| **Sticky state** | `.blackbox/state.json` — project-level state persisted after every run |
| **Memory pack** | `ProjectMemoryPack` — bounded snapshot of intent, claims, failures, dirty tree, transcript |
| **Continuity mode** | `always` / `attention` / `off` — controls when launch injection happens |
| **Attention level** | `none` / `info` / `continue` / `blocked` — describes how urgently context should be read |
| **Claim** | One active project hold under `state.lock` — prevents concurrent-agent blind spots |
| **Gate mode** | `warn` / `require_ack` on explicit `blackbox run` — optional enforcement layer |

---

## 2. Sticky state (state.json v2)

**Path:** `.blackbox/state.json`  
**Schema:** `blackbox.state/v2` (additive over v1 — old files get defaults on load)  
**Lock:** `.blackbox/state.lock` — exclusive `flock` for all sticky read-modify-write operations

### Fields

| Field | Type | Description |
|---|---|---|
| `schema` | string | Schema identifier `blackbox.state/v2` |
| `last_run` | `RunPointer \| null` | Most recently finished run |
| `last_failure` | `RunPointer \| null` | Most recent failed run |
| `attention_level` | `"none" \| "info" \| "continue" \| "blocked"` | Current attention severity |
| `attention_needed` | bool | Derived: `true` when attention_level ≠ `none` |
| `unresolved_failure_id` | `string \| null` | Run ID that still needs resolution |
| `memory_updated_at` | `DateTime \| null` | When memory was last refreshed |
| `intent` | `IntentState` | Goal, plan summary, open items, do-not-retry list |
| `active_claim` | `ClaimPointer \| null` | Current project holder |
| `notes` | `string \| null` | Free-form agent notes |

### RunPointer

```rust
pub struct RunPointer {
    pub id: String,
    pub short_id: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub name: Option<String>,
    pub command_preview: String,
    pub ended_at: Option<DateTime<Utc>>,
    pub adapter: Option<String>,
}
```

### IntentState

| Field | Type | Description |
|---|---|---|
| `goal` | `string \| null` | Current project goal (explicit via `memory set`) |
| `plan_summary` | `string \| null` | Plan summary (explicit only) |
| `open_items` | `string[]` | Open TODO items — **explicit only** in MVP, capped at 8 |
| `do_not_retry` | `string[]` | Last 3 failed runs' fingerprints, capped at 5 |

## 3. Attention algorithm

After each run completes, `apply_run_outcome()` determines the new `attention_level`. The decision tree:

| Condition | attention_level |
|---|---|
| Unresolved failure exists (from a prior or current run) | `continue` |
| Active claim held by a **different** agent | `continue` |
| Dirty git tree with non-empty `open_items` | `continue` |
| Dirty git tree (no open items) | `info` |
| Clean tree, files touched on success | `info` |
| Clean tree, no failure, no open items, no dirty | `none` |
| `require_ack` gate blocking | `blocked` |

### M6 rule (silent failure discipline)

**Unrelated success does not clear an unresolved failure.** Only these actions clear it:

- `blackbox resolve` (explicit resolution)
- `blackbox resolve --clear-wip` (also clears open_items/goal)
- A successful run with `parent_run_id` linking to the failure
- A `resolves:<failure-id>` tag on the successful run

This prevents a "run `true`" from accidentally wiping the attention state.

---

## 4. Project Memory Pack (blackbox.memory/v1)

The memory pack is the output document that agents read. It is rebuilt after every run and written to `.blackbox/MEMORY.md` + `.blackbox/MEMORY.json`.

### Build sources

| Source | Detail |
|---|---|
| Sticky state | Intent, claims, attention level, last run pointers |
| Store (last ≤3 runs) | Events, checkpoints, summaries (≤2000 events per run) |
| Live git status | `git status --porcelain` (500ms timeout — `dirty=false` on failure) |
| SideEffectClassifier | Ranked side-effect samples from tool/process events |
| SecretScanner | Aggregate `secret_redaction_events` count (never secret values) |
| Focus run | Transcript tail (lowest priority, skipped when attention=none) |

### Budget shrink order

Items are dropped in reverse order to stay under `max_tokens`. The first five items are **never** dropped:

1. `headline`, `next_action`, `attention_reason`, `attention_level` — never dropped
2. Active claim + conflicts string
3. `intent` (goal, open_items, do_not_retry — already capped)
4. Focus run `failed_tools` + `errors_top`
5. `files_touched` + `destructive_paths` + git dirty summary
6. `side_effects_top` + `secret_redaction_events`
7. `predecessor_run` pointer
8. `last_tools` (last 25 tool names from the run)
9. `transcript_tail` — **first to shrink/drop; skipped entirely when attention_level = `none`**

### Degraded mode

If the store cannot be opened (e.g., file lock contention, corruption), the pack is built from sticky state only with `degraded = true`. An empty or degraded pack is still injected — "something" beats "nothing."


## 5. Continuity modes

Three modes control when launch injection happens:

| Mode | Launch inject | End-of-run MEMORY write | Use case |
|---|---|---|---|
| `always` | Always (env + files + preamble) | Always | New projects, CI fleets, memory-bus adopters |
| `attention` | Only when `attention_level ≠ none` | Always | Conservative — no noise on clean success |
| `off` | Never | Never | Opt-out, legacy 1.0 behavior |

### Precedence

1. CLI flag (`--continuity always|attention|off` on `blackbox run`)
2. `BLACKBOX_CONTINUITY` environment variable
3. `BLACKBOX_AUTO_RESUME` environment variable (1.0 compat — `0` = off, `1` = attention)
4. `[capture].continuity` in `.blackbox/config.toml`
5. Project default: `always` for new enables, `attention` for migrated 1.1 projects

### Migration from 1.1

Re-enabling an existing project preserves the current continuity mode — no silent flip. Use `blackbox enable --continuity always` or `--memory-bus` to opt in explicitly.

---

## 6. Launch injection

When continuity is active, the following happens before the harness starts:

### File injection

| File | Format | Contents |
|---|---|---|
| `.blackbox/MEMORY.md` | Markdown | Human-readable memory pack |
| `.blackbox/MEMORY.json` | JSON | Machine-readable memory pack |
| `.blackbox/RESUME.md` | Markdown | Identical copy (1.0 backward compat) |
| `.blackbox/RESUME.json` | JSON | Identical copy (1.0 backward compat) |

### Environment variables

| Variable | Value |
|---|---|
| `BLACKBOX_MEMORY_FILE` | Path to MEMORY.md |
| `BLACKBOX_MEMORY_SCHEMA` | `blackbox.memory/v1` |
| `BLACKBOX_CONTINUITY` | `1` (set when active) |
| `BLACKBOX_RESUME_FILE` | Path to RESUME.md (legacy) |
| `BLACKBOX_RESUME_RUN_ID` | Focus run ID (when attention ≥ continue) |
| `BLACKBOX_RESUME_HINT` | Short one-line context hint |

### Preamble injection (strong harnesses only)

For harnesses with a known prompt flag (e.g., `claude -p`, `codex exec`), a compact preamble is prepended:

```
<<<BLACKBOX_UNTRUSTED_MEMORY>>>
project: <project_root>
attention: <level>
headline: <headline>
next: <next_action>
claim: <claim one-liner or "none">
<<<END_BLACKBOX_UNTRUSTED_MEMORY>>>
```

**Strength matrix:**

| Class | Harnesses | Delivery |
|---|---|---|
| Strong | `claude -p`/`--print`, `codex exec` | Env + files + compact preamble prepended |
| Weak | aider, gemini, grok last-arg | Env + files + best-effort last-arg prepend |
| File/env only | Interactive TUI, cursor, opencode, unknown | Env + files only; no argv mutation |
| Escape | `BLACKBOX_OFF`, nest, `continuity=off` | No injection |


## 7. Claims

One **active project claim** exists per project, stored in sticky state and guarded by `state.lock`.

### Lifecycle

1. **Acquire** — Under exclusive `state.lock`: if no active claim or it has expired (`expires_at < now`), write a new `ClaimPointer` with holder, TTL, and session ID. If a live claim exists from another agent, return conflict.
2. **Hold** — Claim is valid until `expires_at`. Default TTL is **1800 seconds (30 minutes)**.
3. **Release** — Under exclusive `state.lock`: clear `active_claim`.
4. **Heartbeat** — Extends `expires_at`. Performed on continuity prepare or explicit `claim heartbeat`.
5. **Expiry** — A claim is considered expired when `expires_at < now`. Any agent may acquire over an expired claim.

### ClaimPointer

```rust
pub struct ClaimPointer {
    pub holder: String,          // Agent identifier
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub run_id: Option<String>,  // Run that holds the claim
    pub session_id: Option<String>,
}
```

### auto_claim

| Setting | Default | Behavior |
|---|---|---|
| `auto_claim` | `false` | Auto-acquire on run start, release on run end |
| `auto_claim` on `--ci` | `true` (for that invocation) | CI fleets opt into coordination |
| TTL | 1800s | Released in `RunSupervisor` finally/drop path |

### Conflict behavior

When a claim conflict is detected (another agent holds the lock), the memory pack includes a conflict string and sets `attention_level = continue`. The harness is **never blocked** from starting — the conflict is advisory unless `claim.policy = block_record` **and** the path is explicit `blackbox run` (not maybe-run).

---

## 8. Gate modes

Gate modes provide optional enforcement on **explicit** `blackbox run` only. The ambient shell (`maybe-run`) is **never** blocked.

| Mode | `blackbox run` | `maybe-run` / shell wrap |
|---|---|---|
| `off` | No gate | No gate |
| `warn` | Stderr warning + pack flag; child starts | Stderr warning only if TTY allows |
| `require_ack` | Child does **not** start until `blackbox ack` or `BLACKBOX_ACK=1` | Treat as `warn` — never blocks |

### ack contract

```bash
# An agent or operator acknowledges the memory pack
blackbox ack

# Or set env before launch
export BLACKBOX_ACK=1
blackbox run -- <command>
```

The `require_ack` mode is for fleets and critical paths where reading prior context is non-negotiable.

---

## 9. MCP / CLI surfaces

| Surface | Operations |
|---|---|
| `blackbox memory show --json` | Returns full project memory pack |
| `blackbox memory set --goal "..." --open "..."` | Updates intent fields |
| `blackbox claim acquire\|release\|status` | Project claim management |
| `blackbox resolve [--clear-wip]` | Clears unresolved failure |
| `blackbox status --json` | Returns attention.level + project_memory |
| `blackbox handoff --json` | Status + memory pack |
| `blackbox ack` | Acknowledges gate |
| MCP `blackbox_memory` | Project memory pack |
| MCP `blackbox_claim` | acquire/release/status |
| MCP `blackbox_resolve` | Clear unresolved failure |
| MCP `blackbox_memory_update` | Set goal/open_items |

