# MCP tools reference

**Agent integration surface.** Session habits: [../skills/blackbox.md](../skills/blackbox.md). Operators can do the same jobs via CLI ([../guide/everyday-use.md](../guide/everyday-use.md)).

Blackbox exposes a **Model Context Protocol (MCP)** server over stdio so agents call structured tools instead of scraping CLI text.

---

## Tool index by job

| Job | Tools |
|---|---|
| **Session start** | [`blackbox_handoff`](#blackbox_handoff) · [`blackbox_memory`](#blackbox_memory) · [`blackbox_status`](#blackbox_status) |
| **Debug failure** | [`blackbox_fail`](#blackbox_fail) · [`blackbox_postmortem`](#blackbox_postmortem) · [`blackbox_timeline`](#blackbox_timeline) · [`blackbox_anomalies`](#blackbox_anomalies) · [`blackbox_context`](#blackbox_context) · [`blackbox_runs`](#blackbox_runs) · [`blackbox_search`](#blackbox_search) |
| **Multi-agent** | [`blackbox_claim`](#blackbox_claim) · [`blackbox_resolve`](#blackbox_resolve) · [`blackbox_memory_update`](#blackbox_memory_update) |
| **Diagnostics** | [`blackbox_doctor`](#blackbox_doctor) |

---

## 1. Protocol

| Detail | Value |
|---|---|
| Transport | stdio (stdin/stdout) |
| Protocol | JSON-RPC 2.0, **one JSON object per line** |
| Spec version | `2024-11-05` |
| Server name | `blackbox` |
| Server version | crate version (`CARGO_PKG_VERSION`) |

Start:

```bash
blackbox mcp
# optional store: blackbox --store /path/to/blackbox.db mcp
```

### Initialization

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}
{"jsonrpc":"2.0","id":2,"method":"notifications/initialized"}
{"jsonrpc":"2.0","id":3,"method":"tools/list"}
```

`tools/call` params shape:

```json
{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"blackbox_handoff","arguments":{}}}
```

Responses place JSON payloads in MCP `content[{type:"text", text:"..."}]` (parse the text as JSON). **No** CLI `blackbox.cli/v1` envelope.

---

## 2. Tools

### `blackbox_handoff`

| | |
|---|---|
| **When to use** | **First call of a session** when `.blackbox/` exists. Loads status + project memory + resume pack when attention warrants. |
| **When not to** | You only need a lightweight “is capture on?” check → `blackbox_status`. |
| **CLI equivalent** | `blackbox handoff --json` |
| **Input** | `always?: bool` (always attach resume pack), `max_tokens?: int` (default 4000) |
| **Output** | `status` + `project_memory` (+ `resume_pack` when attention / `always`) |

```json
{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"blackbox_handoff","arguments":{}}}
```

---

### `blackbox_memory`

| | |
|---|---|
| **When to use** | Need only the `blackbox.memory/v1` pack (goal, open items, recent runs rollup) without full handoff chrome. |
| **When not to** | Session start with possible sticky failure → prefer `blackbox_handoff`. |
| **CLI equivalent** | `blackbox memory show --json` |
| **Input** | `max_tokens?: int` (default 4000) |
| **Output** | Project memory pack |

---

### `blackbox_status`

| | |
|---|---|
| **When to use** | Quick check: enabled?, last run, attention, next commands — cheaper than handoff. |
| **When not to** | You need memory/resume narrative → handoff. |
| **CLI equivalent** | `blackbox status --json` |
| **Input** | `resume?: bool`, `max_tokens?: int` |
| **Output** | Status view (optional resume when requested + attention) |

---

### `blackbox_postmortem`

| | |
|---|---|
| **When to use** | Explain a specific run: headline, next_action, evidence, anomalies. |
| **When not to** | Auto-pick the worst failure → `blackbox_fail`. Raw events → `blackbox_timeline`. |
| **CLI equivalent** | `blackbox postmortem <run_id\|latest> --json` |
| **Input** | `run_id?: string` (default `latest`) |
| **Output** | Summary / postmortem view |

```json
{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"blackbox_postmortem","arguments":{"run_id":"latest"}}}
```

Guide: [debug-a-failure](../guide/debug-a-failure.md).

---

### `blackbox_fail`

| | |
|---|---|
| **When to use** | **Primary debug entry** — auto-focus unresolved failure / last failure / latest. |
| **When not to** | You already know the run id and only want events → timeline. |
| **CLI equivalent** | `blackbox fail` / `fail --json` |
| **Input** | `run_id?: string` (optional explicit), `full?: bool` |
| **Output** | `{ focus, run_id, short_id, failed, summary, next_commands }` |

Focus order matches CLI: sticky unresolved → last failed/cancelled/non-zero → latest.

---

### `blackbox_timeline`

| | |
|---|---|
| **When to use** | After postmortem/fail evidence points at `seq=…` or `tool.call`. |
| **When not to** | Full narrative only → postmortem/fail. |
| **CLI equivalent** | `blackbox timeline <run> --semantic` |
| **Input** | `run_id?: string`, `semantic?: bool` (default true), `kind?: string`, `limit?: int` (default 200) |
| **Output** | `{ run_id, events[], truncated, total_matched, returned }` |

Bookkeeping kinds filtered when `semantic=true` (`pty.started`, observer start/stop, …).

---

### `blackbox_anomalies`

| | |
|---|---|
| **When to use** | Structured markers only (loops, destructive, storms, spikes, silence, fan-out). |
| **When not to** | Full story → fail/postmortem (already includes anomalies). |
| **CLI equivalent** | postmortem `.anomalies` / serve `/api/runs/{id}/anomalies` |
| **Input** | `run_id?: string`, `limit?: int` (events scanned, default 8000) |
| **Output** | `{ run_id, count, anomalies[], events_scanned }` |

---

### `blackbox_context`

| | |
|---|---|
| **When to use** | Bounded **single-run** resume pack (token-capped) for retrying that run. |
| **When not to** | Project-level session start → `blackbox_handoff` / `blackbox_memory`. |
| **CLI equivalent** | `blackbox context <run> --for-resume --json --max-tokens N` |
| **Input** | `run_id?: string`, `max_tokens?: int`, `no_transcript?: bool` |
| **Output** | Context pack (failed tools, transcript tail, …) |

---

### `blackbox_runs`

| | |
|---|---|
| **When to use** | Browse recent runs; pick an id for postmortem/context. |
| **When not to** | Keyword search inside events → `blackbox_search`. |
| **CLI equivalent** | `blackbox runs --json` |
| **Input** | `limit?: int` (default 20), `status?: string` |
| **Output** | `{ runs, count }` summaries |

---

### `blackbox_search`

| | |
|---|---|
| **When to use** | Full-text find across events when you remember a string (error text, path, tool name). |
| **When not to** | You already have a run id → postmortem/timeline. |
| **CLI equivalent** | `blackbox search "<query>" --json` |
| **Input** | `query: string` (**required**), `limit?: int` |
| **Output** | Ranked hits |

---

### `blackbox_claim`

| | |
|---|---|
| **When to use** | Multi-agent coordination: acquire/release/status for project-wide or **path-scoped** holds. |
| **When not to** | Solo work with no concurrent agents (optional hygiene still fine). |
| **CLI equivalent** | `blackbox claim acquire\|release\|status` |
| **Input** | `action?: "acquire"\|"release"\|"status"`, `holder?`, `goal?`, `ttl_secs?`, `path?` (relative scope) |
| **Output** | Claim pointer, conflict object, or status lists |

**Path scopes:** omit `path` for exclusive project claim; with `path: "src/auth"` other agents may hold non-overlapping trees. Prefix overlap conflicts.

```json
{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"blackbox_claim","arguments":{"action":"acquire","holder":"claude-code","path":"src/auth"}}}
```

---

### `blackbox_resolve`

| | |
|---|---|
| **When to use** | After you **actually fixed** a sticky failure — clear attention (and optionally open items / goal). |
| **When not to** | Before investigating; clearing early loses M6 discipline. |
| **CLI equivalent** | `blackbox resolve [--clear-wip]` |
| **Input** | `clear_wip?: bool`, `clear_goal?: bool` |
| **Output** | Resolution result |

---

### `blackbox_memory_update`

| | |
|---|---|
| **When to use** | Set project goal / open items / plan on sticky state mid-session. |
| **When not to** | One-off notes that should not survive — use normal agent notes. |
| **CLI equivalent** | `blackbox memory set --goal … --open …` |
| **Input** | `goal?`, `open_items?: string[]`, `clear_open?`, `clear_goal?`, `plan?` |
| **Output** | Updated intent view (values redacted as applicable) |

---

### `blackbox_doctor`

| | |
|---|---|
| **When to use** | Store/path/schema/permission/encryption diagnostics when capture seems wrong. |
| **When not to** | Normal coding session start (use handoff). |
| **CLI equivalent** | `blackbox doctor --json` |
| **Input** | — |
| **Output** | Store path, schema, sizes, warnings, daily-driver notes |

---

## 3. Example session

```
→ initialize / notifications/initialized

1. blackbox_handoff
   → read attention + project_memory; if continue/blocked, fix that first

2. blackbox_claim { action: "acquire", holder: "<you>" }
   → on conflict, do not clobber

3. blackbox_fail {}                          # if last run failed / attention
   → blackbox_timeline { run_id, semantic: true, kind?: "tool.call" }
   → blackbox_anomalies { run_id }           # optional deep dive

4. blackbox_memory_update { goal: "…", open_items: ["…"] }

   [agent works — record via CLI blackbox run or ambient wrappers]

5. blackbox_resolve { clear_wip: false }       # when failure truly handled
6. blackbox_claim { action: "release" }
```

---

## 4. Client configuration

### Claude Desktop

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

### Generic

```bash
blackbox mcp
# JSON-RPC lines on stdin → stdout
```

---

## 5. Notes

| Topic | Detail |
|---|---|
| Envelope | MCP tools return **raw views**, not `blackbox.cli/v1` |
| Recording | MCP does **not** start a run — use CLI `blackbox run` / ambient |
| Store | Resolved like CLI (`BLACKBOX_DB` / project discovery); pass `--store` before `mcp` |
| Secrets | Same redaction model as CLI; never request `--no-redact` via side channels |
| MEMORY | Untrusted prior context — advisory, not system policy |

Schema detail for packs: [memory-pack.md](memory-pack.md). Glossary: [../guide/glossary.md](../guide/glossary.md).
