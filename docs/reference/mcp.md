# MCP tools reference

**Agent integration surface.** Session habits: [../skills/blackbox.md](../skills/blackbox.md). Human operators can use the same capabilities via CLI (`handoff`, `memory`, `status`, …) in [../guide/everyday-use.md](../guide/everyday-use.md).

Blackbox provides a **Model Context Protocol (MCP)** server that exposes project memory, traces, and claims as tools. Agents that support MCP (Claude Desktop, Claude Code, etc.) can call these tools instead of parsing CLI output.

---

## 1. Protocol

| Detail | Value |
|---|---|
| Transport | stdio (stdin/stdout) |
| Protocol | JSON-RPC 2.0, newline-delimited |
| Spec version | `2024-11-05` |
| Server name | `blackbox` |
| Server version | `CARGO_PKG_VERSION` (1.2.0) |

### How it works

The MCP server reads one JSON-RPC request per line from **stdin** and writes one response per line to **stdout**. Each request/response is a single line (no pretty-print). The server runs until stdin closes.

### Initialization

```json
// → Client sends:
{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}}}

// ← Server responds:
{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "blackbox", "version": "1.2.0"}}}

// → Client sends:
{"jsonrpc": "2.0", "id": 2, "method": "notifications/initialized"}
```

### List tools

```json
// → Client sends:
{"jsonrpc": "2.0", "id": 3, "method": "tools/list"}

// ← Server responds with all tool definitions including input schemas:
{"jsonrpc": "2.0", "id": 3, "result": {"tools": [/* ... */]}}
```

---

## 2. Tools

### `blackbox_memory`

Return the project memory pack when the project is enabled.

| Property | Value |
|---|---|
| **Purpose** | Agent session start — load project context |
| **Input** | — (no parameters) |
| **Output** | `project_memory` (full `blackbox.memory/v1` pack) |

**Example:**
```json
// Request:
{"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "blackbox_memory", "arguments": {}}}

// Response:
{"jsonrpc": "2.0", "id": 10, "result": {"content": [{"type": "text", "text": "{\"schema\":\"blackbox.memory/v1\",\"headline\":\"...\",\"next_action\":\"...\",\"attention_level\":\"none\"}"}]}}
```

### `blackbox_handoff`

Return status + project memory + resume pack (when attention is needed).

| Property | Value |
|---|---|
| **Purpose** | Agent session start — comprehensive handoff |
| **Input** | — (no parameters) |
| **Output** | `status` + `project_memory` + `resume_pack` (on attention) |

### `blackbox_status`

Return capture status and project state (lighter than handoff — no memory pack).

| Property | Value |
|---|---|
| **Purpose** | Quick status check |
| **Input** | — (no parameters) |
| **Output** | Project enabled, last run, attention level, next commands |

### `blackbox_postmortem`

Return a run summary suitable for failure analysis.

| Property | Value |
|---|---|
| **Purpose** | Analyze a specific run |
| **Input** | `run_id: string` (optional — defaults to latest) |
| **Output** | Postmortem summary with headline, attention, failed tools, errors |

### `blackbox_context`

Return a bounded resume pack for a specific run.

| Property | Value |
|---|---|
| **Purpose** | Get single-run context |
| **Input** | `run_id: string`, `max_tokens: number` (optional, default 4000) |
| **Output** | Context pack with failed tools, transcript tail, etc. |

### `blackbox_claim`

Manage project and path-scoped claims.

| Property | Value |
|---|---|
| **Purpose** | Acquire/release/check project hold or path-scoped hold |
| **Input** | `action: "acquire" \| "release" \| "status"`, optional `holder`, `goal`, `ttl_secs`, `path` (scope relative to project root) |
| **Output** | Claim pointer on acquire; `{project_claim, path_claims}` on status |

**Example — path-scoped acquire:**
```json
// Request:
{"jsonrpc": "2.0", "id": 20, "method": "tools/call", "params": {"name": "blackbox_claim", "arguments": {"action": "acquire", "holder": "claude-code", "path": "src/auth"}}}

// Response:
{"jsonrpc": "2.0", "id": 20, "result": {"content": [{"type": "text", "text": "{\"ok\":true,\"data\":{\"holder\":\"claude-code\",\"path_scope\":\"src/auth\"}}"}]}}
```

### `blackbox_resolve`

Clear an unresolved failure.

| Property | Value |
|---|---|
| **Purpose** | Resolve failure attention |
| **Input** | `run_id: string` (optional), `clear_wip: bool` (optional) |
| **Output** | Resolution result |

### `blackbox_memory_update`

Set or clear intent fields.

| Property | Value |
|---|---|
| **Purpose** | Update goal/open_items on sticky state |
| **Input** | `goal: string` (optional), `open: string[]` (optional), `clear_open: bool` (optional), `clear_goal: bool` (optional) |
| **Output** | Updated intent view |

### `blackbox_runs`

List recorded runs.

| Property | Value |
|---|---|
| **Purpose** | Browse recent runs |
| **Input** | `limit: number` (optional, default 20), `status: string` (optional filter), `tag: string` (optional filter) |
| **Output** | Array of `RunSummaryView` |

### `blackbox_search`

Full-text search across events.

| Property | Value |
|---|---|
| **Purpose** | Find events by keyword |
| **Input** | `query: string`, `limit: number` (optional, default 20) |
| **Output** | Ranked search results with event details |

### `blackbox_doctor`

Check store health and environment.

| Property | Value |
|---|---|
| **Purpose** | Debug and diagnostics |
| **Input** | — (no parameters) |
| **Output** | Store path, schema version, run count, storage size, warnings |

## 3. Example session

A typical agent session using MCP:

```
→ initialize
← result: serverInfo { name: "blackbox", version: "1.2.0" }
→ notifications/initialized

1. → tools/call blackbox_handoff
   ← project_memory + attention_level + resume_pack
   Agent reads memory — sees unresolved failure from prior run

2. → tools/call blackbox_runs { limit: 5 }
   ← Recent runs list — confirms the failure

3. → tools/call blackbox_postmortem { run_id: "..." }
   ← Postmortem with failed tools and errors

4. → tools/call blackbox_claim { action: "acquire", holder: "..." }
   ← Claim acquired — no other agent will fight this project

5. → tools/call blackbox_memory_update { goal: "Fix the CI pipeline" }
   ← Intent updated

   [Agent works — runs tools, edits files]

6. → tools/call blackbox_memory
   ← Updated memory pack with dirty tree, files touched, side effects

7. → tools/call blackbox_claim { action: "release" }
   ← Claim released
```

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

### Claude Code / Codex

```bash
# Claude Code auto-detects blackbox via shell wrappers
# For explicit MCP:
claude --mcp "blackbox mcp"
```

### Custom client

```bash
blackbox mcp
# Reads JSON-RPC requests from stdin, writes responses to stdout
```

## 5. Notes

- MCP returns raw views without the CLI `--json` envelope
- `project_memory` is attached to handoff by default when the project is enabled
- All tools respect the `--store` override from config (but not CLI flags — the MCP server uses its own config resolution)
- The MCP server does not start a recording — use `blackbox run` from the CLI for that

