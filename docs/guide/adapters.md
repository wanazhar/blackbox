# Harness adapters

**Answers:** Which agent CLIs blackbox detects, what structured signal you get, where native logs are scanned, and how to add a custom binary to the wrap list.

Related: [leave-it-on](leave-it-on.md) (ambient wrap), [stream-protocol](../reference/stream-protocol.md) (custom NDJSON), [concepts](concepts.md) (semantic vs raw terminal).

---

## What an adapter does

On each supervised run, blackbox picks a **`HarnessAdapter`** from argv (first match wins):

1. **Detect** — basename / argv patterns  
2. **Parse** — lift tool calls, results, session, usage from PTY and/or native logs into `TraceEvent`s  
3. **Optional launch prepare** — continuity inject / resume flags on **explicit** `blackbox run` (never ambient)

If parse misses something, the **PTY timeline still exists**. Adapters improve structure; they are not a substitute for capture.

Detection order (specific → generic):

`claude` → `codex` → `aider` → `gemini` → `cursor` → `opencode` → `grok` → **`generic`**

Code: `src/adapters/detect.rs`.

---

## Default ambient wrap list

Basenames in `capture.wrap` (defaults):

| Basename | Adapter id |
|---|---|
| `claude` | `claude` |
| `codex` | `codex` |
| `aider` | `aider` |
| `cursor`, `cursor-agent` | `cursor` |
| `gemini` | `gemini` |
| `opencode` | `opencode` |
| `grok` | `grok` |

Anything else recorded via `blackbox run -- my-tool` uses **generic** (plaintext / NDJSON heuristics).

---

## Per-adapter notes

### Claude (`claude`)

| | |
|---|---|
| **Detect** | argv0 basename `claude` |
| **Parse** | stream-json / NDJSON tool events + plaintext fallback |
| **Native logs (project scope)** | `.claude/logs`, `.claude/projects`, `.claude/session-env`, `.claude/` |
| **Native logs (home, if enabled)** | `~/.claude/…` |
| **Launch / resume** | Strong support for `-p` and session resume prepare on explicit run |

```bash
blackbox run -- claude -p "summarize git status"
```

### Codex (`codex`)

| | |
|---|---|
| **Detect** | basename `codex` |
| **Parse** | Codex event stream + plaintext fallback |
| **Native logs** | project `.codex/logs`, `.codex/sessions`; home `~/.codex/…` when scope allows |
| **Typical argv** | `codex exec …` |

```bash
blackbox run -- codex exec "fix the flaky test"
```

### Aider (`aider`)

| | |
|---|---|
| **Detect** | basename `aider` |
| **Parse** | Plaintext-oriented tool heuristics |
| **Native logs** | project root + `.aider/`; home `~/.aider` if scope=home |
| **Note** | Log discovery treats `.aider*` specially under project trees |

### Gemini (`gemini`)

| | |
|---|---|
| **Detect** | basename `gemini` |
| **Parse** | NDJSON-or-plaintext |
| **Native logs** | `.gemini/`, `.gemini/tmp`; home `~/.gemini`, `~/.config/gemini` |

### Cursor (`cursor` / `cursor-agent`)

| | |
|---|---|
| **Detect** | `cursor`, `cursor-agent`, `cursor-agent-cli` |
| **Parse** | Plaintext + structured markers when present |
| **Native logs** | `.cursor/`, `.cursor/projects`; home Cursor config / Application Support paths on macOS |

### OpenCode (`opencode`)

| | |
|---|---|
| **Detect** | basename `opencode` |
| **Parse** | NDJSON-or-plaintext |
| **Native logs** | `.opencode/`, logs; home share path when scope=home |

### Grok (`grok`)

| | |
|---|---|
| **Detect** | basename `grok` |
| **Parse** | NDJSON-or-plaintext |
| **Native logs** | `.grok/`, sessions; home `~/.grok`, `~/.config/grok` |

### Generic

| | |
|---|---|
| **Detect** | Fallback for everything else |
| **Parse** | [Stream protocol](../reference/stream-protocol.md) NDJSON when present; else terminal-only structure |
| **Use** | Custom agents, scripts, `npm test`, shells |

```bash
blackbox run -- ./my-agent --json-stream
# emit tool_call / tool_result lines per stream-protocol.md
```

---

## Native log scope

Config: `capture.native_log_scope`

| Value | Behavior |
|---|---|
| `project` (**default**) | Only under project tree — no home-dir ingest |
| `home` | Project + well-known home harness dirs |
| `off` | Disable native log polling |

Prefer `project` for privacy. Home scope copies more session recovery material into the store — see [security](security.md).

---

## Ambient vs explicit for adapters

| Path | Adapter parse | Continuity inject / prepare_launch |
|---|---|---|
| Ambient `maybe-run` | Yes | **No** (observe-only) |
| Explicit `blackbox run` | Yes | Yes when continuity allows |
| `--observe-only` / `--eval` | Yes | **No** |

---

## Custom binary on wrap list

1. Install a basename you control (or symlink).  
2. Add to config:

```toml
[capture]
wrap = ["claude", "codex", "my-agent"]
```

3. Prefer emitting [stream protocol](../reference/stream-protocol.md) lines for tool structure.  
4. Re-enable shell wrappers if needed: `blackbox enable --install-shell`  
5. Verify: `blackbox run -- my-agent …` then `timeline latest --kind tool.call`

Contributor path for a first-class adapter: [AGENTS.md](https://github.com/wanazhar/blackbox/blob/master/AGENTS.md) (“Adding a new harness adapter”).

---

## Verify detection

```bash
# after a run
blackbox show latest --json | jq '.data.run.adapter // .data.adapter // .'
# or inspect notes / run record for adapter id
blackbox timeline latest --kind tool.call
```

Unit smoke: `cargo test --test ci_eval detects_post_11_adapters`

---

## Limitations (honest)

- Interactive full-screen TUIs may not emit machine-readable tool events  
- Vendor log layouts change; pollers are best-effort  
- Adapter id is detection, not a guarantee of complete tool coverage  
- Home log scope increases residual secret surface  

---

## See also

- [cheatsheet](cheatsheet.md) · [recipes](recipes.md) · [leave-it-on](leave-it-on.md)  
- [../reference/stream-protocol.md](../reference/stream-protocol.md)  
- [../internals/capture-pipeline.md](../internals/capture-pipeline.md)  
