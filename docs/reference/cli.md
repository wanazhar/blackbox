# CLI reference

All blackbox subcommands, arguments, exit codes, and JSON output schemas. Every command accepts `--json` for machine-readable output wrapped in the `blackbox.cli/v1` envelope.

---

## Global flags

| Flag | Env | Purpose |
|---|---|---|
| `--store <path>` | `BLACKBOX_DB` | Override store database path |
| `--json` | — | Machine-readable JSON output |
| `--no-redact` | — | Disable redaction on capture/export/sync |
| `-h` / `--help` | — | Print help |
| `-V` / `--version` | — | Print version |

---

## 1. `enable` / `disable`

Enable or disable project-level capture.

### `enable`

```bash
blackbox enable [--install-shell] [--uninstall-shell] [--memory-bus]
                [--continuity always|attention|off] [--shell bash|zsh|powershell]
```

| Arg | Description |
|---|---|
| `--install-shell` | Install shell wrappers for common harnesses |
| `--uninstall-shell` | Remove previously installed shell wrappers |
| `--memory-bus` | Enable 1.2 memory bus (sets continuity=always) |
| `--continuity <mode>` | Set continuity mode directly |
| `--shell <kind>` | Shell kind for wrappers (bash, zsh, powershell) |

**Use case:** First-time project setup. Creates `.blackbox/` directory, default config, and optionally installs shell wrappers.

**Scenario:** A developer starts a new project and wants ambient capture:

```bash
cd ~/new-project
git init
blackbox enable --install-shell --memory-bus
# Now `claude`, `codex`, etc. are auto-wrapped
```

> On re-enable, existing continuity mode is preserved. Use `--continuity` or `--memory-bus` to change it.

### `disable`

```bash
blackbox disable
```

Disables project capture. Does NOT remove `.blackbox/` data — you can re-enable later.

---

## 2. `run`

Supervise a command under observation.

```bash
blackbox run [--name <label>] [--ci] [--artifact-dir <dir>] [--tag <tag>]...
             [--no-auto-resume] [--continuity always|attention|off]
             [--gate-mode off|warn|require_ack] [--insecure-raw]
             [--project <dir>]
             [--store <path>]
             -- <command> [args...]
```

| Arg | Description |
|---|---|
| `--name <label>` | Human-readable label |
| `--ci` | Propagate child exit code (exit 1 on failure) |
| `--artifact-dir <dir>` | Write run.json, postmortem.json, portable.json |
| `--tag <tag>` | Add tags (repeatable) |
| `--no-auto-resume` | Skip auto-resume injection |
| `--continuity <mode>` | Override continuity mode |
| `--gate-mode <mode>` | Gate mode (warn/require_ack) |
| `--insecure-raw` | Store raw PTY bytes as blobs (dangerous) |
| `--project <dir>` | Project directory (default: cwd) |
| `--store <path>` | Override store path |

**Use case:** Record a specific command with full capture.

**Scenario: Run a CI test suite and save artifacts:**

```bash
blackbox run --ci --artifact-dir ./ci-artifacts --tag ci -- npm test
```

**Scenario: Debug a failing agent harness:**

```bash
blackbox run --name "fix-login" -- claude -p "Fix the login bug"
```

**JSON output:**

```json
{
  "ok": true,
  "command": "run",
  "data": {
    "run_id": "<uuid>",
    "short_id": "abc12345",
    "status": "succeeded",
    "exit_code": 0,
    "attention_needed": false,
    "handoff_hint": null
  }
}
```

## 3. `maybe-run`

Project-gated ambient capture for shell wrappers. Not intended for direct use.

```bash
blackbox maybe-run -- <name> [args...]
```

Evaluates: `BLACKBOX_OFF` -> nest check -> project enabled -> wrap list -> record or passthrough.

**Decision order:**

| # | Condition | Action |
|---|---|---|
| 1 | `BLACKBOX_OFF` set | Passthrough bare command |
| 2 | `BLACKBOX_ACTIVE_RUN` set | Passthrough (nested) |
| 3 | No enabled project | Passthrough |
| 4 | Basename not in wrap list | Passthrough |
| 5 | Else | Record under project store |

---

## 4. `status`

Show project capture status, last run, attention level, and suggested next commands.

```bash
blackbox status [--store <path>]
```

**Use case:** Quick check of project state before starting work.

**Scenario:** An agent starts a session and checks what happened:

```bash
blackbox status --json
```

Returns `enabled`, `store_path`, `last_run`, `attention.level`, `project_memory`, `next_commands`.

---

## 5. `handoff`

Agent handoff: status + resume pack + project memory.

```bash
blackbox handoff [--always] [--store <path>]
```

| Arg | Description |
|---|---|
| `--always` | Always attach resume pack (not just when attention needed) |

**Use case:** Agent session start.

```bash
blackbox handoff --json
```

Returns `status` + `project_memory` (full `blackbox.memory/v1`) + `resume_pack` (on attention).

---

## 6. `memory show` / `memory set`

### `memory show`

Display the project memory pack.

```bash
blackbox memory show [--store <path>]
```

**JSON output:** Full `blackbox.memory/v1` pack.

### `memory set`

Update intent fields on sticky state.

```bash
blackbox memory set [--goal <text>] [--clear-goal] [--open <item>]... [--clear-open]
```

| Arg | Description |
|---|---|
| `--goal <text>` | Set project goal |
| `--clear-goal` | Clear the goal |
| `--open <item>` | Add an open TODO item (repeatable, cap 8) |
| `--clear-open` | Clear all open items |

**Scenario:**

```bash
blackbox memory set --goal "Fix CI" --open "Fix flaky test"
```


## 7. `claim`

Manage the project claim.

```bash
blackbox claim acquire [--holder <name>] [--ttl <seconds>]
blackbox claim release
blackbox claim status
```

| Subcommand | Description |
|---|---|
| `acquire` | Acquire exclusive project claim. Fails if another agent holds live claim |
| `release` | Release your claim |
| `status` | Show current claim (without lock, may be stale) |

**Scenario:** Agent takes project hold:

```bash
blackbox claim acquire --holder "claude-code"
```

---

## 8. `resolve`

Clear an unresolved failure from sticky state.

```bash
blackbox resolve [<run-id>] [--clear-wip]
```

| Arg | Description |
|---|---|
| `<run-id>` | Specific run to resolve (default: latest unresolved) |
| `--clear-wip` | Also clear open items and goal |

**Scenario:** After fixing the root cause:

```bash
blackbox resolve --clear-wip
```

---

## 9. `ack`

Acknowledge the gate requirement (`gate_mode=require_ack`).

```bash
blackbox ack
```

Also honored via `BLACKBOX_ACK=1` env var.

---

## 10. `runs`

List recorded runs.

```bash
blackbox runs [--limit <N>] [--status succeeded|failed|cancelled]
              [--tag <tag>] [--json] [--store <path>]
```

**Scenario:** Show last 5 failed runs:

```bash
blackbox runs --limit 5 --status failed --json
```

---

## 11. `show`

Show detailed view of a single run.

```bash
blackbox show <run-id> [--json] [--tui] [--transcript] [--tools] [--store <path>]

With `--tui`, the daily-driver screen shows a **run header** (status, adapter,
duration, capture quality, files, failures, side-effect risk, observe-only vs
record mode) plus a content panel switched by keys:

| Key | Panel |
|---|---|
| `t` | Timeline |
| `o` | Processes |
| `f` | Files |
| `e` | Failures |
| `x` | Side effects |
| `c` | Capture quality |
| `p` | Postmortem |
| `h` | Handoff / resume |
| `r` | Replay preflight (guarantees) |
| `d` | Diff CLI hint |
| `/` | Toggle bookkeeping on timeline |
| `?` | Help |
| `q` | Quit |

Equivalent CLI/JSON surfaces remain available without the TUI.
```

| Arg | Description |
|---|---|
| `--tui` | Open interactive ratatui TUI viewer |
| `--transcript` | Print full terminal transcript |
| `--tools` | Print tool call timeline |

**Scenario:** Inspect a failed run:

```bash
blackbox show abc12345 --json
```

---

## 12. `timeline`

Display event timeline for a run.

```bash
blackbox timeline <run-id> [--semantic] [--kind <kind>] [--source <source>]
                          [--json] [--store <path>]
```

| Arg | Description |
|---|---|
| `--semantic` | Group by semantic meaning (tool calls, errors, etc.) |
| `--kind <kind>` | Filter by event kind (e.g. `tool.call`, `terminal.output`) |
| `--source <source>` | Filter by event source (e.g. `Tool`, `Terminal`, `Filesystem`) |

**Scenario:** View only tool calls in a run:

```bash
blackbox timeline abc12345 --kind tool.call --json
```

---

## 13. `inspect`

Show full details of a single event, including blob content.

```bash
blackbox inspect <event-id> [--json] [--store <path>]
```

**Scenario:** Inspect a specific tool result:

```bash
blackbox inspect evt_xyz789 --json
```

---

## 14. `diff`

Compare two runs.

```bash
blackbox diff <run-a> <run-b> [--trajectory] [--json] [--store <path>]
```

| Arg | Description |
|---|---|
| `--trajectory` | Include human-readable trajectory report |

**Scenario:** Compare a failed run with a successful retry:

```bash
blackbox diff abc123 xyz789 --trajectory
```

---

## 15. `analyze`

Run analysis passes (errors, side-effects, correlations) on a run.

```bash
blackbox analyze <run-id> [--pass error|side-effect|correlation] [--json] [--store <path>]
```

| Arg | Description |
|---|---|
| `--pass <name>` | Run a specific pass only (repeatable). Default: all |

**Scenario:** Analyze errors in a failed run:

```bash
blackbox analyze abc12345 --pass error --json
```


## 16. `search`

Full-text search across events (FTS5).

```bash
blackbox search <query> [--limit <N>] [--json] [--store <path>]
```

**Scenario:** Find all events mentioning "timeout":

```bash
blackbox search "timeout" --limit 10 --json
```

---

## 17. `watch`

Live-tail events for a run as they appear.

```bash
blackbox watch <run-id> [--store <path>]
```

**Scenario:** Watch a running CI job in real-time:

```bash
blackbox watch abc12345
```

---

## 18. `export`

Export a run trace to a shareable format.

```bash
blackbox export <run-id> [--format jsonl|html|portable]
                         [--no-redact] [--inline-blobs]
                         -o <output-path> [--store <path>]
```

| Arg | Description |
|---|---|
| `--format` | Output format: `jsonl`, `html`, or `portable` (default portable) |
| `--no-redact` | Export unredacted (dangerous) |
| `--inline-blobs` | Include blob content inline (portable only) |
| `-o <file>` | Output file path |

---

## 19. `import`

Import a portable JSON archive into the store.

```bash
blackbox import <file> [--store <path>]
```

---

## 20. `sync push` / `sync pull`

Sync traces with a remote backend.

```bash
blackbox sync push [--dir <path>] [--remote <url>] [--s3 <url>] [--no-redact]
blackbox sync pull [--dir <path>] [--remote <url>] [--s3 <url>] [--no-redact]
```

---

## 21. `serve`

Start the local web dashboard.

```bash
blackbox serve [--bind <addr>] [--token <token>] [--store <path>]
```

| Arg | Description |
|---|---|
| `--bind <addr>` | Bind address (default `127.0.0.1:7788`) |
| `--token <token>` | Auth token for API access |

**Endpoints:**

| Path | Description |
|---|---|
| `GET /` | Dashboard home |
| `GET /api/status` | Project status |
| `GET /api/handoff` | Handoff JSON |
| `GET /api/runs` | Runs list |

## 22. `replay`

Replay a recorded run.

```bash
blackbox replay <run-id> [--mode timeline|mock|sandbox] [--store <path>]
```

| Mode | Description |
|---|---|
| `timeline` | Print event timeline |
| `mock` | Re-run tool calls with mock responses |
| `sandbox` | Replay in a sandboxed environment |

---

## 23. `fork`

Fork a new run from recorded context.

```bash
blackbox fork <run-id> [--launch <command>] [--store <path>]
```

---

## 24. `scrub`

Re-redact historical secrets and optionally GC orphaned blobs.

```bash
blackbox scrub [--gc] [--store <path>]
```

---

## 25. `doctor`

Diagnose store health and environment.

```bash
blackbox doctor [--reindex] [--json] [--store <path>]
```

Output: store path, schema version, run count, DB size, blob count/size, storage warning, memory/claim/continuity fields.

---

## 26. `rm`

Delete one or more runs.

```bash
blackbox rm <run-id>... [--store <path>]
```

Note: blob files not removed (use `scrub --gc`).

---

## 27. `purge`

Delete runs by policy.

```bash
blackbox purge [--keep <N>] [--status <s>] [--older-than <duration>]
               [--dry-run] [--store <path>]
```

| Arg | Description |
|---|---|
| `--keep <N>` | Keep N most recent runs |
| `--older-than <d>` | Delete runs older than duration (e.g. `30d`) |
| `--dry-run` | Simulate without deleting |

---

## 28. `tags` / `tag`

List tags or add/remove a tag on a run.

```bash
blackbox tags
blackbox tag <run-id> <tag>
blackbox tag --remove <run-id> <tag>
```

---

## 29. `stats`

Aggregate store dashboard.

```bash
blackbox stats [--json] [--store <path>]
```

Output: run count, event count, blob count, db size, total storage, warnings.

---

## 30. `gc`

Run retention policy (dry-run or apply) from config.

```bash
blackbox gc [--dry-run] [--store <path>]
```

---

## 31. `postmortem`

One-command failure/success postmortem.

```bash
blackbox postmortem <run-id> [--fail-on-failure] [--json] [--store <path>]
```

| Arg | Description |
|---|---|
| `--fail-on-failure` | Exit 1 if run failed/cancelled |

---

## 32. `summary`

Run summary (alias for postmortem).

```bash
blackbox summary <run-id> [--json] [--store <path>]
```

---

## 33. `context`

Bounded resume pack for a single run.

```bash
blackbox context <run-id> [--for-resume] [--max-tokens <N>] [--json] [--store <path>]
```

| Arg | Description |
|---|---|
| `--for-resume` | Build resume-optimized pack |
| `--max-tokens <N>` | Token budget (default 4000) |

---

## 34. `mcp`

Start the MCP stdio server.

```bash
blackbox mcp [--store <path>]
```

Reads JSON-RPC 2.0 requests from stdin, writes responses to stdout.

---

## 35. `completions`

Generate shell completion scripts.

```bash
blackbox completions <shell>
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error / run failed (`--ci` mode) |
