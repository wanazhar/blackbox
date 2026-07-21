# CLI reference

**Normative flag and subcommand list.** For task-oriented walkthroughs, start with [../guide/README.md](../guide/README.md).

Every command accepts global `--json` for machine-readable output (`blackbox.cli/v1` envelope — [json-api.md](json-api.md)). This page is exhaustive; use the job index below to jump.

---

## Command index by job

| Job | Commands |
|---|---|
| **Project setup** | [`setup`](#setup) · [`enable`](#1-enable-disable) · [`disable`](#1-enable-disable) |
| **Record** | [`run`](#2-run) · [`maybe-run`](#3-maybe-run) |
| **Status / memory / multi-agent** | [`status`](#4-status) · [`handoff`](#5-handoff) · [`memory`](#6-memory-show-memory-set) · [`claim`](#7-claim) · [`resolve`](#8-resolve) · [`ack`](#9-ack) · [`context`](#33-context) |
| **Inspect** | [`runs`](#10-runs) · [`show`](#11-show) · [`timeline`](#12-timeline) · [`inspect`](#13-inspect) · [`watch`](#17-watch) · [`search`](#16-search) |
| **Explain / compare** | [`fail`](#fail) · [`postmortem`](#31-postmortem) · [`summary`](#32-summary) · [`analyze`](#15-analyze) · [`diff`](#14-diff) |
| **Share / move data** | [`export`](#18-export) · [`import`](#19-import) · [`backup` / `restore`](#19b-backup-restore) · [`sync`](#20-sync-push-sync-pull) |
| **Dashboard / agents** | [`serve`](#21-serve) · [`mcp`](#34-mcp) |
| **Replay** | [`replay`](#22-replay) · [`fork`](#23-fork) |
| **Hygiene** | [`scrub`](#24-scrub) · [`doctor`](#25-doctor) · [`stats`](#29-stats) · [`gc`](#30-gc) · [`rm`](#26-rm) · [`purge`](#27-purge) · [`tags`](#28-tags-tag) |
| **Integrity / verification** | [`fsck`](#36-fsck) · [`verify`](#37-verify) · [`experiment`](#38-experiment) · [`report`](#39-report) · [`gate`](#40-gate) |
| **Capsules / budgets / index** | [`capsule`](#41-capsule) · [`cassette`](#42-cassette-experimental) · [`budget`](#43-budget) · [`adapter`](#44-adapter) · [`projects`](#45-projects) |
| **Shell** | [`completions`](#35-completions) |

Guide shortcuts: [getting-started](../guide/getting-started.md) · [debug](../guide/debug-a-failure.md) · [config](../guide/configuration.md) · [security](../guide/security.md) · [fsck](../guide/fsck-and-integrity.md) · [verification](../guide/verification.md).

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

## `setup`

**When to use:** First time in a repo — enable project, optional shell/memory/harden, sample run, doctor snapshot.

```bash
blackbox setup [--memory-bus] [--install-shell] [--harden] [--no-sample] [--require-ready]
               [--shell bash|zsh|fish|powershell]
```

| Arg | Description |
|---|---|
| `--memory-bus` | Continuity=always (not observe-only) |
| `--install-shell` | Install ambient wrappers |
| `--harden` | Trust profile: `encrypt_blobs`, project native logs, env allowlist, retention; key under `~/.config/blackbox/default.key` when possible (same as `enable --harden`) |
| `--no-sample` | Skip supervised `true` sample run |
| `--require-ready` | Exit non-zero if soft daily-driver not ready |

**JSON:** `command=setup` with project paths, flags, `sample_run_id`, `daily_driver_ready`, `next`.

---

## `fail`

**When to use:** Something broke — one-shot failure story without hunting run ids.

```bash
blackbox fail [run-id|latest] [--full] [--fail-on-failure]
```

**Focus order** (when run id omitted): sticky `unresolved_failure` → last failed/cancelled/non-zero → latest.

| Arg | Description |
|---|---|
| `run-id` | Optional explicit run (prefix ok) |
| `--full` | Larger event window for postmortem |
| `--fail-on-failure` | Exit 1 if focused run failed (CI) |

**JSON:** `command=fail` with `focus`, `run_id`, `failed`, `summary` (full postmortem), `next_commands`.

---

## 1. `enable` / `disable`

**When to use:** First time in a repo (`enable`); pause capture without deleting data (`disable`).

### `enable`

```bash
blackbox enable [--install-shell] [--uninstall-shell] [--memory-bus] [--harden]
                [--continuity always|attention|off] [--shell bash|zsh|powershell]
```

| Arg | Description |
|---|---|
| `--install-shell` | Install shell wrappers for common harnesses |
| `--uninstall-shell` | Remove previously installed shell wrappers |
| `--memory-bus` | Enable 1.2 memory bus (sets continuity=always) |
| `--harden` | Hardened trust profile: `encrypt_blobs`, project native logs, env allowlist, retention; external key + `.blackbox/HARDEN.txt` tip |
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

**When to use:** Deliberate supervised capture (CI, eval, continuity inject, debugging). Everything after `--` is the child command.

```bash
blackbox run [--name <label>] [--ci] [--eval] [--artifact-dir <dir>] [--tag <tag>]...
             [--observe-only] [--no-auto-resume] [--continuity always|attention|off]
             [--gate-mode off|warn|require_ack] [--insecure-raw]
             [--project <dir>]
             [--store <path>]
             -- <command> [args...]
```

| Arg | Description |
|---|---|
| `--name <label>` | Human-readable label |
| `--ci` | Propagate child exit code (exit 1 on failure) |
| `--eval` | Eval harness mode: force observe-only + CI exit codes + tags `eval`/`ci` (no launch mutation) |
| `--observe-only` | No prompt mutation, continuity inject, or env injection |
| `--artifact-dir <dir>` | Write run.json, postmortem.json, anomalies.json, summary.txt, **score.json**, portable.json |
| `--tag <tag>` | Add tags (repeatable) |
| `--no-auto-resume` | Skip auto-resume injection |
| `--continuity <mode>` | Override continuity mode |
| `--gate-mode <mode>` | Gate mode (warn/require_ack) |
| `--experiment <id>` | Link run to experiment (creates meta; auto-creates experiment row) |
| `--task` / `--variant` / `--attempt` / `--role` | Experiment cohort fields |
| `--model` / `--provider` / `--harness` / `--harness-version` | Experiment model fields |
| `--seed` / `--dataset-case` | Experiment reproducibility fields |
| `--max-wall` / `--max-processes` / `--max-output` / `--max-tool-calls` | Execution budgets (see [budgets guide](../guide/budgets-and-adapters.md)) |
| `--max-memory` / `--max-cpu-percent` / `--contained` | Memory/CPU cgroup prefs; contained preflight |
| `--insecure-raw` | Store raw PTY bytes as blobs (dangerous) |
| `--project <dir>` | Project directory (default: cwd) |
| `--store <path>` | Override store path |

**Use case:** Record a specific command with full capture.

**Scenario: Run a CI test suite and save artifacts:**

```bash
blackbox run --ci --artifact-dir ./ci-artifacts --tag ci -- npm test
```

**Scenario: Model/harness benchmark (observe-only, never mutates launch):**

```bash
blackbox run --eval --artifact-dir ./eval-out -- claude -p "solve the task"
# writes: run.json postmortem.json anomalies.json summary.txt score.json [portable]
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

**When to use:** Almost never by hand. Shell wrappers installed by `enable --install-shell` call this. Prefer `blackbox run` for deliberate recording.

```bash
blackbox maybe-run -- <name> [args...]
```

Evaluates: `BLACKBOX_OFF` → nest check → project enabled → wrap list → record or passthrough. Passthrough never opens the store. Ambient record is always **observe-only**.

**Decision order:**

| # | Condition | Action |
|---|---|---|
| 1 | `BLACKBOX_OFF` set | Passthrough bare command |
| 2 | Nested under active supervisor (PID marker or legacy `BLACKBOX_ACTIVE_RUN`) | Passthrough (nested) |
| 3 | No enabled project | Passthrough |
| 4 | Basename not in wrap list | Passthrough |
| 5 | Else | Record under project store; register supervisor PID marker |

Operator guide: [leave-it-on](../guide/leave-it-on.md). Normative: [ambient-contract](../ambient-contract.md).

---

## 4. `status`

**When to use:** Before starting work — is capture enabled, what is attention, what is the last run?

```bash
blackbox status [--store <path>]
```

**Scenario:** An agent starts a session and checks what happened:

```bash
blackbox status --json
```

Returns `enabled`, `store_path`, `last_run`, `attention.level`, `project_memory`, `next_commands`.

---

## 5. `handoff`

**When to use:** Session start for agents/humans — status + project memory + resume pack when attention warrants.

```bash
blackbox handoff [--always] [--store <path>]
```

| Arg | Description |
|---|---|
| `--always` | Always attach resume pack (not just when attention needed) |

```bash
blackbox handoff --json
```

Returns `status` + `project_memory` (full `blackbox.memory/v1`) + `resume_pack` (on attention).

---

## 6. `memory show` / `memory set`

**When to use:** Read or update project goal/open items without a full handoff.

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

**When to use:** Multi-agent coordination so two holders do not clobber the same tree.

```bash
blackbox claim acquire [--holder <name>] [--ttl-secs <seconds>] [--goal <text>] [--path <scope>]
blackbox claim release [--holder <name>]
blackbox claim status
blackbox claim heartbeat [--holder <name>] [--ttl-secs <seconds>]
```

| Subcommand | Description |
|---|---|
| `acquire` | Acquire exclusive project claim, or a path-scoped claim with `--path`. Fails on scope conflict |
| `release` | Release claims for holder (or all if no holder) |
| `status` | Show project claim + path claims |
| `heartbeat` | Extend TTL for holder's active claims |

**Path scopes:** Omit `--path` for whole-project exclusive. With `--path src/auth`, other agents may claim non-overlapping scopes (e.g. `src/ui`). Prefix overlap conflicts (`src` vs `src/auth`). A project claim blocks all path claims, and foreign path claims block taking a project claim.

**Scenario:** Agent takes project hold:

```bash
blackbox claim acquire --holder "claude-code"
```

**Scenario:** Two agents on non-overlapping trees:

```bash
blackbox claim acquire --holder agent-a --path src/auth
blackbox claim acquire --holder agent-b --path src/ui
blackbox claim status
```

---

## 8. `resolve`

**When to use:** After you actually handled a sticky failure — clear attention (optionally WIP goal/open items).

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

**When to use:** Project `gate_mode=require_ack` and an explicit `blackbox run` is blocked until acknowledgment.

```bash
blackbox ack
# equivalent for one command:
BLACKBOX_ACK=1 blackbox run -- …
```

Does not apply to ambient `maybe-run` (ambient never hard-blocks on gate).

---

## 10. `runs`

**When to use:** Find a run id after a session, or filter failures for CI triage.

```bash
blackbox runs [--limit <N>] [--status succeeded|failed|cancelled]
              [--tag <tag>] [--json] [--store <path>]
```

```bash
blackbox runs --limit 5 --status failed --json
```

---

## 11. `show`

**When to use:** Inspect one run’s metadata and (optionally) transcript, tools, or TUI.

```bash
blackbox show <run-id> [--json] [--tui] [--transcript] [--tools] [--store <path>]
```

| Arg | Description |
|---|---|
| `--tui` | Open interactive ratatui TUI viewer |
| `--transcript` | Print full terminal transcript |
| `--tools` | Print tool call timeline |

With `--tui`, the header shows status/adapter/duration/capture quality; content panels:

| Key | Panel |
|---|---|
| `t` | Timeline |
| `o` | Processes |
| `f` | Files |
| `e` | Failure story (evidence, anomalies) |
| `a` | Anomalies |
| `x` | Side effects |
| `c` | Capture quality |
| `p` | Postmortem |
| `h` | Handoff / resume |
| `r` | Replay preflight |
| `d` | Diff vs previous run |
| `Enter` / `g` | Jump to timeline at evidence/`seq=` |
| `/` | Toggle bookkeeping |
| `?` | Help |
| `q` | Quit |

**Scenario:** Inspect a failed run:

```bash
blackbox show abc12345 --json
```

---

## 12. `timeline`

**When to use:** Walk ordered events; filter to tools or errors after postmortem evidence points at a `seq`.

```bash
blackbox timeline <run-id> [--semantic] [--kind <kind>] [--source <source>]
                          [--json] [--store <path>]
```

| Arg | Description |
|---|---|
| `--semantic` | Hide bookkeeping observer noise (preferred default in UIs) |
| `--kind <kind>` | Filter by event kind (e.g. `tool.call`, `terminal.output`) |
| `--source <source>` | Filter by event source (e.g. `Tool`, `Terminal`, `Filesystem`) |

```bash
blackbox timeline latest --semantic
blackbox timeline abc12345 --kind tool.call --json
```

---

## 13. `inspect`

**When to use:** Expand one event (metadata + blob payload) after timeline or evidence names an event id.

```bash
blackbox inspect <event-id> [--json] [--store <path>]
```

```bash
blackbox inspect evt_xyz789 --json
```

---

## 14. `diff`

**When to use:** “It worked yesterday” — compare two runs’ semantic trajectories.

```bash
blackbox diff <run-a> <run-b> [--trajectory] [--json] [--store <path>]
```

| Arg | Description |
|---|---|
| `--trajectory` | Emphasize human-readable trajectory report (LCP / divergence) |

Prints shared semantic prefix, first divergence with seq labels, exclusive steps, files after divergence, and a next-step hint.

```bash
blackbox diff abc123 xyz789 --trajectory
blackbox diff latest <prev> --json
```

---

## 15. `analyze`

**When to use:** Persist or review derived analysis (errors, side-effects, correlations) without full postmortem narrative.

```bash
blackbox analyze <run-id> [--pass error|side-effect|correlation] [--json] [--store <path>]
```

| Arg | Description |
|---|---|
| `--pass <name>` | Run a specific pass only (repeatable). Default: all |

```bash
blackbox analyze abc12345 --pass error --json
```

For headline/evidence/anomalies prefer [`postmortem`](#31-postmortem).

---

## 16. `search`

**When to use:** Full-text find across stored events (FTS5) when you remember a string but not the run id.

```bash
blackbox search <query> [--limit <N>] [--json] [--store <path>]
```

```bash
blackbox search "timeout" --limit 10 --json
```

---

## 17. `watch`

**When to use:** Live-tail events for a run that is still recording (CLI alternative to dashboard live view).

```bash
blackbox watch <run-id> [--store <path>]
```

```bash
blackbox watch abc12345
```

---

## 18. `export`

**When to use:** Share or archive one run. Default is **redacted**. Guide: [export-and-sync](../guide/export-and-sync.md).

```bash
blackbox export <run-id> [--format jsonl|html|portable|portable-dir]
                         [-o <path>]
                         [--no-redact]
                         [--encrypt] [--passphrase <phrase>]
```

| Arg | Description |
|---|---|
| `--format` | `jsonl`, `html`, `portable`, or `portable-dir` |
| `-o` / `--output` | File path (or directory for `portable-dir`) |
| `--no-redact` | Export unredacted (**dangerous**) |
| `--encrypt` | Seal portable JSON with store key |
| `--passphrase` | Seal portable JSON with PBKDF2 (`BLACKBOX_EXPORT_PASSPHRASE`) |

```bash
blackbox export latest --format html -o report.html
blackbox export latest --format portable --passphrase '…' -o run.bbx.json
blackbox export latest --format portable-dir -o ./trace-dir
```

Sealed packs: `blackbox.export.sealed/v1`. Directory layout is not sealed via `--passphrase`.

---

## 19. `import`

**When to use:** Load a portable JSON, sealed pack, or portable directory into the current store.

```bash
blackbox import <file-or-dir> [--keep-ids] [--passphrase <phrase>]
```

```bash
blackbox import trace.json
blackbox import run.bbx.json --passphrase '…'
blackbox import ./trace-dir
```

---

## 19b. `backup` / `restore`

**When to use:** Cold vault of sticky state + optional SQLite/blobs (laptop theft, machine move). Not a substitute for live SQLCipher.

```bash
blackbox backup -o vault.bbx.json --passphrase '…' [--include-db] [--include-blobs]
blackbox restore vault.bbx.json --passphrase '…'
```

| Arg | Description |
|---|---|
| `--passphrase` | Seal/open with PBKDF2 (**recommended**) |
| `--store-key` | Seal with project store key instead |
| `--include-db` | Embed `blackbox.db` |
| `--include-blobs` | Embed content blobs (size-capped) |

`store.key` is never embedded in backups. See [security](../guide/security.md).

---

## 20. `sync push` / `sync pull`

**When to use:** Replicate runs to a directory, HTTP sync endpoint, or S3 (redacted by default).

```bash
blackbox sync push [--dir <path>] [--remote <url>] [--s3 <url>] [--no-redact]
blackbox sync pull [--dir <path>] [--remote <url>] [--s3 <url>] [--no-redact]
```

```bash
blackbox sync push --dir /mnt/backup/traces
blackbox sync pull --s3 s3://bucket/prefix/
```

---

## 21. `serve`

**When to use:** Local web UI + JSON/SSE API for browsing runs. Default bind `127.0.0.1:7788`.

```bash
blackbox serve [--bind <addr>] [--token <token>] [--store <path>] [--reindex]
```

| Arg | Description |
|---|---|
| `--bind <addr>` | Bind address (default `127.0.0.1:7788`) |
| `--token <token>` | Auth token (`BLACKBOX_SERVE_TOKEN`); **required** off-loopback |
| `--reindex` | Rebuild FTS before serving |

**Auth:** `Authorization: Bearer <token>` only (no query API auth).

| Path | Description |
|---|---|
| `GET /` | Dashboard home (SSE run list + anomaly badges) |
| `GET /runs/{id}` | Run detail |
| `GET /runs/{id}/live` | Live SSE timeline |
| `GET /api/status` | Project status |
| `GET /api/handoff` | Handoff JSON |
| `GET /api/runs` | Runs list |
| `GET /api/runs/{id}/anomalies` | Anomaly markers |

```bash
blackbox serve --token "$TOKEN"
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:7788/api/runs
```

---

## 22. `replay`

**When to use:** Revisit a run without trusting LLM re-execution. Modes differ in how much they re-execute tools.

```bash
blackbox replay <run-id> [--mock-tools | --workspace | --sandbox | --live] [--store <path>]
```

| Mode | Executes? | Notes |
|---|---|---|
| `timeline` | No | Playback |
| `mock` | No | Mock tool results |
| `workspace` (`--sandbox` alias) | Yes, temporary directory only | Not OS isolation; dangerous ops blocked by policy |
| `live` | Yes | **Dangerous** — real re-execution |

Not deterministic model replay.

```bash
blackbox replay latest --mode timeline
```

---

## 23. `fork`

**When to use:** Start a new run from recorded context; optionally launch native harness resume when a session is known.

```bash
blackbox fork <run-id> [--launch] [--name <label>] [--store <path>]
```

```bash
blackbox fork abc12345
blackbox fork abc12345 --launch
```

---

## 24. `scrub`

**When to use:** Re-apply current secret patterns to historical events after scanner improvements or accidental raw capture.

```bash
blackbox scrub [--gc] [--store <path>]
```

```bash
blackbox scrub --gc
```

---

## 25. `doctor`

**When to use:** First diagnostic for path, schema, permissions, encryption tips, daily-driver score, orphan runs.

```bash
blackbox doctor [--reindex] [--json] [--store <path>]
```

```bash
blackbox doctor
blackbox doctor --json
```

---

## 26. `rm`

**When to use:** Delete specific runs by id. Orphaned blobs may remain until GC.

```bash
blackbox rm <run-id>... [--store <path>]
```

```bash
blackbox rm abc12345 def67890
blackbox scrub --gc    # reclaim blobs
```

---

## 27. `purge`

**When to use:** Bulk delete by policy (keep N, age, status). Prefer `--dry-run` first.

```bash
blackbox purge [--keep <N>] [--status <s>] [--older-than <duration>]
               [--dry-run] [--store <path>]
```

| Arg | Description |
|---|---|
| `--keep <N>` | Keep N most recent runs |
| `--older-than <d>` | Delete older than duration (e.g. `30d`) |
| `--dry-run` | Simulate |

```bash
blackbox purge --keep 50 --dry-run
blackbox purge --keep 50
```

---

## 28. `tags` / `tag`

**When to use:** Label runs for filtering (`runs --tag`, CI `eval`/`ci` tags).

```bash
blackbox tags
blackbox tag <run-id> <tag>
blackbox tag --remove <run-id> <tag>
```

```bash
blackbox tag latest nightly
blackbox runs --tag nightly
```

---

## 29. `stats`

**When to use:** Aggregate store size and volume (pairs with [overhead](../guide/overhead.md)).

```bash
blackbox stats [--json] [--store <path>]
```

```bash
blackbox stats --json
```

---

## 30. `gc`

**When to use:** Apply retention from config (`[retention]`) without hand-picking ids. Alias-style policy path for `purge`.

```bash
blackbox gc [--dry-run] [--store <path>]
```

```bash
blackbox gc --dry-run
blackbox gc
```

---

## 31. `postmortem`

**When to use:** One-shot failure/success story: headline, next_action, evidence, anomalies. Primary debug command after a bad run.

```bash
blackbox postmortem <run-id> [--fail-on-failure] [--json] [--store <path>]
```

| Arg | Description |
|---|---|
| `--fail-on-failure` | Exit 1 if run failed/cancelled (CI) |

```bash
blackbox postmortem latest
blackbox postmortem latest --json --fail-on-failure
```

Guide: [debug-a-failure](../guide/debug-a-failure.md).

---

## 32. `summary`

**When to use:** Alias for [`postmortem`](#31-postmortem) (same summary builder).

```bash
blackbox summary <run-id> [--json] [--store <path>]
```

---

## 33. `context`

**When to use:** Bounded resume pack for **one run** (token-capped). Prefer `handoff` for project-level session start.

```bash
blackbox context <run-id> [--for-resume] [--max-tokens <N>] [--json] [--store <path>]
```

| Arg | Description |
|---|---|
| `--for-resume` | Resume-optimized packing |
| `--max-tokens <N>` | Budget (default 4000) |

```bash
blackbox context latest --for-resume --json --max-tokens 4000
```

---

## 34. `mcp`

**When to use:** Expose status/handoff/memory/search tools to MCP clients over stdio. Tool list: [mcp.md](mcp.md).

```bash
blackbox mcp [--store <path>]
```

JSON-RPC 2.0 on stdin/stdout. Agents: [skills/blackbox.md](../skills/blackbox.md).

---

## 35. `completions`

**When to use:** Install shell completions for interactive CLI use.

```bash
blackbox completions <shell>
```

Supported: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

```bash
blackbox completions bash > ~/.local/share/bash-completion/completions/blackbox
```

---

## 36. `fsck`

**When to use:** Store integrity after crashes, import issues, or suspected blob loss.

```bash
blackbox fsck [--deep] [--repair] [--json]
```

| Flag | Description |
|---|---|
| `--deep` | Load and re-hash referenced blobs; offer FTS rebuild |
| `--repair` | Apply auto-safe repairs (aggregates, stale Running, FTS rebuild, orphan GC) |

Guide: [fsck-and-integrity](../guide/fsck-and-integrity.md).

---

## 37. `verify`

**When to use:** Attach an immutable verification receipt (separate from `Run.status`).

```bash
blackbox verify <run-id|latest> [--scope <label>] [--parent <receipt-id>] \
  [--junit <path>] [--tap <path>] [--assert-file <path>] [--assert-git-clean] \
  [-- <command>…]
```

Exactly one verifier path: trailing `-- command…`, or `--junit` / `--tap` /
`--assert-file` / `--assert-git-clean`.

Guide: [verification](../guide/verification.md).

---

## 38. `experiment`

```bash
blackbox experiment init <name> [--id <id>]
blackbox experiment show <id>
blackbox experiment list
blackbox experiment validate <id>
blackbox experiment link <experiment> <run-id> [--task …] [--variant …] [--attempt N] [--role …] [--model …]
```

Guide: [experiments](../guide/experiments.md).

---

## 39. `report`

```bash
blackbox report --experiment <id> [--group-by variant] [--min-samples N] [--json]
```

---

## 40. `gate`

```bash
blackbox gate --experiment <id> \
  [--baseline <key>] [--candidate <key>] \
  [--min-attempts N] [--min-verified-rate R] \
  [--max-p95-duration-regression PCT] \
  [--require-capture-complete] [--group-by variant]
```

Non-zero exit when any rule fails. Verified-rate rules prefer domain-confirmed
receipts (execution success alone never passes).

---

## 41. `capsule`

```bash
blackbox capsule create <run-id> [-o path]
blackbox capsule inspect <path>
blackbox capsule verify <path>
blackbox capsule execute <path> [--contained] [--rerun]
```

Guide: [capsules-and-cassettes](../guide/capsules-and-cassettes.md).

---

## 42. `cassette` (experimental)

```bash
blackbox cassette inspect <path>
blackbox cassette match <path> <request.json> [--mode normalized] [--tool tools/call]
blackbox cassette proxy --record <path> [--redact] -- <mcp-server>…
blackbox cassette proxy --replay <path> [--mode …] [--on-unknown fail|deny|live] -- <mcp-server>…
```

MCP stdio only; does not intercept harness-internal tools.

---

## 43. `budget`

```bash
blackbox budget [--max-wall N] [--max-processes N] [--max-output N] \
  [--max-tool-calls N] [--max-tokens N] [--max-memory N] [--max-cpu-percent N] \
  [--contained] [--observed-wall N] [--observed-processes N] [--json]
```

Prints capability classification for configured limits (no process supervision).

---

## 44. `adapter`

```bash
blackbox adapter validate <manifest.toml|json>
blackbox adapter test <manifest> [--fixtures events.ndjson]
```

Live process conformance runs the manifest `command` and validates NDJSON stdout
when fixtures alone are not enough.

---

## 45. `projects`

```bash
blackbox projects scan [roots…]
blackbox projects list [--query substr] [--limit N]
blackbox projects prune
blackbox projects remove <project-root>
```

Metadata-only index at `~/.blackbox/projects-index.json`.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error / run failed (`--ci` / `--eval` / `--fail-on-failure` / gate fail) |
