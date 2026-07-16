# Configuration

Blackbox can be configured through CLI flags, environment variables, and a project-level TOML config file. This document covers all configuration surfaces.

---

## 1. Store paths

Paths are resolved in priority order:

| Priority | Source | Example |
|---|---|---|
| 1 | CLI `--store` | `blackbox run --store /custom/path/db.sqlite` |
| 2 | `BLACKBOX_DB` env | `export BLACKBOX_DB=/custom/path/db.sqlite` |
| 3 | Legacy `./blackbox.db` | If that file already exists in the project root |
| 4 | Default `.blackbox/` | `.blackbox/blackbox.db` + `.blackbox/blobs/` |

### Gitignore

Add to your project `.gitignore`:

```
.blackbox/
blackbox.db
*.db-wal
*.db-shm
```

---

## 2. Config file (`.blackbox/config.toml`)

Blackbox reads configuration from `.blackbox/config.toml` when present. A default is created on `blackbox enable`.

### Full schema

```toml
# ── Capture settings ──

[capture]
# Which agent harnesses to wrap (space-separated basenames).
# Default: claude codex aider cursor cursor-agent gemini opencode grok
wrap = ["claude", "codex", "aider", "cursor", "cursor-agent", "gemini", "opencode", "grok"]

# Continuity mode: "always" | "attention" | "off"
# New projects default "always"; migrated 1.1 projects default "attention"
continuity = "always"

# Hard observe-only / recorder mode (daily-driver trust).
# When true: no prompt mutation, no MEMORY/RESUME inject, no adapter
# prepare_launch flags, no auto parent-run linking. Continuity is forced off.
# Prefer: blackbox enable --observe-only
# observe_only = false

# Process-tree enrichment (optional; safe defaults)
# denser adaptive poll (25–100ms vs 50–200ms)
# process_dense_poll = false
# sample redacted /proc/<pid>/environ into process events (opt-in)
# process_environ = false
# Linux child subreaper for best-effort descendant exit codes (default true)
# process_subreaper = true

# Environment capture: "allowlist" (default — PATH/HOME/CI/BLACKBOX_* only)
# or "full" (all vars after name+value redaction)
# env_capture = "allowlist"
# Store full git diffs as blobs (default true). false = preview+stats only.
# store_git_diffs = true
# Native log roots: "project" (default), "home" (also ~/.claude etc.), "off"
# native_log_scope = "project"
# Encrypt blobs at rest (ChaCha20-Poly1305); key in .blackbox/store.key
# Also seals state.json + MEMORY.json when the key is present.
# encrypt_blobs = false

# Auto-resume (legacy 1.0 compat): true | false
# When continuity ≠ off, this is overridden by continuity mode
auto_resume = true

# ── Retention settings ──

[retention]
# Apply retention automatically after each run
auto_apply = true

# Keep at most N most recent runs (0 = keep all)
keep_runs = 100

# ── Claim settings ──

[claim]
# Auto-acquire claim on run start (default false)
auto_claim = false

# Gate mode: "off" | "warn" | "require_ack"
gate_mode = "off"

# Claim policy on conflict: "warn" | "block_record"
policy = "warn"
```

---

## 2b. Product modes: recorder vs continuity

Blackbox exposes a simple **product mode** (`capture.product_mode()` derived from
flags):

| Product mode | Meaning |
|---|---|
| **recorder** | Hard observe-only; ambient wrap never mutates launches (default) |
| **continuity** | Memory bus may inject on **explicit** `blackbox run` only |

Ambient shell wrap is **always** recorder semantics.

Blackbox can run as a **neutral recorder** or as a **continuity / memory bus**.
Do not conflate them.

| Mode | How to enable | Mutates launch? | Injects MEMORY/RESUME? | Use when |
|---|---|---|---|---|
| **Observe-only** (recorder) | **New-project default**; `blackbox enable --observe-only`; ambient shell wrap always | No | No | Leave ambient on forever; evaluate harness/model behavior |
| **Continuity always** | `blackbox enable --continuity always` or `--memory-bus` | May prepare adapter launch / inject env | Yes (when configured) | Multi-day agent work with project memory (explicit opt-in) |
| **Continuity attention** | `continuity = "attention"` | Only when sticky attention needs it | When attention is set | Less aggressive memory inject |
| **Continuity off** | `continuity = "off"` | No continuity inject | No | Recording without memory plane |

**Ambient shell wrap (`maybe-run`) is always observe-only** — continuity inject
never applies to wrapped `claude`/`codex`/… launches. Use explicit
`blackbox run -- <cmd>` (without observe-only, with continuity configured) when
you want the memory bus.

CLI override: `blackbox run --observe-only -- <cmd>` forces recorder semantics for
that run even if project continuity is enabled.

Replay modes are separate again (see `blackbox replay --help`):

| Mode | Command | Executes? |
|---|---|---|
| Timeline playback | `blackbox replay <run>` | No |
| Recorded tool playback | `blackbox replay --mock-tools` | No (mocks) |
| Sandbox re-execution | `blackbox replay --sandbox` | Yes, isolated; lossy/shell blocked |
| Live re-execution | `blackbox replay --live` | Yes, dangerous |
| Forked continuation | `blackbox fork <run> --launch` | Native harness resume when session known |

None of these are deterministic LLM replay.

---

## 3. Environment variables

### Store and paths

| Variable | Purpose | Example |
|---|---|---|
| `BLACKBOX_DB` | Override store path | `/tmp/blackbox.db` |
| `BLACKBOX_SERVE_TOKEN` | Auth token for HTTP serve | `my-secret-token` |

### Continuity and inject

| Variable | Purpose | Example |
|---|---|---|
| `BLACKBOX_CONTINUITY` | Continuity mode override | `always` \| `attention` \| `off` |
| `BLACKBOX_AUTO_RESUME` | Legacy auto-resume (1.0) | `1` \| `0` |
| `BLACKBOX_MEMORY_FILE` | Path to MEMORY.md (set by blackbox) | — |
| `BLACKBOX_MEMORY_SCHEMA` | Memory schema version (set by blackbox) | `blackbox.memory/v1` |
| `BLACKBOX_RESUME_FILE` | Path to RESUME.md (set by blackbox) | — |
| `BLACKBOX_RESUME_RUN_ID` | Focus run ID (set by blackbox) | — |
| `BLACKBOX_RESUME_HINT` | Context hint (set by blackbox) | — |

### Process capture enrichment

| Variable | Purpose | Example |
|---|---|---|
| `BLACKBOX_PROCESS_DENSE_POLL` | Tighter process poll (25–100 ms) | `1` \| `0` |
| `BLACKBOX_PROCESS_ENVIRON` | Sample redacted `/proc` environ into process events | `1` \| `0` |
| `BLACKBOX_PROCESS_SUBREAPER` | Linux child subreaper for waitpid exit codes | `1` \| `0` (default on) |
| `BLACKBOX_ENCRYPT_BLOBS` | Enable at-rest blob encryption | `1` \| `0` |
| `BLACKBOX_STORE_KEY` | 64-hex store encryption key | — |
| `BLACKBOX_STORE_KEY_FILE` | Path to key file **outside** project (recommended) | `~/.config/blackbox/default.key` |
| `BLACKBOX_EXPORT_PASSPHRASE` | Passphrase for sealed export/backup | — |

### Ambient capture

| Variable | Purpose | Example |
|---|---|---|
| `BLACKBOX_OFF` | Disable all ambient capture | `1` |
| `BLACKBOX_ACTIVE_RUN` | Set when inside a supervised run (nest protection) | — |
| `BLACKBOX_ACK` | Acknowledge gate mode | `1` |

### Pricing

| Variable | Purpose | Example |
|---|---|---|
| `BLACKBOX_ESTIMATE_COST` | Enable cost estimation | `1` |
| `BLACKBOX_PRICING` | Override pricing file path | `/path/to/pricing.toml` |

### Debug

| Variable | Purpose | Example |
|---|---|---|
| `RUST_LOG` | Tracing/logging level | `debug` |
| `RUST_BACKTRACE` | Full panic backtrace | `1` |

---

## 4. Pricing config (optional)

When `BLACKBOX_ESTIMATE_COST=1`, blackbox fills `estimated_cost_usd` on runs. Built-in model rates are used by default. Custom rates can be set in `.blackbox/pricing.toml`:

```toml
[models."my-custom-model"]
input_per_mtok = 1.0
output_per_mtok = 2.0
```

Or via `BLACKBOX_PRICING=/path/to/pricing.toml`.

> Pricing is **opt-in only** — blackbox never invents a price when disabled or the model is unknown.

---

## 5. CLI flags reference

See the [CLI reference](../reference/cli.md) for a complete list of all subcommands and their arguments.

Key flags that appear on multiple subcommands:

| Flag | Applies to | Purpose |
|---|---|---|
| `--json` | All commands | Machine-readable JSON envelope output |
| `--store` | All commands | Override store database path |
| `--no-redact` | capture, export, sync | Disable redaction (dangerous) |
| `--insecure-raw` | `run` | Store raw PTY bytes (dangerous) |
| `--no-auto-resume` | `run` | Skip auto-resume injection |
| `--ci` | `run` | Propagate child exit code |
| `--eval` | `run` | Eval harness: observe-only + CI + tags `eval`/`ci` |
| `--observe-only` | `run` | No launch mutation / continuity inject |
| `--artifact-dir` | `run` | Write run/postmortem/anomalies/summary artifacts |
| `--tui` | `show` | Interactive TUI viewer |

---

## 6. Shell wrappers

Generated by `blackbox enable --install-shell`:

- **bash/zsh**: Managed blocks in `~/.bashrc` / `~/.zshrc`
- **PowerShell**: Managed blocks in PowerShell profile
- Idempotent: running `--install-shell` multiple times creates only one block
- Safe: if `blackbox` binary is missing, the bare command runs (never hard-fail)
- Escape: `BLACKBOX_OFF=1` before the harness command skips recording

Remove with:

```bash
blackbox enable --uninstall-shell
```
