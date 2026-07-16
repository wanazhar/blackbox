# Configuration

**Answers:** Store path resolution, override precedence (CLI → env → config), product modes (recorder vs continuity), every important `config.toml` key, environment variables, and which CLI flags cross-cut commands.

Related: [getting-started.md](getting-started.md), [leave-it-on.md](leave-it-on.md), [security.md](security.md). Exhaustive per-command flags: [../reference/cli.md](../reference/cli.md).

---

## Quick answers

| Question | Short answer |
|---|---|
| Where is my data? | `.blackbox/blackbox.db` + `.blackbox/blobs/` unless overridden |
| How do I force a store? | `--store PATH` or `BLACKBOX_DB` |
| Why isn’t continuity injecting? | Ambient is always observe-only; use explicit `blackbox run` and check `observe_only` / continuity |
| How do I stop ambient for one shell? | `export BLACKBOX_OFF=1` |
| How do I encrypt blobs? | `capture.encrypt_blobs = true` or `BLACKBOX_ENCRYPT_BLOBS=1` |
| How do I cap disk? | `[retention] keep_runs = N` + `auto_apply = true` |

---

## 1. Store paths

Resolved in this order (first hit wins):

| Priority | Source | Notes |
|---|---|---|
| 1 | CLI `--store <path>` | Usually path to the SQLite file |
| 2 | `BLACKBOX_DB` | Same |
| 3 | Legacy `./blackbox.db` | **Only if that file already exists** in the project root |
| 4 | Default | `.blackbox/blackbox.db` + `.blackbox/blobs/` under the discovered project |

**Project discovery:** walk ancestors from cwd for an enabled `.blackbox/` (config present / enabled). Explicit `--project` / run `--project` can pin the project root when relevant.

### Layout

```text
.blackbox/
  config.toml
  blackbox.db          # SQLite (events, runs, FTS, …)
  blackbox.db-wal      # WAL (gitignored)
  blackbox.db-shm
  blobs/               # content-addressed payloads
  state.json           # sticky: attention, claims, intent (may be sealed)
  MEMORY.md            # human-readable pack
  MEMORY.json          # structured pack (may be sealed)
  store.key            # optional; prefer external key path
```

### Gitignore

```gitignore
.blackbox/
blackbox.db
*.db-wal
*.db-shm
```

---

## 2. Override precedence

### Continuity (inject policy)

Effective continuity for an invocation:

1. CLI (`--continuity`, `--observe-only`, `--eval`, `--no-auto-resume` / `--auto-resume` as applicable)
2. `BLACKBOX_CONTINUITY`
3. `BLACKBOX_AUTO_RESUME` (legacy: `0` → off; `1` → attention when continuity env absent)
4. `config.toml` → `capture.continuity` / `observe_only` / `auto_resume` derivation
5. Built-in default for new configs (see schema defaults below)

**Hard rules that always win conceptually:**

| Rule | Effect |
|---|---|
| `observe_only = true` (config or `--observe-only` / `--eval` / ambient) | Continuity inject off for that path |
| Ambient `maybe-run` | Always observe-only (no MEMORY/env inject) |
| Explicit `blackbox run` | May inject when continuity allows and observe-only is false |

### Capture policy (redaction, store)

| Surface | Typical precedence |
|---|---|
| Redaction on | Default on; `--no-redact` / `--insecure-raw` opt-in danger |
| Blob encryption | `BLACKBOX_ENCRYPT_BLOBS` / config `encrypt_blobs` + key env/files |
| Process enrichment | Config + `BLACKBOX_PROCESS_*` env |

When in doubt: `blackbox doctor` and `blackbox status --json` show effective project settings.

---

## 3. Product modes: recorder vs continuity

Do not conflate **recording** with **memory inject**.

| Product mode | Meaning |
|---|---|
| **recorder** | Hard observe-only: no prompt mutation, no MEMORY/RESUME inject, no adapter `prepare_launch` rewrites |
| **continuity** | Memory plane may inject on **explicit** `blackbox run` only |

Derived roughly from `observe_only` + effective continuity (`capture.product_mode()` in code).

| Mode | How you get it | Mutates launch? | Injects memory? | Use when |
|---|---|---|---|---|
| Observe-only / recorder | Default for ambient; `enable --observe-only`; `run --observe-only`; `--eval` | No | No | Leave ambient on; eval harnesses |
| Continuity always | `enable --memory-bus` / `--continuity always` | May prepare launch / inject env | Yes (when not observe-only) | Multi-session agent work |
| Continuity attention | `continuity = "attention"` | Only when sticky attention needs it | Conditional | Less aggressive inject |
| Continuity off | `continuity = "off"` or observe-only | No continuity inject | No | Pure recorder |

CLI: `blackbox run --observe-only -- <cmd>` forces recorder for that run even if the project is continuity-oriented.

### Replay is a third axis

| Mode | Executes child? | Notes |
|---|---|---|
| Timeline | No | Playback of recorded events |
| Mock tools | No (mocks) | Tool replay without real side effects |
| Sandbox | Yes, isolated | Lossy; some shell ops blocked |
| Live / fork launch | Yes | Dangerous / native resume when session known |

None of these are bit-identical LLM re-execution. See `blackbox replay --help` and [CLI reference](../reference/cli.md).

---

## 4. Config file (`.blackbox/config.toml`)

Created by `blackbox enable`. Missing keys use Rust/serde defaults (not necessarily every field written out).

### Annotated schema

```toml
# Top-level
enabled = true

[capture]
# Basenames for ambient maybe-run wrap (not full paths).
wrap = ["claude", "codex", "aider", "cursor", "cursor-agent", "gemini", "opencode", "grok"]

# Continuity: "always" | "attention" | "off"
# enable --memory-bus sets always; stock Default often observe_only=true + continuity off
# continuity = "always"

# Hard observe-only: forces continuity off, skips launch mutation / BLACKBOX_* inject
# observe_only = true

# Legacy: when continuity key absent, true→attention, false→off
auto_resume = true
# resume_max_tokens = 4000
# memory_max_tokens = 4000   # optional override for pack budget

# Explicit run only: "off" | "warn" | "require_ack"
gate_mode = "off"
auto_claim = false
claim_ttl_secs = 1800
# claim_policy = "warn"   # or "block_record"

# Process tree
# process_dense_poll = false   # 25–100ms vs 50–200ms
# process_environ = false      # redacted /proc environ (opt-in)
# process_subreaper = true     # Linux PR_SET_CHILD_SUBREAPER

# env_capture = "allowlist"    # or "full" (all vars after name+value redaction)
# store_git_diffs = true       # false = preview+stats only
# native_log_scope = "project" # "project" | "home" | "off"
# encrypt_blobs = false

[retention]
auto_apply = true
keep_runs = 100              # 0 = keep all (subject to other tools)
```

### Field reference (capture)

| Key | Default (typical) | Effect |
|---|---|---|
| `wrap` | common harness basenames | Ambient recording candidates |
| `continuity` | often `off` unless `--memory-bus` | Inject policy for explicit run |
| `observe_only` | **true** on default `CaptureConfig` | Recorder semantics |
| `auto_resume` | true | Legacy continuity derivation when `continuity` absent |
| `resume_max_tokens` / `memory_max_tokens` | ~4k | Pack budget |
| `gate_mode` | off | `warn` / `require_ack` on **explicit** run only |
| `auto_claim` | false | Acquire claim on run (`--ci`/`--eval` may force for invocation) |
| `claim_ttl_secs` | 1800 | Claim lifetime |
| `claim_policy` | warn | Conflict: warn vs block_record |
| `process_dense_poll` | false | Tighter process sampling |
| `process_environ` | false | Redacted environ sampling |
| `process_subreaper` | true | Linux descendant exit codes |
| `env_capture` | allowlist | PATH/HOME/CI/BLACKBOX_* vs full redacted env |
| `store_git_diffs` | true | Full diff blobs vs preview only |
| `native_log_scope` | project | Do not ingest `~/.claude` unless `home` |
| `encrypt_blobs` | false | ChaCha20-Poly1305 blobs + seal sticky JSON |

### Retention

| Key | Effect |
|---|---|
| `auto_apply` | Apply keep policy after runs |
| `keep_runs` | Max recent runs retained (0 = unlimited via this knob) |

Manual: `blackbox purge`, `blackbox rm`, `blackbox scrub --gc`, `blackbox gc`.

---

## 5. Environment variables

### Store, serve, crypto

| Variable | Purpose |
|---|---|
| `BLACKBOX_DB` | Store SQLite path override |
| `BLACKBOX_SERVE_TOKEN` | Dashboard/API Bearer token |
| `BLACKBOX_ENCRYPT_BLOBS` | `1`/`0` enable blob encryption |
| `BLACKBOX_STORE_KEY` | 64-hex key material |
| `BLACKBOX_STORE_KEY_FILE` | Key file path (prefer outside project) |
| `BLACKBOX_EXPORT_PASSPHRASE` | Sealed export / backup passphrase |

### Continuity and inject (set by you or by blackbox)

| Variable | Purpose |
|---|---|
| `BLACKBOX_CONTINUITY` | `always` \| `attention` \| `off` |
| `BLACKBOX_AUTO_RESUME` | Legacy on/off → continuity derivation |
| `BLACKBOX_MEMORY_FILE` | Path to MEMORY.md (**set by blackbox** on inject) |
| `BLACKBOX_MEMORY_SCHEMA` | e.g. `blackbox.memory/v1` (**set by blackbox**) |
| `BLACKBOX_RESUME_FILE` / `BLACKBOX_RESUME_RUN_ID` / `BLACKBOX_RESUME_HINT` | Resume inject (**set by blackbox**) |

### Ambient and gates

| Variable | Purpose |
|---|---|
| `BLACKBOX_OFF` | Disable ambient capture for this environment |
| `BLACKBOX_ACTIVE_RUN` | Set while inside supervised run (nest → passthrough) |
| `BLACKBOX_ACK` | Satisfy `require_ack` gate |

### Process capture

| Variable | Purpose |
|---|---|
| `BLACKBOX_PROCESS_DENSE_POLL` | Tighter poll |
| `BLACKBOX_PROCESS_ENVIRON` | Sample redacted environ |
| `BLACKBOX_PROCESS_SUBREAPER` | Linux subreaper on/off |

### Pricing (opt-in)

| Variable | Purpose |
|---|---|
| `BLACKBOX_ESTIMATE_COST` | Enable `estimated_cost_usd` filling |
| `BLACKBOX_PRICING` | Path to custom `pricing.toml` |

### Debug

| Variable | Purpose |
|---|---|
| `RUST_LOG` | tracing filter (e.g. `blackbox=debug`) |
| `RUST_BACKTRACE` | panic backtraces |

---

## 6. Pricing config (optional)

Only when `BLACKBOX_ESTIMATE_COST=1`. Built-in model rates apply; unknown models do not invent prices.

`.blackbox/pricing.toml` (or `BLACKBOX_PRICING`):

```toml
[models."my-custom-model"]
input_per_mtok = 1.0
output_per_mtok = 2.0
```

---

## 7. Cross-cutting CLI flags

| Flag | Where | Purpose |
|---|---|---|
| `--json` | global | `blackbox.cli/v1` envelope |
| `--store` | global | Store path |
| `--no-redact` | capture/export/sync | Disable redaction (**dangerous**) |
| `--insecure-raw` | `run` | Raw PTY blobs (**dangerous**) |
| `--observe-only` | `run` | Recorder semantics |
| `--ci` | `run` | Propagate exit code; CI-friendly claim behavior |
| `--eval` | `run` | observe-only + CI + tags `eval`/`ci` |
| `--artifact-dir` | `run` | `run.json`, `postmortem.json`, `anomalies.json`, `summary.txt`, … |
| `--no-auto-resume` / `--auto-resume` | `run` | Continuity inject override |
| `--tui` | `show` | Interactive viewer |

Full list: [../reference/cli.md](../reference/cli.md).

---

## 8. Shell wrappers

```bash
blackbox enable --install-shell
blackbox enable --uninstall-shell
```

- Managed markers: `# >>> blackbox >>>` … `# <<< blackbox <<<`
- bash/zsh rc or PowerShell profile
- Idempotent single block; missing binary → bare command (never hard-fail)
- Escape: `BLACKBOX_OFF=1`

Operator depth: [leave-it-on.md](leave-it-on.md). Normative table: [../ambient-contract.md](../ambient-contract.md).

---

## 9. Verify effective config

```bash
blackbox doctor
blackbox status --json
blackbox doctor --json
```

Look for: store path, product mode / continuity, encrypt_blobs, native_log_scope, retention, orphan Running runs, permission warnings.
