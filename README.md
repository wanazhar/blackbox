# blackbox

**Flight recorder for AI-agent runs.** Launch any command under PTY supervision, capture terminal + git + filesystem events into SQLite, inspect timelines, export safe traces.

## Quality bar

- **Secrets never at rest by default** — argv, env, and terminal output are redacted before write. Use `--insecure-raw` only when you deliberately want raw bytes.
- **True timelines** — one event writer owns monotonic sequence numbers.
- **Payloads as blobs** — terminal content lives in content-addressed files; metadata holds previews only.
- **Project-local store** — `.blackbox/blackbox.db` + `.blackbox/blobs/` (override with `--store` / `BLACKBOX_DB`).
- **Safe export default** — `export` redacts unless you pass `--no-redact`.

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full attack plan.

## Install / build

```bash
cargo build --release
./target/release/blackbox --help
```

## Quick start

```bash
# Record a command
blackbox run -- echo "hello"

# List runs
blackbox runs

# Text summary + tool/error overview
blackbox show latest

# Semantic timeline (hide bookkeeping noise)
blackbox timeline latest --semantic

# Inspect an event (by id, sequence, or "latest")
blackbox inspect latest latest
blackbox inspect latest 3

# Analysis passes
blackbox analyze latest

# Re-redact historical traces that still hold secrets
blackbox scrub --dry-run
blackbox scrub
blackbox scrub --gc          # also delete orphaned blob files

# Fork + resume harness under observation
blackbox fork latest --launch

# Export (redacted by default)
blackbox export latest > trace.jsonl
blackbox export latest --no-redact   # dangerous

# Interactive TUI
blackbox show latest --tui
```

### Record an agent

```bash
blackbox run --name "fix" -- claude -p "fix the login bug"
# or
blackbox run -- codex ...
```

If the harness prints stream-json / NDJSON tool calls, blackbox parses them into `tool.call` events.

## Storage layout

```
.project/
  .blackbox/
    blackbox.db      # runs, events, checkpoints
    blobs/           # sha256 content-addressed payloads
```

Legacy: if `./blackbox.db` already exists, it is used (migration path).

## Security

| Mode | Behavior |
|---|---|
| default | Redact secrets in terminal/env/argv before persist |
| `--insecure-raw` | Also store raw PTY bytes as blobs |
| `--no-redact` | Disable all redaction (do not use with secrets) |

Export is **redacted by default**. Pass `--no-redact` only for private offline analysis.

## Commands

| Command | Purpose |
|---|---|
| `run` | Supervise a command, capture events |
| `runs` | List runs |
| `show` | Text summary (or `--tui`) |
| `timeline` | Event list (`--semantic` filters noise) |
| `inspect` | Event detail + blob content |
| `diff` | Compare two runs (status, tools, kinds) |
| `analyze` | Error / side-effect / correlation passes |
| `scrub` | Re-redact secrets already stored at rest |
| `doctor` | Diagnose store path, blob dir, secret residue |
| `export` | JSONL / HTML / portable |
| `replay` | Timeline, mock tools, sandbox (seeded workspace) |
| `fork` | Branch a new run record from a checkpoint |

### Agent capture tips

```bash
# Claude print mode → blackbox injects --output-format stream-json --verbose
blackbox run -- claude -p "fix the login bug"

# Force machine JSON even for interactive launches
BLACKBOX_FORCE_JSON=1 blackbox run -- claude

# Codex exec → injects --json
blackbox run -- codex exec "..."
```

## Development

```bash
cargo test
cargo clippy
cargo fmt
```

## Status

Working recorder with P0 trust fixes. Replay/sandbox and full harness fidelity are still maturing — see the roadmap.
