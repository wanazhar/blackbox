# blackbox

**Flight recorder for AI-agent runs.** Supervise any command under a PTY, capture terminal output plus git/filesystem/process context into SQLite, then inspect, search, export, and sync traces — with secrets redacted by default.

| | |
|---|---|
| **CLI / lib name** | `blackbox` |
| **crates.io package** | [`blackbox-recorder`](https://crates.io/crates/blackbox-recorder) |
| **License** | MIT OR Apache-2.0 |
| **Status** | **0.4.0** — daily driver: enable → auto-capture → fail → `handoff` / resume pack → next agent |

## Why use it

- **Secrets stay out of the store** — argv, env, and terminal output are redacted before write. Opt into raw capture only with `--insecure-raw`.
- **Honest timelines** — a single `EventWriter` owns monotonic sequence numbers.
- **Payloads as blobs** — large content lives under content-addressed files; events keep short previews.
- **Project-local store** — `.blackbox/blackbox.db` + `.blackbox/blobs/` (override with `--store` / `BLACKBOX_DB`).
- **Safe share defaults** — `export` and `sync push` redact unless you pass `--no-redact`.

## Install

```bash
# From crates.io (after publish)
cargo install blackbox-recorder

# From this repo
cargo install --path .
# or
cargo build --release
./target/release/blackbox --help
```

Requires a recent stable Rust toolchain. Linux and macOS are the primary targets.

```bash
blackbox doctor   # verify store path + health
```

## Quick start

```bash
# Record anything
blackbox run -- echo "hello"

# Record an agent (Claude / Codex get stream-json injection when safe)
blackbox run --name "fix-login" -- claude -p "fix the login bug"
blackbox run -- codex exec "..."

# Inspect
blackbox runs
blackbox show latest
blackbox timeline latest --semantic
blackbox inspect latest latest
blackbox analyze latest

# Search, live tail, TUI
blackbox search "bash ls"
blackbox watch latest
blackbox show latest --tui

# Export (redacted by default)
blackbox export latest > trace.jsonl
blackbox export latest --format html > report.html
blackbox export latest --format portable > run.json   # v2: includes blobs

# Import a portable archive
blackbox import run.json
```

## Workflows

### Share and multi-machine sync

```bash
# Shared folder (NFS / rsync / Dropbox)
blackbox sync push --dir /shared/bb-sync
blackbox sync pull --dir /shared/bb-sync

# HTTP: machine A runs `blackbox serve --token secret --bind 0.0.0.0:7788`
blackbox sync push --remote http://host-a:7788 --token secret
blackbox sync pull --remote http://host-a:7788 --token secret

# S3 (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION)
blackbox sync push --s3 s3://my-bucket/blackbox/
blackbox sync pull --s3 s3://my-bucket/blackbox/
```

### Local web dashboard

```bash
blackbox serve
# → http://127.0.0.1:7788
# → http://127.0.0.1:7788/watch          (latest run, live SSE)
# Optional: --token / BLACKBOX_SERVE_TOKEN
```

### Housekeeping

```bash
blackbox scrub --dry-run          # re-redact historical residue
blackbox scrub --gc               # scrub + drop orphan blobs
blackbox rm latest
blackbox purge --keep 20 --yes --gc
blackbox stats
blackbox tag latest --add important
blackbox runs --tag important --show-tags
```

### Agent capture tips

```bash
# Claude print mode → injects --output-format stream-json --verbose
blackbox run -- claude -p "fix the login bug"

# Force machine JSON for interactive launches
BLACKBOX_FORCE_JSON=1 blackbox run -- claude

# Codex exec → injects --json
blackbox run -- codex exec "..."

# Fork + re-launch harness under observation
blackbox fork latest --launch
```

### Daily-driver loop (leave it on)

```bash
# Once per project — writes config + agent instructions; installs shell wrappers
blackbox enable --install-shell

# Agents at session start (machine-readable; embeds resume pack on failure)
blackbox status --json
blackbox handoff --json

# After a failure — one-command postmortem / resume pack
blackbox postmortem latest --json
blackbox context latest --for-resume --json --max-tokens 4000

# Explicit capture still works
blackbox run --name "fix-login" -- claude -p "fix the login bug"

# Opt out for one shell session
export BLACKBOX_OFF=1

# Retention (auto_apply=true by default after enable; manual still available)
blackbox gc                  # dry-run
blackbox gc --apply --yes    # destructive

# Trajectory compare
blackbox diff runA runB --trajectory
```

### Shell completions

```bash
blackbox completions fish > ~/.config/fish/completions/blackbox.fish
blackbox completions bash > /etc/bash_completion.d/blackbox
blackbox completions zsh  > "${fpath[1]}/_blackbox"
```

## Storage layout

```
<project>/
  .blackbox/
    blackbox.db      # runs, events, checkpoints, FTS
    blobs/           # sha256 content-addressed payloads
    config.toml      # enabled, wrap list, retention
    state.json       # sticky last-run / attention (agent handoff)
    AGENT.md         # instructions for coding agents
```

| Priority | Path |
|---|---|
| 1 | `--store` / `BLACKBOX_DB` |
| 2 | Legacy `./blackbox.db` **if that file already exists** |
| 3 | Default: `.blackbox/blackbox.db` + `.blackbox/blobs/` |

> **Tip:** Prefer the default `.blackbox/` layout. A leftover `./blackbox.db` in the project root steals resolution (legacy migration). Delete it (or move it under `.blackbox/`) if you want the modern layout.

Add to your project `.gitignore`:

```
.blackbox/
blackbox.db
*.db-wal
*.db-shm
```

## Security

| Mode | Behavior |
|---|---|
| **default** | Redact secrets in terminal / env / argv before persist |
| `--insecure-raw` | Also store raw PTY bytes as blobs (dangerous) |
| `--no-redact` | Disable redaction on capture/export/sync (do not use with secrets) |

Export and sync push are **redacted by default**. Pass `--no-redact` only for private offline analysis.

`blackbox serve` binds to `127.0.0.1` by default. Use `--token` (or `BLACKBOX_SERVE_TOKEN`) before exposing it on a network interface.

## Commands

| Command | Purpose |
|---|---|
| `run` | Supervise a command; capture events |
| `maybe-run` | Project-gated ambient capture (shell wrappers) |
| `enable` / `disable` | Opt-in project capture; `--install-shell` manages rc wrappers |
| `status` | Project status: enabled, last run, attention, next commands |
| `handoff` | Agent handoff: status + resume pack when attention is needed |
| `postmortem` / `summary` | One-command failure/success postmortem |
| `context` | Bounded resume pack (`--for-resume`) |
| `gc` | Retention dry-run / apply from config (auto_apply after runs by default) |
| `runs` | List runs (`--tag`, `--status`, `--limit`) |
| `show` | Run summary (`--tui`, `--transcript`, `--tools`) |
| `timeline` | Event list (`--semantic`, `--kind`, `--source`) |
| `inspect` | Event detail + blob content |
| `diff` | Compare two runs |
| `analyze` | Error / side-effect / correlation passes |
| `search` | Full-text search (FTS5) across runs |
| `watch` | Live-tail events for a run |
| `export` | JSONL / HTML / portable (redacted by default) |
| `import` | Import portable JSON archive (v1/v2 + blobs) |
| `sync` | Push/pull via `--dir`, `--remote`, or `--s3` |
| `serve` | Local web dashboard + JSON/SSE API |
| `replay` | Timeline, mock tools, sandbox |
| `fork` | Branch a run record; optional `--launch` |
| `scrub` | Re-redact at-rest secrets (`--gc` for blobs) |
| `doctor` | Store path, health, optional `--reindex` |
| `rm` / `purge` | Delete runs; reclaim blobs |
| `tags` / `tag` | List tags; add/remove on a run |
| `stats` | Aggregate store dashboard |
| `completions` | bash / zsh / fish completions |

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
cargo build --release
```

CI runs clippy (`-D warnings`) and the full test suite on `master` / `main`. See [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

Contributor-oriented architecture notes: [`AGENTS.md`](AGENTS.md).  
Quality bar and remaining work: [`docs/ROADMAP.md`](docs/ROADMAP.md).  
Release checklist: [`docs/PUBLISH.md`](docs/PUBLISH.md).  
Changelog: [`CHANGELOG.md`](CHANGELOG.md).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
