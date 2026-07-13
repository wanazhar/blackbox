# blackbox

**Flight recorder, debugger, and project memory bus for AI-agent runs.**

Supervise any command under a PTY, capture terminal output plus git/filesystem/process context into SQLite, then inspect, search, export, and sync traces — with **secrets redacted by default**.

| | |
|---|---|
| **CLI / lib name** | `blackbox` |
| **crates.io package** | [`blackbox-recorder`](https://crates.io/crates/blackbox-recorder) |
| **License** | MIT OR Apache-2.0 |
| **Version** | **1.2.0** — Agent Memory Bus |

---

## Why blackbox?

- **Secrets stay out of the store** — argv, env, and terminal output are redacted before write. Raw capture requires explicit `--insecure-raw`.
- **Honest timelines** — a single `EventWriter` owns monotonic sequence numbers. Order matches capture order.
- **Payloads as blobs** — large content lives under content-addressed files; events keep short previews.
- **Project-local store** — `.blackbox/blackbox.db` + `.blackbox/blobs/` (override with `--store` / `BLACKBOX_DB`).
- **Safe share defaults** — export and sync redact unless you pass `--no-redact`.
- **Agent-native** — `--json` envelope, handoff, MCP tools, project memory bus on launch.
- **Continuity plane (1.2)** — every supervised launch delivers a bounded project memory pack (files, env, preamble). Agents cannot honestly start cold.

---

## Quick start

```bash
# Install (binary, no Rust required)
curl -fsSL https://raw.githubusercontent.com/wanazhar/blackbox/master/install.sh | sh

# Or from crates.io
cargo install blackbox-recorder

# Enable a project with memory bus
cd ~/my-project
blackbox enable --install-shell --memory-bus

# Record your first run
blackbox run -- echo hello world

# See the result
blackbox runs
blackbox show <short-id>
blackbox handoff --json

# Check project memory
blackbox memory show --json
blackbox memory set --goal "Fix the CI"
blackbox resolve
```

See the [Getting Started guide](docs/guide/getting-started.md) for a full walkthrough.

---

## Documentation

| For | Start here |
|---|---|
| **New users** | [Getting started](docs/guide/getting-started.md) |
| **Configuration** | [Configuration guide](docs/guide/configuration.md) |
| **Security model** | [Security guide](docs/guide/security.md) |
| **CLI reference** | [CLI reference](docs/reference/cli.md) |
| **MCP tools** | [MCP reference](docs/reference/mcp.md) |
| **JSON API** | [JSON API reference](docs/reference/json-api.md) |
| **Memory pack** | [Memory pack reference](docs/reference/memory-pack.md) |
| **Contributors** | [AGENTS.md](AGENTS.md) |
| **Architecture** | [Architecture internals](docs/internals/architecture.md) |
| **Roadmap & quality bar** | [ROADMAP.md](docs/ROADMAP.md) |
| **Changelog** | [CHANGELOG.md](CHANGELOG.md) |

---

## Key features by version

### 1.0 — Capability daily-driver

PTY capture, redact-before-write, SQLite + content-addressed blobs, CLI/TUI/dashboard, MCP stdio server, auto-resume, harness adapters (Claude, Codex, aider, etc.), export (JSONL/HTML/portable), sync (dir/HTTP/S3), search (FTS5), replay (timeline/mock/sandbox/fork).

### 1.1 — Adoption bar ("leave it on")

Ambient shell contract (OFF/nest/wrap/binary-missing), redaction regression gate, resume-pack quality, cost visibility (doctor/stats), CI/eval polish (`--ci`, `--artifact-dir`, `postmortem --fail-on-failure`), pricing opt-in, sandbox git restore, Windows soft/hard kill + PowerShell install, richer adapters (aider/gemini/cursor/opencode/grok).

### 1.2 — Agent Memory Bus / Continuity plane

Project memory pack (`blackbox.memory/v1`) with budget shrink, continuity modes (`always`/`attention`/`off`), sticky state v2 + M6 attention discipline, `state.lock` + claims (one active project claim), gate modes (`warn`/`require_ack`), memory CLI/MCP surfaces, M2a quality test suite.

---

## Commands at a glance

| Command | Purpose |
|---|---|
| `enable` / `disable` | Opt-in project capture; `--install-shell` wrappers |
| `run` | Supervise a command; capture events |
| `maybe-run` | Project-gated ambient capture (shell wrappers) |
| `status` / `handoff` | Project status + agent handoff with memory pack |
| `memory show` / `set` | Project memory pack display and intent update |
| `claim` | Acquire/release/status project claim |
| `resolve` | Clear unresolved failure attention |
| `ack` | Acknowledge gate (required_ack mode) |
| `runs` / `show` / `timeline` / `inspect` | List, view, and inspect runs and events |
| `diff` | Compare two runs |
| `analyze` | Error, side-effect, and correlation analysis |
| `search` | Full-text search across events |
| `export` / `import` | Share traces (redacted by default) |
| `sync push` / `pull` | Sync to directory, HTTP, or S3 |
| `serve` | Local web dashboard + JSON/SSE API |
| `replay` / `fork` | Replay run timeline or fork from checkpoint |
| `postmortem` / `summary` | Failure/success postmortem |
| `context` | Bounded resume pack |
| `scrub` / `gc` | Re-redact historical secrets + blob GC |
| `doctor` / `stats` | Diagnostics and storage usage |
| `purge` / `rm` | Delete runs by policy |
| `mcp` | MCP stdio server |
| `completions` | Shell completions |

---

## Development

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
cargo build --release
```

CI runs clippy (`-D warnings`) and the full test suite. See [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
