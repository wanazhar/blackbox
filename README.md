# blackbox

Local **flight recorder, debugger, and project memory** for AI-agent runs and other commands you need an honest timeline for.

Supervise a process under a PTY, merge git/filesystem/process signal, **redact secrets before write**, store an ordered event stream in SQLite + content-addressed blobs, then inspect with CLI, TUI, dashboard, MCP, or `--json`.

| | |
|---|---|
| **Binary / lib** | `blackbox` |
| **crates.io** | [`blackbox-recorder`](https://crates.io/crates/blackbox-recorder) |
| **License** | MIT OR Apache-2.0 |
| **Docs** | **[docs/README.md](docs/README.md)** — index by question |

---

## Who this is for

You already use a terminal and probably an agent harness (Claude, Codex, aider, …). You want:

1. **Record** what actually ran (not a partial scrollback)
2. **Inspect** failures with structure (postmortem, anomalies, timeline)
3. **Continue** work with project memory and handoff—without treating the store as a cloud brain

It is not a SaaS, not a secret vault by default, and not deterministic LLM replay. Boundaries: [What is blackbox?](docs/guide/what-is-blackbox.md).

---

## Install

```bash
# Binary (no Rust required)
curl -fsSL https://raw.githubusercontent.com/wanazhar/blackbox/master/install.sh | sh

# Or crates.io (package name ≠ binary name)
cargo install blackbox-recorder

blackbox --version
blackbox doctor
```

Details: [Install](docs/guide/install.md).

---

## First five minutes

```bash
cd ~/my-project
blackbox enable --memory-bus --install-shell   # or: blackbox enable

blackbox run -- echo hello world
blackbox runs
blackbox show latest
blackbox timeline latest --semantic
```

Failed run?

```bash
blackbox postmortem latest
blackbox show latest --tui    # e = failure story, Enter/g = jump to seq
```

Full walkthrough: [Getting started](docs/guide/getting-started.md).

---

## Documentation by question

| Question | Doc |
|---|---|
| What is this, technically? | [What is blackbox?](docs/guide/what-is-blackbox.md) |
| How do capture / memory / inspect fit? | [Concepts](docs/guide/concepts.md) |
| What do these terms mean? | [Glossary](docs/guide/glossary.md) |
| Copy-paste workflows | [Recipes](docs/guide/recipes.md) |
| One-screen commands | [Cheatsheet](docs/guide/cheatsheet.md) |
| Harness adapters | [Adapters](docs/guide/adapters.md) |
| Doctor / capture quality | [Doctor & capture](docs/guide/doctor-and-capture.md) |
| Sample handoff/status JSON | [Examples](docs/guide/examples.md) |
| Day-to-day CLI / TUI / dashboard | [Everyday use](docs/guide/everyday-use.md) |
| Debug a failed agent run | [Debug a failure](docs/guide/debug-a-failure.md) |
| Ambient shell wrappers | [Leave it on](docs/guide/leave-it-on.md) |
| Config, env, store paths | [Configuration](docs/guide/configuration.md) |
| Redaction & threat model | [Security](docs/guide/security.md) |
| Export / sync / backup | [Export and sync](docs/guide/export-and-sync.md) |
| Something broken | [Troubleshooting](docs/guide/troubleshooting.md) |
| **Full docs map** | **[docs/README.md](docs/README.md)** |
| Local docs site (optional) | `pip install mkdocs-material && mkdocs serve` |

### Reference & agents

| | |
|---|---|
| Every subcommand | [CLI reference](docs/reference/cli.md) |
| `--json` views | [JSON API](docs/reference/json-api.md) |
| MCP tools | [MCP reference](docs/reference/mcp.md) |
| Memory pack schema | [Memory pack](docs/reference/memory-pack.md) |
| Coding-agent playbook | [skills/blackbox.md](docs/skills/blackbox.md) |

### Contributors

| | |
|---|---|
| Repo map & conventions | [AGENTS.md](AGENTS.md) |
| Architecture | [docs/internals/architecture.md](docs/internals/architecture.md) |
| How we write docs | [docs/WRITING.md](docs/WRITING.md) |
| Roadmap / quality bar | [docs/ROADMAP.md](docs/ROADMAP.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

---

## Commands (orientation, not a full reference)

| Job | Command |
|---|---|
| Enable project | `blackbox enable` / `--memory-bus` / `--install-shell` |
| Record | `blackbox run -- <cmd>` · `--ci` · `--eval` · `--observe-only` |
| Ambient policy | `blackbox maybe-run` (shell wrappers) |
| Inspect | `runs` · `show` · `timeline` · `inspect` · `tui` · `serve` |
| Explain failure | `postmortem` · `analyze` · `diff` |
| Continuity | `status` · `handoff` · `memory` · `claim` · `resolve` · `context` |
| Share | `export` · `import` · `sync` · `backup` / `restore` |
| Hygiene | `doctor` · `stats` · `scrub` · `gc` · `purge` / `rm` |
| Agents | `mcp` · global `--json` |

Exhaustive flags: [docs/reference/cli.md](docs/reference/cli.md).

---

## Defaults worth knowing

- **Redact-before-write** on argv, env, terminal, tool payloads. Raw capture requires `--insecure-raw` / `--no-redact` (dangerous).
- **Store is project-local:** `.blackbox/blackbox.db` + `.blackbox/blobs/` (override: `--store`, `BLACKBOX_DB`).
- **Export/sync redact** unless `--no-redact`.
- **Ambient capture is observe-only** (no continuity inject). Explicit `run` is the inject path.
- **At-rest:** optional `encrypt_blobs` + sealed sticky files; offline vault via `blackbox backup`/`restore`. Live SQLCipher is not used—see [security](docs/guide/security.md).

---

## Development

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
cargo build --release
```

Stable Rust, edition 2021. CI: [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
