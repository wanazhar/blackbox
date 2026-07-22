# blackbox

Local flight recorder, debugger, and project memory for AI-agent runs and other
commands that need an ordered, redacted timeline on disk.

Supervises a process under a PTY, merges git / filesystem / process signals,
**redacts secrets before write**, stores events in SQLite plus content-addressed
blobs, then inspects them with CLI, TUI, a local dashboard, MCP, or `--json`.

| | |
|---|---|
| **CLI binary** | `blackbox` |
| **Library path** | `blackbox` (`use blackbox::…`) |
| **crates.io package** | [`blackbox-recorder`](https://crates.io/crates/blackbox-recorder) |
| **API docs** | [docs.rs/blackbox-recorder](https://docs.rs/blackbox-recorder) |
| **Operator docs** | [docs/README.md](https://github.com/wanazhar/blackbox/blob/master/docs/README.md) |
| **License** | MIT OR Apache-2.0 |

> **crates.io / docs.rs note:** package name is `blackbox-recorder`; the binary
> and Rust crate path stay `blackbox`. Deep guides live on GitHub (linked
> above). Relative `docs/` links below work on GitHub; on crates.io use the
> absolute links in the table.

---

## Scope

You already use a terminal and likely an agent harness (Claude, Codex, aider, …).
Blackbox is for:

1. **Record** — what actually ran (PTY + layers), not a partial scrollback
2. **Inspect** — failures with structure (postmortem, anomalies, timeline)
3. **Continue** — project memory and handoff for the next launch

Not a SaaS, not a secret vault by default, not deterministic LLM replay.
Boundaries: [What is blackbox?](https://github.com/wanazhar/blackbox/blob/master/docs/guide/what-is-blackbox.md).

---

## Install

```bash
# Binary (no Rust toolchain required)
curl -fsSL https://raw.githubusercontent.com/wanazhar/blackbox/master/install.sh | sh

# Or crates.io (package name ≠ binary name)
cargo install blackbox-recorder

blackbox --version
blackbox doctor
```

Details: [Install](https://github.com/wanazhar/blackbox/blob/master/docs/guide/install.md).

---

## First five minutes

```bash
cd ~/my-project
blackbox setup --memory-bus --install-shell   # enable + sample + doctor
# blackbox setup --harden                     # optional encrypt_blobs + external key

blackbox run -- echo hello world
blackbox runs
blackbox show latest
blackbox timeline latest --semantic
```

Failed run?

```bash
blackbox fail                 # focus + postmortem + anomalies + next
blackbox show latest --tui    # e = failure story, Enter/g = jump to seq
```

Walkthrough: [Getting started](https://github.com/wanazhar/blackbox/blob/master/docs/guide/getting-started.md).

---

## Documentation by question

Links point at the GitHub tree so they resolve from crates.io as well as GitHub.

| Question | Doc |
|---|---|
| What is this, technically? | [What is blackbox?](https://github.com/wanazhar/blackbox/blob/master/docs/guide/what-is-blackbox.md) |
| Capture / memory / inspect planes | [Concepts](https://github.com/wanazhar/blackbox/blob/master/docs/guide/concepts.md) |
| Terms | [Glossary](https://github.com/wanazhar/blackbox/blob/master/docs/guide/glossary.md) |
| Copy-paste workflows | [Recipes](https://github.com/wanazhar/blackbox/blob/master/docs/guide/recipes.md) |
| One-screen commands | [Cheatsheet](https://github.com/wanazhar/blackbox/blob/master/docs/guide/cheatsheet.md) |
| Harness adapters | [Adapters](https://github.com/wanazhar/blackbox/blob/master/docs/guide/adapters.md) |
| Doctor / capture quality | [Doctor & capture](https://github.com/wanazhar/blackbox/blob/master/docs/guide/doctor-and-capture.md) |
| Store integrity (`fsck`) | [Fsck & integrity](https://github.com/wanazhar/blackbox/blob/master/docs/guide/fsck-and-integrity.md) |
| Verification receipts | [Verification](https://github.com/wanazhar/blackbox/blob/master/docs/guide/verification.md) |
| Experiments & CI gates | [Experiments](https://github.com/wanazhar/blackbox/blob/master/docs/guide/experiments.md) |
| Boundaries, evidence, incidents (1.7) | [Boundaries & incidents](https://github.com/wanazhar/blackbox/blob/master/docs/guide/boundaries-and-incidents.md) |
| Capsules & MCP cassettes | [Capsules](https://github.com/wanazhar/blackbox/blob/master/docs/guide/capsules-and-cassettes.md) |
| Budgets & external adapters | [Budgets](https://github.com/wanazhar/blackbox/blob/master/docs/guide/budgets-and-adapters.md) |
| Day-to-day CLI / TUI / serve | [Everyday use](https://github.com/wanazhar/blackbox/blob/master/docs/guide/everyday-use.md) |
| Debug a failed run | [Debug a failure](https://github.com/wanazhar/blackbox/blob/master/docs/guide/debug-a-failure.md) |
| Ambient shell wrappers | [Leave it on](https://github.com/wanazhar/blackbox/blob/master/docs/guide/leave-it-on.md) |
| Config / env / store paths | [Configuration](https://github.com/wanazhar/blackbox/blob/master/docs/guide/configuration.md) |
| Redaction & threat model | [Security](https://github.com/wanazhar/blackbox/blob/master/docs/guide/security.md) |
| Export / sync / backup | [Export and sync](https://github.com/wanazhar/blackbox/blob/master/docs/guide/export-and-sync.md) |
| Something broken | [Troubleshooting](https://github.com/wanazhar/blackbox/blob/master/docs/guide/troubleshooting.md) |
| **Full map** | [docs/README.md](https://github.com/wanazhar/blackbox/blob/master/docs/README.md) |

### Reference & agents

| | |
|---|---|
| Every subcommand | [CLI reference](https://github.com/wanazhar/blackbox/blob/master/docs/reference/cli.md) |
| `--json` views | [JSON API](https://github.com/wanazhar/blackbox/blob/master/docs/reference/json-api.md) |
| MCP tools | [MCP](https://github.com/wanazhar/blackbox/blob/master/docs/reference/mcp.md) |
| Boundary contracts (1.7) | [Boundary reference](https://github.com/wanazhar/blackbox/blob/master/docs/reference/boundary.md) |
| Eval score.json | [Score](https://github.com/wanazhar/blackbox/blob/master/docs/reference/score.md) |
| Memory pack schema | [Memory pack](https://github.com/wanazhar/blackbox/blob/master/docs/reference/memory-pack.md) |
| Agent session playbook | [skills/blackbox.md](https://github.com/wanazhar/blackbox/blob/master/docs/skills/blackbox.md) |

### Contributors

| | |
|---|---|
| Repo map | [AGENTS.md](https://github.com/wanazhar/blackbox/blob/master/AGENTS.md) |
| Architecture | [internals/architecture.md](https://github.com/wanazhar/blackbox/blob/master/docs/internals/architecture.md) |
| Writing standard | [WRITING.md](https://github.com/wanazhar/blackbox/blob/master/docs/WRITING.md) |
| Roadmap | [ROADMAP.md](https://github.com/wanazhar/blackbox/blob/master/docs/ROADMAP.md) |
| Changelog | [CHANGELOG.md](https://github.com/wanazhar/blackbox/blob/master/CHANGELOG.md) |

Optional local MkDocs preview (not deployed):

```bash
pip install -r requirements-docs.txt
bash scripts/prepare_docs_site.sh
mkdocs serve
```

---

## Commands (orientation)

| Job | Command |
|---|---|
| Enable project | `blackbox enable` / `--memory-bus` / `--install-shell` |
| Record | `blackbox run -- <cmd>` · `--ci` · `--eval` · `--observe-only` |
| Ambient policy | `blackbox maybe-run` (shell wrappers) |
| Inspect | `runs` · `show` · `timeline` · `inspect` · `tui` · `serve` · `search` |
| Explain failure | `fail` · `postmortem` · `analyze` · `diff` |
| Continuity | `status` · `handoff` · `memory` · `claim` · `resolve` · `context` |
| Integrity | `fsck` · `fsck --deep` · `fsck --repair` |
| Verification | `verify` · `report` · `gate` · `experiment` |
| Share | `export` · `import` · `sync` · `backup` / `restore` · `capsule` |
| Hygiene | `doctor` · `stats` · `scrub` · `gc` · `purge` / `rm` |
| Agents | `mcp` · global `--json` |

Flags: [CLI reference](https://github.com/wanazhar/blackbox/blob/master/docs/reference/cli.md).

---

## Defaults worth knowing

- **Redact-before-write** on argv, env, terminal, tool payloads. Raw capture needs `--insecure-raw` / `--no-redact` (dangerous).
- **Store is project-local:** `.blackbox/blackbox.db` + `.blackbox/blobs/` (`--store` / `BLACKBOX_DB`).
- **Export/sync redact** unless `--no-redact`.
- **Ambient capture is observe-only** (no continuity inject). Explicit `run` is the inject path.
- **Execution success is not verification** — use `blackbox verify` receipts for gates.
- **At-rest:** optional `encrypt_blobs` + sealed sticky files; offline vault via `backup`/`restore`. Live SQLCipher is not used — [security](https://github.com/wanazhar/blackbox/blob/master/docs/guide/security.md).

---

## Development

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
cargo build --release
python3 scripts/check_doc_links.py
```

Stable Rust, edition 2021. CI: [`.github/workflows/ci.yml`](https://github.com/wanazhar/blackbox/blob/master/.github/workflows/ci.yml).

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
