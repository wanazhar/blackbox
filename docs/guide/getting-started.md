# Getting started

**Answers:** How to enable a project, record the first run, inspect it, and optionally turn on project memory and ambient wrappers—without requiring prior knowledge of blackbox internals.

**Prerequisites:** [Install](install.md) (`blackbox --version` works). **Background:** [What is blackbox?](what-is-blackbox.md).

CI keeps this path honest: `cargo test --test docs_first_run` (record → list → postmortem → artifact files).

---

## 1. Enable a project

**Fast path (recommended):**

```bash
cd ~/my-project
blackbox setup                          # enable + sample `true` + doctor
# or:
blackbox setup --memory-bus --install-shell
blackbox setup --harden                 # encrypt_blobs + key under ~/.config/blackbox/
```

**Manual enable:**

```bash
cd ~/my-project   # or any repo you want traced

# Minimal: project store + config
blackbox enable

# Recommended for agent workflows: continuity defaults + shell wrappers
blackbox enable --memory-bus --install-shell
```

| Flag / command | Effect |
|---|---|
| `setup` | One-shot enable + optional shell/memory/harden + sample run |
| `enable` | Creates `.blackbox/`, default `config.toml`, `enabled = true` |
| `--memory-bus` | Continuity-oriented defaults (`capture.continuity = "always"` among them) |
| `--install-shell` | Installs managed wrappers for harness basenames on the wrap list |
| `--harden` (setup) | `encrypt_blobs=true`, project native logs, external key path |

**What lands on disk:**

```text
.blackbox/
  config.toml      # capture, retention, product mode, …
  blackbox.db      # created on first write
  blobs/           # content-addressed payloads
  # later: state.json, MEMORY.md, MEMORY.json, store.key (if encrypt_blobs), …
```

Add to `.gitignore` if not already ignored:

```gitignore
.blackbox/
blackbox.db
*.db-wal
*.db-shm
```

Shell wrapper mechanics and opt-out: [leave-it-on.md](leave-it-on.md).

---

## 2. Record a run

Everything after `--` is the supervised command:

```bash
blackbox run -- echo hello world
```

Example human output (wording may vary slightly by version):

```text
Run completed: a1b2c3d4  (succeeded)
```

The short id is a unique prefix of the run UUID — usable anywhere a run id is accepted (`show`, `timeline`, `postmortem`, …).

### What happens (accurate, brief)

1. Resolve store path (CLI / env / legacy db / `.blackbox/`).
2. Insert a **Run** row; start capture layers (PTY, git, filesystem, process as configured).
3. Spawn the command under a **PTY**; stream output through normalize → **redact** → blob/event pipeline; harness **adapter** may parse tool calls.
4. On exit: stop layers, checkpoint, update run status/exit code, refresh project memory when continuity ≠ off, apply sticky **attention**.

Full pipeline: [capture-pipeline](../internals/capture-pipeline.md).

### Variants you will use soon

```bash
# Propagate child exit code (CI)
blackbox run --ci --artifact-dir ./artifacts -- npm test

# Eval / benchmark: force observe-only + CI + tags eval,ci (no launch mutation)
blackbox run --eval --artifact-dir ./eval-out -- your-agent --prompt "…"

# Hard observe-only without full eval tag set
blackbox run --observe-only -- claude -p "…"

# Label and tag
blackbox run --name "fix-login" --tag wip -- claude -p "Fix login"
```

`--artifact-dir` writes `run.json`, `postmortem.json`, `anomalies.json`, `summary.txt`, and optional portable export. See [CLI reference](../reference/cli.md).

---

## 3. Inspect

```bash
blackbox runs
blackbox show latest
blackbox show latest --transcript
blackbox timeline latest --semantic
```

`runs` lists recent rows (id prefix, status, exit, label, time). `show` prints run metadata and a summary of what was captured. `timeline --semantic` hides observer bookkeeping so tool/terminal structure stays readable.

JSON (envelope `blackbox.cli/v1`):

```bash
blackbox runs --json
blackbox show latest --json
# shape: { "ok": true, "command": "runs"|"show", "data": { … } }
```

Interactive:

```bash
blackbox show latest --tui
# or: blackbox serve   → http://127.0.0.1:7788
```

Day-to-day patterns: [everyday-use.md](everyday-use.md).

---

## 4. When something fails

```bash
blackbox postmortem latest
blackbox handoff --json
```

Step-by-step: [debug-a-failure.md](debug-a-failure.md).

---

## 5. Project memory (if you used `--memory-bus`)

```bash
blackbox memory show
blackbox memory set --goal "Fix the CI flake" --open "Stabilize auth test"
blackbox status
```

Supervised **explicit** runs can inject the memory pack (files / env / preamble depending on harness). Ambient wrappers record but do **not** inject.

Multi-agent claim:

```bash
blackbox claim acquire --holder "$USER"
# … work …
blackbox claim release
```

Schema: [memory-pack.md](../reference/memory-pack.md). Semantics: [continuity-plane](../internals/continuity-plane.md).

---

## 6. Sanity checks

```bash
blackbox doctor
blackbox stats
```

If store path, permissions, or redaction look wrong: [troubleshooting.md](troubleshooting.md), [security.md](security.md).

---

## Next

| Job | Guide |
|---|---|
| More workflows (CI, vault, claims, …) | [recipes.md](recipes.md) |
| One-screen commands | [cheatsheet.md](cheatsheet.md) |
| How the planes fit | [concepts.md](concepts.md) |
| Claude / Codex / other harnesses | [adapters.md](adapters.md) |
| Daily commands, TUI, dashboard | [everyday-use.md](everyday-use.md) |
| Ambient “leave it on” | [leave-it-on.md](leave-it-on.md) |
| Debug failures | [debug-a-failure.md](debug-a-failure.md) |
| Config surfaces | [configuration.md](configuration.md) |
| Export / sync | [export-and-sync.md](export-and-sync.md) |
| All flags | [../reference/cli.md](../reference/cli.md) |
| Agent session playbook | [../skills/blackbox.md](../skills/blackbox.md) |
