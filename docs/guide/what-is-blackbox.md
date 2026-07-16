# What is blackbox?

**Answers:** What problem blackbox solves, how a run is captured, what is stored where, and what it deliberately does *not* do.

---

## In one paragraph

**blackbox** is a local flight recorder and debugger for commands you care about—especially AI coding agents (Claude, Codex, aider, gemini, cursor-agent, opencode, grok, and generic processes). It supervises a process under a **PTY**, merges additional capture layers (git, filesystem, process tree), **redacts secrets before write**, persists an ordered event stream in **SQLite** plus **content-addressed blobs**, and exposes CLI, TUI, a local dashboard, MCP tools, and a **project memory** pack so the next supervised launch need not start cold.

Package on crates.io: `blackbox-recorder`. Binary and library path: `blackbox`.

---

## Problems it targets

| Problem | What blackbox does |
|---|---|
| “The agent failed and I only have a scrollback fragment” | Ordered timeline + postmortem (headline, evidence, anomalies, next action) |
| “Two agents stepped on each other” | Optional **claims** (project or path-scoped) under sticky state |
| “The next session forgot the failure” | Sticky **attention** + project memory + `handoff` / `context` packs |
| “I can’t share this log; it has tokens” | Redact-before-write; export/sync redacted unless `--no-redact` |
| “I need CI/eval traces without mutating the launch” | `--ci` / `--eval` + `--artifact-dir` (observe-only for eval) |

---

## Mental model

```
  blackbox run -- <command>
           │
           ▼
  ┌──────────────── capture layers ────────────────┐
  │  PTY (terminal I/O)  │  git  │  fs  │  process │
  └──────────────────────┬─────────────────────────┘
                         │ merge → EventWriter (monotonic seq)
                         ▼
              .blackbox/blackbox.db  +  .blackbox/blobs/
                         │
         ┌───────────────┼────────────────┐
         ▼               ▼                ▼
      CLI / TUI      serve (HTTP)    memory / handoff
```

### Core objects

| Object | Role |
|---|---|
| **Run** | One supervised invocation: command, cwd, status, exit code, tags, timestamps |
| **TraceEvent** | Sequenced record: kind, source, status, metadata, optional blob refs |
| **Blob** | Large payload addressed by content hash (terminal chunks, tool I/O, …) |
| **Checkpoint** | End-of-run snapshot hooks (e.g. git/fs after state) |
| **Project memory** | Bounded pack (`MEMORY.md` / `MEMORY.json`) rebuilt after runs when continuity ≠ off |
| **Sticky state** | `state.json`: attention, claims, intent, unresolved failure, … |

Default store location: **project-local** `.blackbox/` (override with `--store` / `BLACKBOX_DB`). Legacy `./blackbox.db` is used only if that file already exists.

---

## Capture surfaces (what “observation” means)

| Layer | Typical signal |
|---|---|
| **PTY** | Terminal bytes → normalize ANSI → redact → optional blob → harness adapter parse |
| **Git** | Before/after snapshots, dirty tree signals (subject to redaction policy) |
| **Filesystem** | Observed writes relevant to the run (implementation-dependent filters) |
| **Process** | Process tree, exits; optional redacted environ enrichment |

Harness **adapters** detect argv/env patterns and parse tool calls from output (Claude, Codex, generic, aider, …). Detection and parsing are best-effort structured signal on top of the raw timeline—not a substitute for the PTY stream.

Details: [capture pipeline](../internals/capture-pipeline.md).

---

## Continuity (project memory on launch)

When a project is enabled with continuity on (`capture.continuity = always` is the memory-bus default):

1. End of run refreshes project memory from store + sticky state (budgeted, shrink order applies).
2. Next **explicit** `blackbox run` (non-ambient) may **inject** memory via files/env/preamble depending on harness cooperation and mode (`always` / `attention` / `off`).
3. Ambient shell capture (`maybe-run`) is **observe-only** by design: it records but does not mutate launch for continuity.

Honesty constraint: blackbox can *deliver* memory on supervised paths; it cannot force a model to *read* it without vendor cooperation or optional gates (`require_ack` on explicit run).

Details: [continuity plane](../internals/continuity-plane.md), [memory pack schema](../reference/memory-pack.md).

---

## What blackbox is not

| Not | Reality |
|---|---|
| A cloud SaaS | Local process + local store (sync is opt-in) |
| A secret vault by default | Redaction + optional blob encryption + sealed backup; SQLite is not SQLCipher-live |
| Deterministic LLM replay | Replay modes are timeline/mock/sandbox/fork—not bit-identical model re-execution |
| A replacement for your agent | It records and explains; it does not choose the next tool call for you |
| Guaranteed perfect redaction | Novel secret formats can slip; residual risk is documented in [security](security.md) |

---

## Two ways to record

| Mode | How | Continuity inject | Typical use |
|---|---|---|---|
| **Explicit** | `blackbox run -- <cmd>` | Allowed when configured | Debugging, CI, memory-aware launches |
| **Ambient** | Shell wrapper → `maybe-run` | No (observe-only) | Leave harnesses instrumented without changing habits |

Normative ambient rules: [ambient-contract.md](../ambient-contract.md). Operator guide: [leave-it-on.md](leave-it-on.md).

---

## Related

- Install: [install.md](install.md)
- First project: [getting-started.md](getting-started.md)
- Architecture: [../internals/architecture.md](../internals/architecture.md)
- Quality bar / versions: [../ROADMAP.md](../ROADMAP.md)
