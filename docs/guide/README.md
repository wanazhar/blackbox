# Guides

Operator documentation: install, record, inspect, debug, share, and harden blackbox. Written for people who are comfortable on a terminal and want **accurate answers**, not a simplified story.

For the full map (agents, reference, internals), see the [docs index](../README.md).

---

## Start here

| Order | Guide | Answers |
|---|---|---|
| 1 | [What is blackbox?](what-is-blackbox.md) | Problem it solves, mental model, boundaries |
| · | [Concepts](concepts.md) | How planes fit (capture / inspect / continuity) |
| · | [Glossary](glossary.md) | Precise term definitions |
| 2 | [Install](install.md) | Binary / cargo, PATH, `doctor` |
| 3 | [Getting started](getting-started.md) | Enable → first run → inspect (end-to-end) |
| 4 | [Recipes](recipes.md) | Copy-paste workflows for common jobs |
| · | [Cheatsheet](cheatsheet.md) | One-screen command reference |
| 5 | [Everyday use](everyday-use.md) | List, show, timeline, TUI, dashboard, search |

## Common jobs

| Guide | Answers |
|---|---|
| [Recipes](recipes.md) | 15 end-to-end workflows (CI, eval, vault, claims, …) |
| [Cheatsheet](cheatsheet.md) | Dense command list |
| [Adapters](adapters.md) | Claude, Codex, aider, gemini, cursor, … |
| [Doctor & capture quality](doctor-and-capture.md) | Daily-driver score, coverage surfaces, quality weights |
| [Annotated examples](examples.md) | status/handoff JSON + jq snippets |
| [Debug a failure](debug-a-failure.md) | Postmortem, anomalies, evidence → timeline, handoff |
| [Leave it on](leave-it-on.md) | Ambient shell wrappers, `BLACKBOX_OFF`, wrap list, nest rules |
| [Configuration](configuration.md) | Precedence, product modes, full knobs + env |
| [Security](security.md) | Threat model, redaction, crypto, serve auth |
| [Export and sync](export-and-sync.md) | Formats, sealed packs, sync, store vault |
| [Store integrity (`fsck`)](fsck-and-integrity.md) | Spool recovery, deep blob checks, safe repair |
| [Verification receipts](verification.md) | Execution vs verification vs capture |
| [Experiments & gates](experiments.md) | Typed metadata, reports, CI gates |
| [Capsules & MCP cassettes](capsules-and-cassettes.md) | Reproduction packages; experimental protocol replay |
| [Budgets & adapters](budgets-and-adapters.md) | Enforcement honesty; NDJSON adapters; project index |
| [Overhead](overhead.md) | Soft benches, stats, cost knobs |
| [Troubleshooting](troubleshooting.md) | Q→fix diagnostics and recovery |

## How these relate to reference

Guides explain **when and why**. For exhaustive flags and schemas:

- [CLI reference](../reference/cli.md)
- [JSON envelope / views](../reference/json-api.md)
- [MCP tools](../reference/mcp.md)
- [Memory pack schema](../reference/memory-pack.md)

Implementation detail: [architecture](../internals/architecture.md), [capture pipeline](../internals/capture-pipeline.md), [storage](../internals/storage.md), [continuity plane](../internals/continuity-plane.md).
