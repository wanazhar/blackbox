# Guides

Operator documentation: install, record, inspect, debug, share, and harden blackbox. Written for people who are comfortable on a terminal and want **accurate answers**, not a simplified story.

For the full map (agents, reference, internals), see the [docs index](../README.md).

---

## Start here

| Order | Guide | Answers |
|---|---|---|
| 1 | [What is blackbox?](what-is-blackbox.md) | Problem it solves, mental model, boundaries |
| 2 | [Install](install.md) | Binary / cargo, PATH, `doctor` |
| 3 | [Getting started](getting-started.md) | Enable → first run → inspect (end-to-end) |
| 4 | [Everyday use](everyday-use.md) | List, show, timeline, TUI, dashboard, search |

## Common jobs

| Guide | Answers |
|---|---|
| [Debug a failure](debug-a-failure.md) | Postmortem, anomalies, evidence → timeline, handoff |
| [Leave it on](leave-it-on.md) | Ambient shell wrappers, `BLACKBOX_OFF`, wrap list, nest rules |
| [Configuration](configuration.md) | Store paths, `config.toml`, flags, env vars |
| [Security](security.md) | Redaction model, danger flags, at-rest options, serve auth |
| [Export and sync](export-and-sync.md) | Formats, redacted defaults, push/pull backends |
| [Overhead](overhead.md) | Capture cost, storage stats, soft budgets |
| [Troubleshooting](troubleshooting.md) | Diagnostics, common failures, recovery |

## How these relate to reference

Guides explain **when and why**. For exhaustive flags and schemas:

- [CLI reference](../reference/cli.md)
- [JSON envelope / views](../reference/json-api.md)
- [MCP tools](../reference/mcp.md)
- [Memory pack schema](../reference/memory-pack.md)

Implementation detail: [architecture](../internals/architecture.md), [capture pipeline](../internals/capture-pipeline.md), [storage](../internals/storage.md), [continuity plane](../internals/continuity-plane.md).
