# Documentation index

Blackbox docs are split by **who is reading** and **what question they have**. Technical depth is intentional; pages are structured so you can skip to the answer without wading through design history.

---

## I want to use blackbox

| Question | Go here |
|---|---|
| What is this, exactly? | [guide/what-is-blackbox.md](guide/what-is-blackbox.md) |
| How do the pieces fit? | [guide/concepts.md](guide/concepts.md) |
| Glossary of terms | [guide/glossary.md](guide/glossary.md) |
| Install and verify | [guide/install.md](guide/install.md) |
| First project end-to-end | [guide/getting-started.md](guide/getting-started.md) |
| Copy-paste workflows | [guide/recipes.md](guide/recipes.md) |
| One-screen commands | [guide/cheatsheet.md](guide/cheatsheet.md) |
| Agent harness adapters | [guide/adapters.md](guide/adapters.md) |
| Day-to-day commands | [guide/everyday-use.md](guide/everyday-use.md) |
| Something failed — debug it | [guide/debug-a-failure.md](guide/debug-a-failure.md) |
| Ambient capture / shell wrappers | [guide/leave-it-on.md](guide/leave-it-on.md) |
| Doctor / capture quality | [guide/doctor-and-capture.md](guide/doctor-and-capture.md) |
| Annotated status/handoff JSON | [guide/examples.md](guide/examples.md) |
| Config knobs | [guide/configuration.md](guide/configuration.md) |
| Secrets and threat model | [guide/security.md](guide/security.md) |
| Export, sync, backup | [guide/export-and-sync.md](guide/export-and-sync.md) |
| Performance / disk | [guide/overhead.md](guide/overhead.md) |
| Broken install or store | [guide/troubleshooting.md](guide/troubleshooting.md) |

Guide map: [guide/README.md](guide/README.md).

### Optional local docs site

```bash
pip install mkdocs-material
mkdocs serve          # from repo root — uses mkdocs.yml
mkdocs build -d site  # static output (gitignored)
```

---

## I am wiring an agent or automation

| Question | Go here |
|---|---|
| Session playbook for coding agents | [skills/blackbox.md](skills/blackbox.md) |
| MCP tools | [reference/mcp.md](reference/mcp.md) |
| `--json` envelope and view schemas | [reference/json-api.md](reference/json-api.md) |
| Project memory pack schema | [reference/memory-pack.md](reference/memory-pack.md) |
| Stream / portable formats | [reference/stream-protocol.md](reference/stream-protocol.md), [reference/portable-format.md](reference/portable-format.md) |
| Ambient decision order (normative) | [ambient-contract.md](ambient-contract.md) |

---

## I need exhaustive CLI / protocol detail

| Document | Contents |
|---|---|
| [reference/cli.md](reference/cli.md) | Every subcommand, args, exit codes |
| [reference/json-api.md](reference/json-api.md) | Envelope + views |
| [reference/mcp.md](reference/mcp.md) | MCP tool surface |
| [reference/memory-pack.md](reference/memory-pack.md) | `blackbox.memory/v1` |
| [reference/portable-format.md](reference/portable-format.md) | Import/export archive |
| [reference/stream-protocol.md](reference/stream-protocol.md) | NDJSON stream |

---

## I am changing the code

| Document | Contents |
|---|---|
| [../AGENTS.md](../AGENTS.md) | Module map, conventions, how to add features |
| [internals/architecture.md](internals/architecture.md) | Data flow and crates layout |
| [internals/capture-pipeline.md](internals/capture-pipeline.md) | Layers, PTY, adapters |
| [internals/storage.md](internals/storage.md) | SQLite, blobs, FTS5, GC |
| [internals/continuity-plane.md](internals/continuity-plane.md) | State, memory, claims, gates |
| [WRITING.md](WRITING.md) | How we write docs |

---

## Product direction (not how-to)

| Document | Contents |
|---|---|
| [ROADMAP.md](ROADMAP.md) | Quality bar and version story |
| [../CHANGELOG.md](../CHANGELOG.md) | Released changes |
| [plan/](plan/) | **Historical** design docs — do not treat as current how-to |
| [history/](history/) | Archived plans |

---

## Writing standard

See [WRITING.md](WRITING.md): competent technical audience, answer-first structure, no dumbing down, no design-doc IDs in operator guides.
