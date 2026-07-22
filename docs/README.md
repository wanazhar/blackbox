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
| Store integrity (`fsck`) | [guide/fsck-and-integrity.md](guide/fsck-and-integrity.md) |
| Verification receipts | [guide/verification.md](guide/verification.md) |
| Experiments & CI gates | [guide/experiments.md](guide/experiments.md) |
| Boundaries & incidents (1.7) | [guide/boundaries-and-incidents.md](guide/boundaries-and-incidents.md) |
| Capsules & MCP cassettes | [guide/capsules-and-cassettes.md](guide/capsules-and-cassettes.md) |
| Budgets & external adapters | [guide/budgets-and-adapters.md](guide/budgets-and-adapters.md) |
| Performance / disk | [guide/overhead.md](guide/overhead.md) |
| Broken install or store | [guide/troubleshooting.md](guide/troubleshooting.md) |

Guide map: [guide/README.md](guide/README.md).

### How docs are published

| Surface | What you get |
|---|---|
| **GitHub** | Full tree under `docs/` (this file is the index) |
| **crates.io** | Package README (`README.md`) with absolute links into this repo |
| **docs.rs** | Rust API docs for crate `blackbox-recorder` (`src/lib.rs`) |

There is **no GitHub Pages site** for blackbox. Operator guides are **in-repo
markdown**, not rustdoc pages.

Link check (also run in CI): `python3 scripts/check_doc_links.py`.

Optional local Material site (never deployed):

```bash
pip install -r requirements-docs.txt
bash scripts/prepare_docs_site.sh      # copies AGENTS.md + CHANGELOG.md into docs/
mkdocs serve                           # http://127.0.0.1:8000 only on your machine
```

---

## I am wiring an agent or automation

| Question | Go here |
|---|---|
| Session playbook for coding agents | [skills/blackbox.md](skills/blackbox.md) |
| MCP tools | [reference/mcp.md](reference/mcp.md) |
| `--json` envelope and view schemas | [reference/json-api.md](reference/json-api.md) |
| Project memory pack schema | [reference/memory-pack.md](reference/memory-pack.md) |
| Eval score.json | [reference/score.md](reference/score.md) |
| Boundary / evidence / incidents (1.7) | [reference/boundary.md](reference/boundary.md) |
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
| [reference/boundary.md](reference/boundary.md) | Boundary / containment / evidence / incidents (1.7) |
| [reference/score.md](reference/score.md) | Eval `score.json` including trust fields |
| [reference/stream-protocol.md](reference/stream-protocol.md) | NDJSON stream |

---

## I am changing the code

| Document | Contents |
|---|---|
| [AGENTS.md](https://github.com/wanazhar/blackbox/blob/master/AGENTS.md) | Module map, conventions, how to add features |
| [internals/architecture.md](internals/architecture.md) | Data flow and crates layout |
| [internals/capture-pipeline.md](internals/capture-pipeline.md) | Layers, PTY, adapters |
| [internals/storage.md](internals/storage.md) | SQLite, blobs, FTS5, GC |
| [internals/continuity-plane.md](internals/continuity-plane.md) | State, memory, claims, gates |
| [WRITING.md](WRITING.md) | How we write docs (incl. 1.5 rewrite standard) |
| [inventory.md](inventory.md) | Machine-readable page inventory (`inventory.json`) |

---

## Product direction (not how-to)

| Document | Contents |
|---|---|
| [ROADMAP.md](ROADMAP.md) | Quality bar and version story (incl. 1.6 bar) |
| [plan/trace-integrity-1.5.md](plan/trace-integrity-1.5.md) | 1.5 plan (trace integrity & scale) |
| [CHANGELOG.md](https://github.com/wanazhar/blackbox/blob/master/CHANGELOG.md) | Released changes |
| [plan/](plan/) | Design plans (historical + active) — not operator how-to |
| [history/](history/) | Archived plans |
| [claims.md](claims.md) | High-risk guarantee claim matrix |

---

## Writing standard

See [WRITING.md](WRITING.md): competent technical audience, answer-first structure, no dumbing down, no design-doc IDs in operator guides.
