# Writing blackbox docs

These rules apply when adding or revising documentation. Audience is a **competent technical reader** (engineers, agent authors, SRE-minded developers). Do **not** dumb down mechanisms. Do **make them findable and answerable**.

---

## Goals

1. **Answer questions** — a reader should leave with a decision, a command, or a precise mental model.
2. **Respect technical skill** — use real terms (PTY, FTS5, redaction, continuity). Define once when first needed; do not avoid them.
3. **Separate tracks** — human jobs, agent surfaces, and contributor internals must not be mashed into one undifferentiated wall of text.
4. **Stay accurate** — docs match the binary; prefer linking to reference over inventing shorthand that drifts.

Non-goals: marketing fluff, cartoon analogies that hide behavior, or “you don’t need to understand this.”

---

## Audience

| Track | Who | Entry |
|---|---|---|
| **Operator** | Person installing and using blackbox day to day | [guide/](guide/README.md) |
| **Agent / automation** | LLM harnesses, CI, MCP clients | [skills/blackbox.md](skills/blackbox.md), [reference/mcp.md](reference/mcp.md), [reference/json-api.md](reference/json-api.md) |
| **Contributor** | People changing Rust code | [AGENTS.md](https://github.com/wanazhar/blackbox/blob/master/AGENTS.md), [internals/](internals/) |

If a page serves more than one track, put the primary track first and link the rest.

---

## Page structure (guides)

Prefer this order:

1. **One-line purpose** — what this page answers.
2. **When to use / when not to** — scope boundaries.
3. **Commands that work** — copy-paste, realistic flags.
4. **What actually happens** — correct technical explanation (layers, store paths, defaults).
5. **Failure modes & limits** — honesty over reassurance.
6. **See also** — reference, internals, related jobs.

Avoid opening with version archaeology (1.0 / 1.1 / 1.2 bars). Put that in [ROADMAP.md](ROADMAP.md) or [CHANGELOG.md](https://github.com/wanazhar/blackbox/blob/master/CHANGELOG.md).

---

## Style

| Do | Don’t |
|---|---|
| Lead with the job or question | Lead with module names or ticket IDs (M2a, A1) |
| Use precise terms after a short definition | Replace “redaction” with vague “safety magic” |
| Show expected CLI output when it clarifies | Dump full JSON schemas in guides (link reference) |
| State defaults and override precedence | Assume the reader memorized config.toml |
| Call out danger flags (`--insecure-raw`, `--no-redact`) | Soft-pedal residual risk |
| Link depth (architecture, schemas) | Inline entire design docs into getting-started |

**Tone:** direct, dense enough to be useful, not conversational filler. Complete sentences. Prefer active voice.

**Length:** guides should stay scannable. If a section needs a full schema, move it to `docs/reference/` and link.

---

## Glossary (preferred terms)

Canonical list for operators: [guide/glossary.md](guide/glossary.md). Use these consistently; parentheticals are acceptable once per page.

| Prefer | Means | Avoid as primary label |
|---|---|---|
| **run** | One supervised command invocation with a UUID | “session” (ambiguous with harness sessions) |
| **store** | Project `.blackbox/` (SQLite + blobs) | “database” alone |
| **event** | Ordered `TraceEvent` in a run | “log line” |
| **blob** | Content-addressed payload under `.blackbox/blobs/` | “file dump” |
| **redaction** | Secret scrubbing before write / on export | “sanitization” alone |
| **project memory** | Bounded pack (`MEMORY.md` / `MEMORY.json`) injected or shown for continuity | inventing new product nicknames each page |
| **continuity** | Config-driven delivery of project memory on launch (`always` / `attention` / `off`) | “memory bus” without explanation |
| **ambient capture** | Shell wrappers → `maybe-run` for harness basenames | “auto-magic” |
| **claim** | Exclusive (or path-scoped) holder for multi-agent coordination | “lock” without saying claim |
| **attention** | Sticky level after outcomes (`none` / `continue` / `blocked`) | burying under “handoff vibes” |
| **postmortem** | Structured summary (headline, evidence, anomalies, next action) | “AI summary” (it is deterministic analysis) |
| **observe-only** | No prompt mutation, continuity inject, or launch rewrite | “passive” alone |

Design-doc IDs (A1, M6, …) belong in roadmap/plan docs, not in operator guides, unless citing a test gate.

---

## Code and commands

- Always show the form users type: `blackbox <subcommand> …`
- Use `--` before the supervised command: `blackbox run -- echo hi`
- Prefer `latest` / short run ids in examples when the CLI accepts them
- Mark destructive or privacy-sensitive flags clearly
- For agent-oriented examples, show `--json` and point at the envelope in [json-api.md](reference/json-api.md)

---

## What lives where

| Path | Role |
|---|---|
| `README.md` | Landing: what it is, install, first commands, map by intent |
| `docs/guide/` | Operator answers (jobs, how-to, FAQ) |
| `docs/reference/` | Normative flags, schemas, protocols |
| `docs/internals/` | Implementation truth for contributors |
| `docs/plan/`, `docs/history/` | Historical design — not product docs |
| `docs/skills/` | Agent session playbook |
| `AGENTS.md` | Contributor / coding-agent map of the repo |

---

## Checklist before merging doc changes

- [ ] Can a skilled stranger answer “what do I run?” from the page alone?
- [ ] Are defaults and escape hatches stated?
- [ ] Are danger flags and residual risks honest?
- [ ] Do links go to the right track (guide vs reference vs internals)?
- [ ] Did we avoid inventing behavior that only exists in a plan doc?
- [ ] Spelling of product terms matches this glossary?
- [ ] `python3 scripts/check_doc_links.py` passes (files + heading anchors)
- [ ] Getting-started contract still green: `cargo test --test docs_first_run`
- [ ] Envelope / examples jq paths: `cargo test --test docs_cli_envelope`
- [ ] New harness/wrap claims match [guide/adapters.md](guide/adapters.md) detection table
- [ ] Docs site still builds: `bash scripts/prepare_docs_site.sh && mkdocs build --strict` (or docs.yml CI)
