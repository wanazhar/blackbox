# Glossary

Precise meanings of blackbox terms used across guides and CLI. Prefer these words in docs and issue reports.

Writing rules: [../WRITING.md](../WRITING.md). Mental model: [what-is-blackbox.md](what-is-blackbox.md).

---

| Term | Meaning |
|---|---|
| **ambient capture** | Shell wrappers call `maybe-run`, which records matching harness basenames when policy allows. Always **observe-only** (no continuity inject). |
| **anomaly** | Deterministic marker on a run (tool loop, destructive side effect, error storm, token spike, long silence, process fan-out). Not an LLM judgment. |
| **boundary contract** | Machine-readable authorization for a run (`blackbox.boundary/v1`): allowed/prohibited capabilities, required evidence, fail-closed flag. |
| **boundary trust** | Rollup on summary/score: policy hash, evidence gate, provenance gate, findings, containment honesty. |
| **containment receipt** | Immutable claim about a control (`configured` / `enforced` / `verified` / …). Configured ≠ verified. |
| **external evidence** | Imported telemetry (`blackbox.evidence.event/v1`) from proxy/process/cloud sensors; not Blackbox’s own capture layers. |
| **forensic pack** | Bounded, redacted analysis shard with evidence citations for offline/local models. |
| **incident** | Multi-run reconstruction object (discovery, reuse, earliest signal); not a SIEM case management system. |
| **attention** | Sticky level after outcomes: typically `none` / `continue` / `blocked`. Unrelated success does not clear an unresolved failure. |
| **blob** | Content-addressed payload under `.blackbox/blobs/` (terminal chunks, tool I/O, diffs, …). Events hold keys + previews. |
| **bookkeeping** | Low-signal observer lifecycle events (`pty.started`, `*.observer.stopped`, …). Semantic views hide these. |
| **budget** | Optional execution ceilings (wall, processes, output bytes, tool calls, memory, …) with per-limit capability class. |
| **capsule** | Reproducibility package (portable archive + completeness class). Not deterministic model replay. |
| **cassette** | Experimental MCP stdio record/replay file (proxied tools only). |
| **claim** | Coordination lock: whole-project exclusive or **path-scoped** non-overlapping trees. Held in sticky state under `state.lock`. |
| **config fingerprint** | Stable hash of experiment knobs (variant/task/role/model/…) shared across attempts. |
| **continuity** | Config-driven delivery of **project memory** on explicit `blackbox run` (`always` / `attention` / `off`). Not ambient. |
| **domain match** | How tightly a verification receipt correlates to a prior failure/scope (`confirmed` … `unknown`). |
| **envelope** | `--json` wrapper `blackbox.cli/v1` (`ok`, `command`, `data`, …). See [json-api](../reference/json-api.md). |
| **experiment** | Typed cohort metadata linking runs (task/variant/attempt/role) for reports and gates. |
| **fsck** | Store integrity check (fast/deep) with optional auto-safe repair. |
| **evidence** | Postmortem anchor: detail plus optional `event_id` / `sequence` pointing into the timeline. |
| **EventWriter** | Single sequencer that assigns monotonic `sequence` numbers as events persist. |
| **gate / require_ack** | Explicit-run control: warn or require `blackbox ack` / `BLACKBOX_ACK=1` before recording. |
| **handoff** | Status + project memory (+ resume material when attention warrants) for the next human or agent. |
| **harness / adapter** | Agent CLI (claude, codex, …) plus parser that lifts tool calls from PTY/native logs into structured events. |
| **inject** | Writing memory paths/env/preamble into a supervised launch. Requires non-observe-only explicit run. |
| **maybe-run** | Policy binary behind ambient wrappers: passthrough or record. Never opens the store on passthrough. |
| **observe-only** | Record without mutating argv/prompt/env for continuity. Forced for ambient, `--observe-only`, `--eval`. |
| **postmortem** | Structured run summary: headline, next_action, evidence, anomalies, narrative, … Deterministic analysis. |
| **product mode** | Coarse label: **recorder** (observe-only) vs **continuity** (memory inject allowed on explicit run). |
| **project memory** | Bounded pack (`MEMORY.md` / `MEMORY.json`, schema `blackbox.memory/v1`) rebuilt after runs when continuity ≠ off. |
| **PTY** | Pseudo-terminal under which the supervised command runs; primary terminal capture surface. |
| **redaction** | Secret scrubbing before write / on export-sync. Replacement `[REDACTED]`. Not perfect; see [security](security.md). |
| **run** | One supervised invocation with UUID, command, cwd, status, exit code, tags, timestamps. |
| **scrub** | Re-apply current secret patterns to historical events; optional blob GC. |
| **sealed pack / backup** | Encrypted envelope for portable export or whole-store vault (`backup`/`restore`). Prefer passphrase. |
| **semantic timeline** | Event list with bookkeeping filtered out. |
| **sequence / seq** | Monotonic index of an event within a run (`seq=42` in TUI/CLI). |
| **sticky state** | `state.json`: attention, claims, intent, unresolved failure, … May be sealed at rest. |
| **spool** | Durable ingest journal under `.blackbox/spool/` for crash recovery of batches. |
| **store** | Project `.blackbox/` tree: SQLite + blobs + config + sticky/memory files. |
| **TraceEvent** | Ordered event record: kind, source, status, metadata, optional blob refs. |
| **trajectory / LCP** | Compare two runs: shared semantic prefix, first divergence, exclusive steps, file hints. |
| **verification receipt** | Immutable evidence that a check ran (`verify`); separate from `Run.status`. |
| **provenance record** | Declared vs observed artifact/answer sources; can fail independently of task success. |
| **wrap list** | `capture.wrap` basenames eligible for ambient recording. |

---

## Acronyms and IDs (reference only)

| ID | Context |
|---|---|
| **FTS5** | SQLite full-text search used by `blackbox search` |
| **MCP** | Model Context Protocol server (`blackbox mcp`) |
| **A1 / M2a / …** | Historical design gates in plan docs — not required for operators |

---

## See also

- [configuration.md](configuration.md) — knobs that implement these concepts  
- [debug-a-failure.md](debug-a-failure.md) — postmortem / anomaly workflow  
- [leave-it-on.md](leave-it-on.md) — ambient capture  
