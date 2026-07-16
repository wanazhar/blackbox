# Concepts

**Answers:** How the moving parts fit together once you know the one-paragraph product pitch. For definitions only, see [glossary](glossary.md). For “what is blackbox?”, see [what-is-blackbox](what-is-blackbox.md).

This page is for a technical reader who wants the **system model**, not a flag list.

---

## 1. Three planes

| Plane | Job | Primary surfaces |
|---|---|---|
| **Capture** | Supervise a process; emit ordered events; redact; persist | `run`, `maybe-run`, layers, adapters, store |
| **Inspect** | Explain and navigate what was captured | `show`, `timeline`, TUI, `serve`, `postmortem`, `diff`, `search` |
| **Continuity** | Sticky project intent + bounded memory for the *next* launch | `state.json`, MEMORY, `handoff`, claims, inject |

Ambient capture uses **capture only** (observe-only). Explicit `blackbox run` can use **capture + continuity** when configured.

```
                 ┌────────── ambient wrappers ──────────┐
                 │  maybe-run → record | passthrough      │
                 └──────────────────┬───────────────────┘
                                    │ observe-only
  blackbox run ─────────────────────┼──────────────────► EventWriter → store
         │                          │
         │ continuity inject?       ▼
         │                   inspect (CLI/TUI/serve)
         ▼
   MEMORY / env / preamble     handoff / status / claims
```

---

## 2. Ordering truth

All producers (PTY, git, fs, process, analysis) merge into one stream. **`EventWriter`** assigns monotonic **`sequence`** numbers at persist time. Timeline order is capture order, not “best effort sort later.”

Implications:

- Evidence links that say `seq=42` are stable handles within a run
- Diff/trajectory compare semantic sequences across two runs
- Bookkeeping events still consume sequence numbers even when UIs hide them

Implementation: [../internals/capture-pipeline.md](../internals/capture-pipeline.md).

---

## 3. Events vs blobs

| Piece | Holds | Why |
|---|---|---|
| **TraceEvent** | kind, source, status, small metadata, blob **keys** | Queryable, FTS-indexable, cheap to list |
| **Blob** | Large payload by content hash | Dedup, streaming write, optional encrypt |

Redaction happens **before** blob/event write on the happy path. Export re-scans so share path does not resurrect old raw secrets casually.

---

## 4. Semantic signal vs raw terminal

| Layer | Role |
|---|---|
| Raw PTY | Honest bytes (normalized/redacted) |
| Adapter parse | Lift `tool.call` / `tool.result` / session / usage when patterns match |
| Analysis | Errors, side effects, correlations, anomalies, postmortem narrative |

If an adapter misses a tool call, the terminal timeline still exists. Postmortem quality tracks capture quality — see coverage events and `doctor` notes.

---

## 5. Sticky state and attention

Sticky file: `.blackbox/state.json` (may be sealed). Holds intent, claims, unresolved failure, attention, memory timestamps.

| Attention | Operator meaning |
|---|---|
| `none` | No sticky pressure |
| `info` | Heads-up (e.g. dirty tree) |
| `continue` | Prior failure/WIP expects follow-up |
| `blocked` | Strong stop (e.g. gate) |

**M6 discipline:** an unrelated successful run does **not** clear an unresolved failure. Clear with `blackbox resolve`.

---

## 6. Project memory pack

Bounded document `blackbox.memory/v1` written to `MEMORY.md` / `MEMORY.json` (and RESUME copies). Built from store + sticky with a **token budget** and shrink order (headline/next never dropped first).

| Delivery | Happens? |
|---|---|
| End of run refresh | When continuity ≠ `off` |
| Inject on next explicit run | When continuity allows and not observe-only |
| Ambient wrap | Never injects |

Honesty: delivery ≠ the model reading it. Schema: [../reference/memory-pack.md](../reference/memory-pack.md).

---

## 7. Claims

Coordination primitive under `state.lock`:

- **Project claim** — exclusive whole-tree
- **Path-scoped claim** — non-overlapping path prefixes can coexist

Not a distributed lock service; same-machine / cooperative agents. See CLI `claim` and MCP `blackbox_claim`.

---

## 8. Product modes (recorder vs continuity)

| Mode | Mutates launch? | Typical enable |
|---|---|---|
| Recorder / observe-only | No | Ambient default; `--observe-only`; `--eval` |
| Continuity | May inject | `--memory-bus` / `continuity=always\|attention` |

Do not conflate “recording is on” with “memory is injected.” Details: [configuration](configuration.md#3-product-modes-recorder-vs-continuity).

---

## 9. Trust boundaries (short)

| Boundary | Default stance |
|---|---|
| Redaction | On; danger flags opt-out |
| Multi-UID | Owner-only modes on store paths |
| Same-UID / disk theft | Optional encrypt_blobs + sealed backup |
| Serve | Loopback warning; non-loopback requires token |
| Export/sync | Redacted |

Full model: [security](security.md).

---

## 10. Reading path

| Goal | Order |
|---|---|
| Use it tomorrow | [install](install.md) → [getting-started](getting-started.md) → [recipes](recipes.md) |
| Debug failures well | [debug-a-failure](debug-a-failure.md) → [everyday-use](everyday-use.md) |
| Leave ambient on | [leave-it-on](leave-it-on.md) → [configuration](configuration.md) |
| Automate | [json-api](../reference/json-api.md) → [mcp](../reference/mcp.md) → skill |
| Change code | [architecture](../internals/architecture.md) → capture/storage/continuity internals |

Quality bar / version story: [../ROADMAP.md](../ROADMAP.md).
