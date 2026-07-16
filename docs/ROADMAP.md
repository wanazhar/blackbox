# Roadmap and quality bar

**Answers:** What “good” means for blackbox, what each major version promised, and what remains intentionally out of scope.

This is **product direction**, not a how-to. Operators: [guide/README.md](guide/README.md). Design archives: [plan/](plan/) (historical).

---

## Quality bar (in plain terms)

Blackbox is worth leaving on a machine that holds secrets only if **all** of the following hold:

| # | Bar | Operator meaning |
|---|---|---|
| 1 | **Redact before write** | Secrets are scrubbed before SQLite/blobs unless you pass danger flags |
| 2 | **True timeline** | One sequencer; order matches capture order |
| 3 | **Payloads as blobs** | Large content is content-addressed; events stay small |
| 4 | **Honest checkpoints** | End-of-run git/fs state is *after*, not a copy of *before* |
| 5 | **Crash recovery** | Abandoned `Running` rows become `Failed` on next open |
| 6 | **Project-local store** | `.blackbox/` by default; overridable |
| 7 | **Semantic signal** | Adapters + analysis, not only raw text |
| 8 | **Safe share defaults** | Export/sync redact unless `--no-redact` |
| 9 | **Docs match binary** | README/guides/tests describe real behavior |
| 10 | **Agent-native inspect** | `--json`, handoff, MCP, resume packs |

If a change weakens a bar, it needs an explicit docs + test story.

---

## Versions (shipped story)

| Version | Story | Operator takeaway |
|---|---|---|
| **1.0** | Capability daily-driver | Capture, inspect, export, MCP, resume basics |
| **1.1** | Adoption (“leave it on”) | Ambient contract, redaction gates, adapters, CI/eval, cost visibility |
| **1.2** | Continuity / project memory | MEMORY pack, attention, claims, inject on explicit run |

### 1.1 adoption bar (permanent)

| Id | Criterion | How we keep it honest |
|---|---|---|
| A1 | Ambient shell contract | `tests/ambient_contract.rs` · [ambient-contract.md](ambient-contract.md) |
| A2 | Redaction regression | `tests/redaction_gate.rs` (+ adversarial) |
| A3 | Resume-pack quality | postmortem/handoff tests · memory quality |
| A4 | Cost visibility | `doctor` / `stats` · [guide/overhead.md](guide/overhead.md) |
| A5 | Docs match reality | link checker · first-run golden · this tree |
| A6 | Capture overhead smoke | `tests/overhead_smoke.rs` |
| A7 | Broader adapters | aider/gemini/cursor/opencode/grok detection |

### 1.2 memory bar (permanent)

| Id | Criterion | How we keep it honest |
|---|---|---|
| M1 | Materialize + inject on launch paths | continuity modes · observe-only split |
| M2a | Pack structural quality | `tests/memory_pack_quality.rs` |
| M3 | Side effects surface | pack fields + analysis |
| M4 | Claims MVP | project + path-scoped claims |
| M5 | Sessions disposable | degraded sticky-only pack |
| M6 | Silent failure discipline | success does not clear unresolved failure |
| M7 | Trust on MEMORY paths | redaction + doctor fields |

Historical design prose: [plan/adoption-1.1.md](plan/adoption-1.1.md), [plan/agent-memory-bus-1.2.md](plan/agent-memory-bus-1.2.md).

---

## Post-1.2 themes (already partly landed)

Work continues in-tree beyond the original 1.2 checklist, including:

- Anomaly markers + failure-story TUI / dashboard badges
- Eval harness (`--eval`) and richer CI artifacts
- Sealed export packs, blob encryption, offline `backup`/`restore`
- Docs revamp for human comprehension (this directory)
- Path-scoped claims (operator-usable; was backlog)

See [CHANGELOG.md](../CHANGELOG.md) for what actually shipped.

---

## Backlog (direction, not commitments)

| Priority | Theme | Notes |
|---|---|---|
| Med | Docs depth / fixtures | Golden CLI outputs, more recipe coverage |
| Low | Auto open_items from TODO/FIXME | Explicit memory remains source of truth |
| Low | Sandbox conflict UX | Best-effort git apply exists |
| Low | Windows interactive TUI parity | Kill + PowerShell install shipped; PTY edges remain |
| Low | Per-harness session format notes | Pollers exist; vendor layouts stabilize slowly |
| Low | Live SQLCipher | **Not** planned as default; vault path is sealed backup + blob encrypt |

---

## Non-goals

- Multi-tenant hosted SaaS / remote multi-user ACLs
- Replacing the harness’s own UI
- Perfect Windows parity as a release blocker
- Guaranteeing every interactive TUI agent emits machine-readable tool events
- Inventing `estimated_cost_usd` when estimation is off or model unknown
- Deterministic full LLM re-execution as “replay”

---

## Related

- [CHANGELOG.md](../CHANGELOG.md)  
- [guide/concepts.md](guide/concepts.md)  
- [WRITING.md](WRITING.md)  
