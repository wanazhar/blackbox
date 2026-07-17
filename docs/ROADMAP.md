# Roadmap and quality bar

**Answers:** What “good” means for blackbox, what each major version promised, what **1.4** will add, and what remains out of scope.

This is **product direction**, not a how-to. Operators: [guide/README.md](guide/README.md).  
**1.4 plan (active):** [plan/trust-proof-1.4.md](plan/trust-proof-1.4.md).  
**1.3 plan (shipped):** [plan/trust-explain-1.3.md](plan/trust-explain-1.3.md).

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

## Versions

| Version | Story | Status |
|---|---|---|
| **1.0** | Capability daily-driver | Shipped |
| **1.1** | Adoption (“leave it on”) | Shipped |
| **1.2** | Continuity / project memory | Shipped **1.2.0** |
| **1.3** | Trust, explain, agent-native depth | Shipped **1.3.0** |
| **1.4** | **Trust Proof (Unix 10/10)** | **In progress — do not tag yet** |

### 1.1 adoption bar (permanent)

| Id | Criterion | How we keep it honest |
|---|---|---|
| A1 | Ambient shell contract | `tests/ambient_contract.rs` · [ambient-contract.md](ambient-contract.md) |
| A2 | Redaction regression | `tests/redaction_gate.rs` (+ adversarial) |
| A3 | Resume-pack quality | postmortem/handoff · memory quality |
| A4 | Cost visibility | `doctor` / `stats` · [guide/overhead.md](guide/overhead.md) |
| A5 | Docs match reality | link checker · docs goldens |
| A6 | Capture overhead smoke | `tests/overhead_smoke.rs` |
| A7 | Broader adapters | multi-harness detection |

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

### 1.3 bar (must pass before tag)

Full plan: [plan/trust-explain-1.3.md](plan/trust-explain-1.3.md).

| Id | Criterion | Intent |
|---|---|---|
| **T1** | One-shot **fail** path | ✅ `blackbox fail` shipped (unreleased) |
| **T2** | One-shot **setup** path | ✅ `blackbox setup` shipped (unreleased) |
| **T3** | MCP **timeline + anomalies** | ✅ `blackbox_timeline` / `blackbox_anomalies` / `blackbox_fail` |
| **T4** | Eval **score.json** (`blackbox.score/v1`) + CI action shape | ✅ `score.json` + `.github/actions/blackbox-eval` |
| **T5** | **Harden** project profile | ✅ `setup`/`enable --harden` + security docs |
| **T6** | **Adapter drought** honesty | ✅ coverage + `capture.warning` + doctor |
| **T7** | Optional **ambient notice** | ✅ `ambient_notice` default off; A1 quiet |
| **T8** | **Release gate** | ✅ **1.3.0** published (crates.io; local tag) |

---

## 1.4 bar (must pass before tag)

Full plan: [plan/trust-proof-1.4.md](plan/trust-proof-1.4.md). Epic: [issue #2](https://github.com/wanazhar/blackbox/issues/2).

| Id | Criterion | Intent |
|---|---|---|
| **N1** | Hard recorder neutrality | No child-visible nest-guard env; argv/cwd/user env unchanged |
| **N2** | Neutrality contract | `tests/neutrality_contract.rs` direct vs recorded |
| **C1** | Coverage `not_applicable` | Non-git / inapplicable native logs excluded from score |
| **C2** | Process completeness | Lifecycle signals required for `complete` |
| **C3** | Score contributions | Coverage JSON exposes weighted math |
| **S1** | Holdback redaction | ✅ Holdback stream + split corpus + store scan (Phase B) |
| **G1** | Causal confidence | ✅ fingerprints + edges; `confirmed` needs matching verification (Phase C) |
| **Q1** | Unix release qualify | `scripts/release-qualify-unix.sh` + matrix (Phase E) |

#### 1.4 implementation phases

1. **A** Neutral and honest (nest markers, neutrality tests, coverage honesty)  
2. **B** Security proof (holdback redactor)  
3. **C** Causal precision + postmortem evidence  
4. **D** Unix runtime resilience  
5. **E** Qualification + release gate  

---

## After 1.4 (direction)

| Theme | Notes |
|---|---|
| **1.5 Eval suite** | Multi-run report CLI, regression tables, public scorer recipes |
| Agent-native depth | Marketplace plugins, require-memory-read experiments, richer MCP |
| Distribution | Homebrew/Nix formulas |
| Scale | SSE push, huge-run paging polish |
| Windows | TUI/PTY parity (non-blocking) |

---

## Non-goals (standing)

- Multi-tenant hosted SaaS / remote multi-user ACLs  
- Replacing the harness’s own session UI  
- Perfect Windows parity as a release blocker  
- Guaranteeing every interactive TUI agent emits machine-readable tool events  
- Inventing `estimated_cost_usd` when estimation is off or model unknown  
- Deterministic full LLM re-execution as “replay”  
- Live SQLCipher as default store encryption  

---

## Related

- [plan/trust-proof-1.4.md](plan/trust-proof-1.4.md) — full 1.4 design  
- [plan/trust-explain-1.3.md](plan/trust-explain-1.3.md) — 1.3 design (shipped)  
- [CHANGELOG.md](https://github.com/wanazhar/blackbox/blob/master/CHANGELOG.md)  
- [guide/concepts.md](guide/concepts.md)  
- [WRITING.md](WRITING.md)  
- Historical: [plan/adoption-1.1.md](plan/adoption-1.1.md), [plan/agent-memory-bus-1.2.md](plan/agent-memory-bus-1.2.md)  
