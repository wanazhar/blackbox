# Roadmap and quality bar

What “good” means for blackbox, what each major version promised, what **1.4–1.6** shipped, and what **1.7** targets.

This is **product direction**, not a how-to. Operators: [guide/README.md](guide/README.md).
**1.7 (in progress):** [issue #5](https://github.com/wanazhar/blackbox/issues/5) — agent boundaries, containment evidence, incident reconstruction. Plan: [plan/agent-boundary-1.7.md](plan/agent-boundary-1.7.md).
**1.6 (shipped 1.6.0):** [issue #4](https://github.com/wanazhar/blackbox/issues/4) — verified runs, experiments, reproducibility, durable evidence.
**1.5 plan (shipped):** [plan/trace-integrity-1.5.md](plan/trace-integrity-1.5.md). Epic: [issue #3](https://github.com/wanazhar/blackbox/issues/3).
**1.4 plan (shipped):** [plan/trust-proof-1.4.md](plan/trust-proof-1.4.md).
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
| **1.4** | **Trust Proof (Unix 10/10)** | Shipped **1.4.0** |
| **1.5** | **Trace integrity & scale** | Shipped **1.5.0** — [issue #3](https://github.com/wanazhar/blackbox/issues/3) |
| **1.6** | **Verified runs & reproducibility** | Shipped **1.6.0** — [issue #4](https://github.com/wanazhar/blackbox/issues/4) |
| **1.7** | **Agent boundary evidence & incident reconstruction** | In progress — [issue #5](https://github.com/wanazhar/blackbox/issues/5) |

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
| **T1** | One-shot **fail** path | ✅ `blackbox fail` shipped in 1.3.0 |
| **T2** | One-shot **setup** path | ✅ `blackbox setup` shipped in 1.3.0 |
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
| **Q1** | Unix release qualify | ✅ `scripts/release-qualify-unix.sh` + CI trust gates + release.yml matrix |

#### 1.4 implementation phases

1. **A** Neutral and honest (nest markers, neutrality tests, coverage honesty) ✅
2. **B** Security proof (holdback redactor) ✅
3. **C** Causal precision + postmortem evidence ✅
4. **D** Unix runtime resilience (PTY fidelity, spawn storm, fault recovery) ✅
5. **E** Qualification + release gate ✅ GREEN qualification; shipped in 1.4.0

---

## 1.5 bar (must pass before tag)

Full plan: [plan/trace-integrity-1.5.md](plan/trace-integrity-1.5.md). Epic: [issue #3](https://github.com/wanazhar/blackbox/issues/3).

| Id | Criterion | Intent |
|---|---|---|
| **L1** | Long-run aggregates | Totals and first/last anchors independent of load caps |
| **L2** | Explicit analysis scope | `analysis_scope` on summary/postmortem |
| **D1** | Safe tool dedupe | ID-less retries preserved; merge only proven duplicates |
| **R1** | Replay honesty | Workspace vs contained; capability preflight |
| **W1** | Workspace checkpoints | Binary/untracked restore + completeness |
| **A1** | Archive atomicity | Hash-validated import; no partial permanent state |
| **S1** | Batched ingest | Bounded queue + dedicated writer |
| **C1** | Capture boundaries | Bounded FS/native-log; symlink scope |
| **H1** | Dashboard auth | Browser session + bearer + optional UDS |
| **P1** | Scale APIs | Cursor pagination, compression, streaming portable |
| **Q1** | Tier-1 qualification | Linux + macOS runtime gates |
| **X1** | Docs truth | Inventory, one source of truth, verified examples |

#### 1.5 implementation phases

1. **A** Correct long-run truth (aggregates, analysis_scope, safe dedupe) — done
2. **B** Reproducible / contained replay — done (workspace + optional `--contained` bwrap)
3. **C** Durable storage / imports — done (atomic portable, batch ingest, portable-dir)
4. **D** Capture / platform operations — done (FS/native-log bounds, dashboard auth, macOS CI)
5. **E** Documentation rewrite + release — inventory/claims/gates done; tag after full qualify

---

## After 1.5 (direction)

| Theme | Notes |
|---|---|
| Eval suite | Multi-run report CLI, regression tables, public scorer recipes |
| Agent-native depth | Marketplace plugins, require-memory-read experiments, richer MCP |
| Distribution | Homebrew/Nix formulas |
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

- [plan/agent-boundary-1.7.md](plan/agent-boundary-1.7.md) — 1.7 design (in progress)
- [plan/trace-integrity-1.5.md](plan/trace-integrity-1.5.md) — full 1.5 design
- [plan/trust-proof-1.4.md](plan/trust-proof-1.4.md) — 1.4 design (shipped)
- [plan/trust-explain-1.3.md](plan/trust-explain-1.3.md) — 1.3 design (shipped)
- [CHANGELOG.md](https://github.com/wanazhar/blackbox/blob/master/CHANGELOG.md)
- [guide/concepts.md](guide/concepts.md)
- [WRITING.md](WRITING.md)
- Historical: [plan/adoption-1.1.md](plan/adoption-1.1.md), [plan/agent-memory-bus-1.2.md](plan/agent-memory-bus-1.2.md)

---

## 1.6 bar (shipped in 1.6.0)

Epic: [issue #4](https://github.com/wanazhar/blackbox/issues/4).

| Area | Requirement | Tests / gate |
|---|---|---|
| Integrity A | Symlink-safe manifests, restore fidelity, portable v2 refs, SQL filters, aggregates | `workspace_symlink_safety`, `restore_fidelity`, `portable_v2_references`, `pagination_filtered_scale`, `aggregate_semantics`, `blob_reference_rewrite` |
| Store B | `fsck` fast/deep/repair; durable spool recovery | `fsck_corruption`, `ingest_spool_recovery` |
| Verify C | Execution ≠ verification ≠ capture; immutable receipts | `verification_receipts` |
| Experiments D | Typed metadata; honest reports; fail-closed gates | `experiment_reports`, `regression_gate` |
| Capsules E | Completeness classes; no deterministic model claim | `capsule_integrity` |
| Cassette E | Experimental MCP proxy; mock/live marking | `mcp_cassette` |
| Ops F | Budget capability honesty; adapter protocol; project index | `budget_enforcement_linux`, `adapter_conformance`, `multi_project_index` |
| Endurance L | ≥100k events; aggregates; pagination; fsck deep | `endurance_100k` (`--ignored`) via `scripts/release-qualify-unix.sh` |

Operator guides: [fsck](guide/fsck-and-integrity.md), [verification](guide/verification.md), [experiments](guide/experiments.md), [capsules](guide/capsules-and-cassettes.md), [budgets](guide/budgets-and-adapters.md). Claims: [claims.md](claims.md).

---

## 1.7 bar (in progress)

Epic: [issue #5](https://github.com/wanazhar/blackbox/issues/5). Plan: [plan/agent-boundary-1.7.md](plan/agent-boundary-1.7.md).

| Id | Criterion | Intent / status |
|---|---|---|
| **B1** | Resolved boundary contract | ✅ `blackbox.boundary/v1` + policy hash (`run_boundaries`) |
| **B2** | Containment honesty | ✅ Claim states + immutable receipts |
| **B3** | Required evidence | ✅ `insufficient_evidence` / fail-closed gate |
| **E1** | External evidence import | ✅ `blackbox.evidence.event/v1` NDJSON; transactional; path-safe |
| **E2** | Correlation identity | ✅ Trace identity + multi-signal edges; temporal ≠ confirmed |
| **V1** | Boundary violations | ✅ Deterministic detectors → findings / `boundary.violation` events |
| **P1** | Provenance gates | ✅ Task success independent of provenance validity |
| **I1** | Multi-run incidents | ✅ Incident object + graph (discovery, reuse, earliest signal) |
| **F1** | Forensic packs | ✅ Bounded redacted packs with validated citations |
| **Q1** | Adversarial qualification | ✅ Fixtures + `tests/boundary_1_7_full.rs` |

Reference: [reference/boundary.md](reference/boundary.md). CLI: `boundary`, `evidence`, `incident`, `forensic`.
