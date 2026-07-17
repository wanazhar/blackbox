# Blackbox 1.4 — Trust Proof (Unix 10/10 daily driver)

| Field | Value |
|---|---|
| **Document** | Product + technical plan for 1.4 |
| **Date** | 2026-07-17 |
| **Status** | **In progress** — Phase A done; Phase B (security proof) in train |
| **Baseline** | 1.3.0 (trust & explain shipped) |
| **Target tag** | **1.4.0** |
| **Epic** | [Issue #2](https://github.com/wanazhar/blackbox/issues/2) |
| **North star** | Leave recorder mode on Unix without changing the child, without recoverable secrets, with evidence-linked conclusions |

---

## Why 1.4 exists

| Version | Question answered |
|---|---|
| **1.0–1.2** | Capability, leave-on, project memory |
| **1.3** | When it fails, get a story and jump target fast |
| **1.4** | Can we **prove** neutrality, redaction, causality, and release qualification on Unix? |

1.3 made trust *usable*. 1.4 makes trust *provable*: hard recorder neutrality, adversarial secret holdback, causal confidence policy, context-aware coverage, and a reproducible Unix release gate.

### Platform policy

- **Tier 1:** Linux x86_64 / ARM64; macOS Apple Silicon / x86_64 where practical
- **Tier 2:** other POSIX-like systems with the portable backend
- **Out of scope:** Windows (PTY/ETW/Job Objects/packaging)

---

## Product principles (normative)

| Id | Principle |
|---|---|
| **P1** | Recorder mode is passive — no silent argv/env/cwd/prompt/session mutation |
| **P2** | Claims ≤ evidence — confidence: `confirmed` / `strongly_correlated` / `weakly_correlated` / `unknown` |
| **P3** | Redaction protects **stored** artifacts (SQLite/WAL/blobs/exports/memory), not only returned strings |
| **P4** | Unknown stays unknown — disabled / unavailable / failed / not_applicable / partial / complete |
| **P5** | Unix-first architecture — PTY, signals, process groups, `/proc` / libproc, atomic rename |

---

## 1.4 bar (exit criteria)

| Id | Criterion | Intent |
|---|---|---|
| **N1** | Hard recorder neutrality | No child-visible `BLACKBOX_*` inject; argv/cwd/user env unchanged; nest still works |
| **N2** | Neutrality contract tests | `tests/neutrality_contract.rs` direct vs recorded |
| **C1** | Coverage `not_applicable` | Non-git / generic native-logs do not penalize quality |
| **C2** | Process completeness | Not “complete” from mere event count; lifecycle signals required |
| **C3** | Score contributions | Coverage JSON explains weighted math |
| **S1** | Holdback stream redaction | Split-position corpus; store-level scan |
| **G1** | Causal graph + fingerprints | `confirmed` requires exact verification evidence |
| **P1a** | Postmortem evidence links | Material claims carry confidence + event refs |
| **R1** | Unix runtime resilience | PTY fidelity, spawn storm, fault injection (phase D) |
| **Q1** | Release qualify | `scripts/release-qualify-unix.sh` + Linux/macOS CI matrix |

A1–A7, M1–M7, T1–T8 remain permanent.

---

## Workstreams (summary)

Full acceptance criteria live in [issue #2](https://github.com/wanazhar/blackbox/issues/2).

| WS | Theme | Phase |
|---|---|---|
| 1 | Hard neutrality contract | **A** |
| 2 | Evidence-based causal graph | C |
| 3 | Zero recoverable secret persistence | B |
| 4 | Context-aware capture coverage | **A** |
| 5 | Unix terminal fidelity | D |
| 6 | Stronger process observation | D |
| 7–9 | Fault injection, drops, reconciliation | D |
| 10 | Evidence-first postmortem | C |
| 11 | Permissions / packaging | B / E |
| 12 | CI and release gates | E |
| 13 | Migrations / compat | C / E |

---

## Implementation phases

### Phase A — Neutral and honest (this train)

- [x] Plan + roadmap for 1.4
- [x] Remove child-visible nest-guard env mutation (supervisor PID markers)
- [x] Strip `BLACKBOX_*` from recorder-mode children
- [x] Direct-vs-recorded neutrality contract tests (`tests/neutrality_contract.rs`)
- [x] `not_applicable` coverage + score contributions
- [x] Tighter process completeness criteria
- [x] Docs: exact recorder guarantees (ambient contract, leave-it-on, doctor, changelog)

**Exit:** Blackbox can truthfully claim hard recorder-mode neutrality on supported Unix systems (documented PTY differences only). **Met for Phase A on Linux.**

### Phase B — Security proof

- [x] Holdback stream redactor (no early secret fragments)
- [x] Exhaustive split-position corpus (`tests/redaction_adversarial.rs`)
- [x] Store-level SQLite/WAL/blob scan (`redaction::store_scan` + `tests/redaction_store_scan.rs`)
- [x] Wire holdback flush into PTY path; native-log line redact before parse
- [x] Security docs: holdback vs physical erase honesty
- [ ] Broader permission/key-rotation integration hardening (remainder → WS11 / Phase E)

**Exit:** No adversarial fixture or meaningful fragment survives supported persistence paths under default redaction. **Met for stream/store path on Linux.**

### Phase C — Causal precision

Command fingerprints, tool call/result links, causal edges, verification coverage, postmortem confidence.

### Phase D — Unix runtime resilience

PTY matrix, spawn storm, macOS process backend, fault injection, drop accounting.

### Phase E — Qualification

Release benchmarks, harness matrix, Linux/macOS CI, `release-qualify-unix.sh`.

---

## Non-goals (standing for 1.4)

- Windows support  
- Deterministic LLM replay  
- Full TLS interception  
- Hosted SaaS  
- Physical secure erase on SSD/COW  

---

## Related

- Epic: https://github.com/wanazhar/blackbox/issues/2  
- Prior: [trust-explain-1.3.md](trust-explain-1.3.md), [agent-memory-bus-1.2.md](agent-memory-bus-1.2.md), [adoption-1.1.md](adoption-1.1.md)  
- Ambient: [ambient-contract.md](../ambient-contract.md)  
- Roadmap: [ROADMAP.md](../ROADMAP.md)  
