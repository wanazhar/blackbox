# Blackbox 1.9 — Evidence Protocol & Embeddability

| Field | Value |
|---|---|
| **Document** | Product + technical plan for 1.9 |
| **Date** | 2026-07-23 |
| **Status** | **Implementation under qualification** — phases A–G landed; tag pending green release gates |
| **Baseline** | 1.8.0 (evidence semantics & forensic rigor) |
| **Target tag** | **1.9.0** |
| **Epic** | [Issue #7](https://github.com/wanazhar/blackbox/issues/7) |
| **North star** | Agent harnesses emit, validate, store, and export Blackbox-compatible evidence natively without process wrapping |

---

## Why 1.9 exists

| Version | Question answered |
|---|---|
| **1.0–1.2** | Capability, leave-on, project memory |
| **1.3–1.4** | Trust usable and provable on Unix |
| **1.5** | Trace remains correct at scale |
| **1.6** | Execution ≠ verification ≠ capture |
| **1.7** | What was the agent *allowed* to do? |
| **1.8** | Can we *trust the interpretation*? |
| **1.9** | Can harnesses *speak Blackbox natively* without wrapping? |

1.8 hardened interpretation. 1.9 makes the evidence surface embeddable and
interoperable while preserving a **single published Crates.io package**.

### Release contract

> Agent harnesses can emit, validate, store, and export Blackbox-compatible
> evidence natively without requiring process wrapping, while preserving the
> same integrity, boundary, receipt, citation, and forensic semantics as the
> reference recorder. Blackbox remains one published Crates.io package; internal
> modularization must not create a multi-package maintenance burden.

---

## Packaging constraint

- `blackbox-recorder` remains the only required published Crates.io package.
- No requirement to publish separate `blackbox-*` crates.
- Internal modularization uses modules (and optional private workspace crates
  with `publish = false` only if needed).
- A standalone protocol crate is deferred until external demand is demonstrated.

---

## 1.9 bar (exit criteria)

| Id | Criterion | Intent |
|---|---|---|
| **P1** | Independent protocol schemas | Schemas exist under `/spec` independent of Rust structs |
| **P2** | Canonical form + hashes | Documented rules; test vectors; dual-encoder identity |
| **P3** | Schema validation in CI | Rust serialization validates against published schemas |
| **N1** | Native ingestion API | start/record/finish without PTY or `blackbox run` |
| **N2** | Transports | In-process, Unix socket, bounded NDJSON; idempotent |
| **S1** | Security decision receipts | `blackbox.security.decision/v1` with integrity/provenance |
| **S2** | Action↔effect reconciliation | Typed outcomes with cited evidence |
| **C1** | Evidence commitments | Per-event hash chain + run root; optional Ed25519 |
| **O1** | OTLP interop | Export/import with explicit loss ledger |
| **F1** | Conformance runner | Core/Recorder/Boundary/Forensic public suite |
| **I1** | Reference integration | One native harness path with coverage declaration |
| **A1** | Architecture boundaries | Storage/CLI types do not leak into protocol APIs |
| **Q1** | Permanent gates | 1.4–1.8 gates remain green |

---

## Implementation phases

| Phase | Theme | Deliverables |
|---|---|---|
| **A** | Protocol boundary + canonical form | `/spec`, `/test-vectors`, `src/protocol`, stability inventory, CI |
| **B** | Native ingestion + modularity | `NativeRecorder`, NDJSON + Unix socket, module boundaries |
| **C** | Security decisions + reconciliation | decision schema, action fingerprints, typed outcomes |
| **D** | Evidence commitments | event hashes, run chain, optional signatures |
| **E** | OTLP interop | export map, import transform, loss ledger |
| **F** | Conformance + first integration | `blackbox conform`, reference hooks adapter |
| **G** | Release hardening | fuzz/property tests, docs, qualify inputs |

---

## Non-goals

- Publishing multiple public Crates.io packages
- Hosted SaaS
- Full active enforcement engine
- More dashboards / collaborative incident UI
- Large detector-rule expansion
- Autonomous remediation
- Replacing OpenTelemetry
- Supporting every harness in one release
- Blockchain / public-ledger anchoring

---

## Integrity honesty

Commitments prove **record consistency after commitment**, not completeness of
observation or truth of what occurred outside the recorder's view.
