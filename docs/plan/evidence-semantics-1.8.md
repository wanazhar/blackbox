# Blackbox 1.8 — Evidence Semantics & Forensic Rigor

| Field | Value |
|---|---|
| **Document** | Product + technical plan for 1.8 |
| **Date** | 2026-07-23 |
| **Status** | **In progress** — Phases A–D landed; E–F next |
| **Baseline** | 1.7 (agent boundary evidence & incidents) |
| **Target tag** | **1.8.0** |
| **Epic** | [Issue #6](https://github.com/wanazhar/blackbox/issues/6) |
| **North star** | Policy decisions and incident conclusions are as trustworthy as the underlying trace |

---

## Why 1.8 exists

| Version | Question answered |
|---|---|
| **1.0–1.2** | Capability, leave-on, project memory |
| **1.3–1.4** | Trust usable and provable on Unix |
| **1.5** | Trace remains correct at scale |
| **1.6** | Execution ≠ verification ≠ capture |
| **1.7** | What was the agent *allowed* to do, and what evidence supports that claim? |
| **1.8** | Can we *trust the interpretation* — selectors, findings, continuations, packs? |

1.7 shipped contracts, containment honesty, external evidence, detectors, incidents, and forensic packs. Several interpretation paths still rely on substring heuristics, collapsed confidence, and first-N pack selection. 1.8 hardens those paths without re-litigating capture or storage.

### Release contract

> Blackbox evaluates boundaries using canonical typed resources rather than substring heuristics; findings separate observation, policy, evidence integrity, confidence, and severity; incident continuation requires an explainable entity relationship; and forensic packs retain citation-complete salient evidence without risking structural corruption during redaction.

---

## 1.8 bar (exit criteria)

| Id | Criterion | Intent |
|---|---|---|
| **S1** | Typed resource selectors | Domain/URL/IP/CIDR/port/path/socket/identity/tool/effect matchers |
| **S2** | Canonical normalization | IDNA, case, trailing dots, IPs, paths; structured match reasons |
| **F1** | Calibrated findings | Separate observation, disposition, integrity, confidence, violation, severity |
| **F2** | Evidence-aware confidence | Unverified ≠ hash-verified ≠ signature-verified without override |
| **I1** | Typed incident continuation | Entity/path relation required; no “later event exists” shortcut |
| **P1** | Citation-complete packs | Head/tail + cited + signal + neighborhood + receipts |
| **P2** | Forensic scope accounting | Exact totals, included, truncated, strategy, unavailable citations |
| **R1** | Typed redaction | Free-form only; never mutate schema/IDs/enums/hashes/keys |
| **R2** | Correlatable secrets | Optional project-keyed HMAC; default unlinkable |
| **L1** | Vocabulary lint | Unknown core tokens warn/error; fail-closed errors |
| **L2** | Policy explain | Effective value, source layer, overrides, resolution trace |
| **B1** | Frozen detector benchmark | Versioned corpus separate from tuning fixtures |
| **O1** | Layered output contract | Observations vs facts vs correlations vs findings vs claims |
| **Q1** | Permanent gates | 1.4–1.7 gates remain green |

---

## Implementation phases

| Phase | Theme | Deliverables |
|---|---|---|
| **A** | Typed selectors + normalization | `ResourceSelector`, match explanations, contract dual-form entries | ✅ |
| **B** | Calibrated findings + evidence-aware detectors | `FindingDecision`, severity derivation, integrity classes | ✅ |
| **C** | Typed incident continuation | `ContinuationRelation` + cited conclusions | ✅ |
| **D** | Forensic packs | Citation-complete selection, scope object, typed redaction, HMAC tokens | ✅ |
| **E** | Lint / explain / vocab registry | `boundary lint`, `boundary explain`, fail-closed unknown tokens | |
| **F** | Frozen benchmark + layered views | Versioned corpus, API/UI layer labels, qualify | |

---

## Phase A scope (this sprint)

1. **`src/boundary/selector.rs`** — versioned selector kinds and structured match results.
2. **`src/boundary/normalize.rs`** — host/URL/IP/CIDR/path canonicalization; malformed → `unknown`.
3. **Contract compatibility** — `allowed.network` accepts legacy string tokens *or* typed selector objects; strings that look like hostnames match as exact domains (not substrings).
4. **Detector wiring** — destination authorization uses typed matchers; credential path detector distinguishes doc mentions from verified filesystem reads when integrity/action evidence exists.
5. **Finding decision object** — additive fields on findings; severity derived from disposition + integrity + correlation + effect.
6. **Incident continuation skeleton** — typed relation enum + conclusion object; graph no longer sets `continued_after_signal=true` from unrelated later activity alone.

Permanent gates and existing 1.7 tests must stay green (additive schema only where possible).

---

## Non-goals

- Replacing SIEM/EDR/enforcement platforms
- Hosted model inference
- Rewriting the 1.7 storage schema
- Silent baseline changes to detector quality thresholds
