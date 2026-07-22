# Blackbox 1.7 — Agent Boundary Evidence & Incident Reconstruction

| Field | Value |
|---|---|
| **Document** | Product + technical plan for 1.7 |
| **Date** | 2026-07-22 |
| **Status** | **Gap closure in progress** — issue #5 Definition of Done audit found missing Phase C/F/I coverage |
| **Baseline** | 1.6.0 (verified runs & reproducibility) |
| **Target tag** | **1.7.0** |
| **Epic** | [Issue #5](https://github.com/wanazhar/blackbox/issues/5) |
| **North star** | Record authorization, distinguish configured vs verified containment, detect boundary crossings, and reconstruct multi-run incidents without pretending to be a SIEM or enforcement platform |

---

## Why 1.7 exists

| Version | Question answered |
|---|---|
| **1.0–1.2** | Capability, leave-on, project memory |
| **1.3–1.4** | Trust usable and provable on Unix |
| **1.5** | Trace remains correct at scale |
| **1.6** | Execution ≠ verification ≠ capture; experiments; capsules |
| **1.7** | What was the agent *allowed* to do, and what evidence supports that claim? |

Long-horizon agents operate across sandboxes, services, hosts, and organizations. An agent can stay rationally focused on its objective while escaping the environment, acquiring undeclared capabilities, using credentials, interacting with real systems, or obtaining an answer through an invalid provenance path.

### Release contract

> Blackbox can record what an agent was authorized to do, distinguish configured containment from verified containment, detect and preserve evidence of trust-boundary crossings, correlate agent intent with infrastructure effects, and reconstruct related activity across many runs without pretending to be a complete SIEM or enforcement platform.

Blackbox remains a **local-first evidence and provenance system**. It integrates with kernel, network, cloud, container, and security telemetry rather than reimplementing every sensor.

---

## Platform policy (unchanged)

- **Tier 1:** Linux x86_64 / ARM64; macOS Apple Silicon; macOS x86_64 where practical
- **Best effort:** other POSIX
- **Out of scope:** Windows; replacing EDR/SIEM/firewall/sandbox

---

## 1.7 bar (exit criteria)

| Id | Criterion | Intent |
|---|---|---|
| **B1** | Resolved boundary contract | Every governed run stores immutable resolved policy + hash |
| **B2** | Containment honesty | Configured ≠ enforced ≠ verified ≠ failed ≠ unknown |
| **B3** | Required evidence | Missing required sensors → `insufficient_evidence`, fail-closed when required |
| **E1** | External evidence import | Versioned NDJSON; transactional; idempotent; integrity-checked |
| **E2** | Correlation identity | Multi-signal correlation; tolerate stripped/forged cooperative IDs |
| **V1** | Boundary violations | First-class evidence-linked `boundary.violation` / `behavior.transition` |
| **P1** | Provenance gates | Correct answer can fail independently on containment or provenance |
| **I1** | Multi-run incidents | Discovery, reuse, delegation, credential/artifact flow, earliest signal |
| **F1** | Forensic packs | Bounded redacted shards with valid evidence citations |
| **Q1** | Adversarial qualification | Escape, poison, credential misuse, swarm, telemetry deception, benign controls |

Permanent 1.1–1.6 gates remain green.

### Completion audit addendum (2026-07-22)

The release is not taggable until these issue-level criteria have executable
coverage:

1. Kubernetes and cloud-audit sensor mapping, including a real correlation path.
2. Incident reconstruction that explicitly identifies delegation,
   credential-use, and artifact-derivation flows rather than merely retaining
   opaque edges.
3. Bounded high-volume incident reconstruction and cursor qualification at a
   tens-of-thousands scale.
4. Permanent adversarial detector cases for poisoned input, persistence,
   swarm/fan-out, and deceptive telemetry, alongside benign controls.

Delivery tasks live under `docs/plan/tasks/boundary-17*.md`; independent review
records live under `docs/plan/reviews/` while the sprint is active.

---

## Ordered implementation plan

| Step | Theme | Phase |
|---|---|---|
| 1 | Threat model + `blackbox.boundary/v1` schema | **A** |
| 2 | Containment claim/receipt schema + storage | **A/B** |
| 3 | Capture-coverage requirements + fail-closed gates | **A/B** |
| 4 | Normalized external evidence event + NDJSON importer | **C** ✅ |
| 5 | Trace identity propagation + correlation primitives | **D** ✅ |
| 6 | Process/network/proxy fixtures | **C/D** ✅ |
| 7 | Boundary evaluator + deterministic violation events | **E** ✅ |
| 8 | Provenance records + benchmark gates | **G** ✅ |
| 9 | Incident object + cross-run graph | **F** ✅ |
| 10 | Local forensic pack | **H** ✅ |
| 11 | Optional model-assisted analysis | **H** (claims origin=model supported; no hosted provider) |
| 12 | Scale, adversarial, portability, docs qualification | **I** ✅ fixtures + tests |

---

## Phase A — Threat model and boundary schema (this train)

### Deliverables

1. **Versioned schema** `blackbox.boundary/v1` — purpose, allowed/prohibited capabilities, required evidence, dispositions
2. **Stable vocabularies** — capability, effect, identity, target, data-class, provenance tokens
3. **Dispositions** — `hard_prohibition` · `approval_required` · `allowed` · `observed_only` · `unknown`
4. **Policy resolution** — experiment → run → delegated child inheritance; exact resolved policy + SHA-256 hash stored with the run
5. **Containment claim states** — `configured` · `enforced` · `verified` · `observed_only` · `failed` · `unknown` · `unavailable`
6. **Containment receipts** — immutable verifier identity, method, time, scope, result, evidence hashes
7. **Required-evidence evaluation** — explicit `insufficient_evidence` when required capture is missing; fail-closed gate option
8. **Storage migration v9** — `run_boundaries`, `containment_receipts`
9. **CLI** — `boundary validate|show|set|evaluate`; `run --boundary <file>`
10. **Threat-model docs** — what Blackbox records vs what it does not enforce

### Non-goals (Phase A)

- Live network/kernel sensors
- Autonomous process kill on violation
- Multi-run incident objects
- LLM-assisted forensic packs

### Exit

- Unit + integration tests for schema, hash stability, inheritance, evidence gates, storage round-trip
- Reference doc for `blackbox.boundary/v1`
- ROADMAP 1.7 bar published

---

## Threat model (normative summary)

| Actor | Goal | Blackbox response |
|---|---|---|
| **Malicious agent** | Escape sandbox, steal credentials, exfiltrate, cheat benchmarks | Record authorization; surface violations when evidence exists; never claim prevention |
| **Compromised telemetry** | Forge or strip cooperative trace IDs | Multi-signal correlation; confidence caps; integrity fields on imports |
| **Operator error** | Accidental production access from eval env | Boundary contracts + missing-evidence honesty |
| **Benign security research** | Authorized probing that looks like escape | Disposition + false-positive fixtures; do not auto-block |

**Standing honesty:** Blackbox is evidence and provenance, not a sandbox, firewall, EDR, or SIEM. Conclusions that require sensors not present are `insufficient_evidence` or `unknown`, never silently confirmed.

---

## Schema sketch (`blackbox.boundary/v1`)

```json
{
  "schema": "blackbox.boundary/v1",
  "purpose": "capability evaluation",
  "allowed": {
    "targets": ["local-range"],
    "network": ["package-proxy.internal"],
    "identities": ["eval-workload"],
    "data_classes": ["synthetic"],
    "tools": ["shell", "read_file"],
    "effects": ["workspace_write"]
  },
  "prohibited": [
    "public_network",
    "production_credentials",
    "external_organizations",
    "undeclared_answer_sources"
  ],
  "dispositions": {
    "public_network": "hard_prohibition",
    "package_install": "approval_required"
  },
  "required_evidence": [
    "process",
    "network",
    "containment_receipt",
    "artifact_provenance"
  ],
  "fail_closed": true,
  "parent_policy_hash": null,
  "extensions": {}
}
```

Resolved form adds `resolved_at`, `policy_hash`, `inheritance_chain`, and freezes the exact document stored with the run.

---

## Related

- Epic: [issue #5](https://github.com/wanazhar/blackbox/issues/5)
- Prior: [ROADMAP.md](../ROADMAP.md), [claims.md](../claims.md)
- 1.6 verification: [guide/verification.md](../guide/verification.md)
