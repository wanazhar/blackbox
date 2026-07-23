# Blackbox 1.8 completion evidence

This matrix maps issue
[#6](https://github.com/wanazhar/blackbox/issues/6) to permanent implementation
and release evidence. It is a qualification record, not an operator guide.

| Release-contract criterion | Implementation evidence | Permanent gate |
|---|---|---|
| No substring authorization/prohibition | `boundary::selector`; canonical provenance matching | `boundary_1_8_release_contract`, provenance unit tests |
| Typed domain, URL, IP, CIDR, port, path, socket, identity, tool, effect selectors | `boundary::selector`, `boundary::normalize` | selector + normalization unit tests |
| Separated finding semantics | `FindingDecision`; detector completion pass | `every_detector_finding_has_a_calibrated_decision` |
| Allowed/ambiguous credentials are not critical | calibrated credential detector | finding and detector corpus tests |
| Unverified evidence is confidence-capped | integrity-aware violation/severity derivation | frozen benchmark severity and sensor-loss slices |
| Typed, cited incident continuation | `incident::continuation`; graph continuation conclusion | continuation and incident graph tests |
| Typed forensic redaction | structural-key/value rejection; free-form-only sanitizer | forensic hostile-pattern tests |
| Citation-complete included findings | cited selection plus explicit unavailable reasons | forensic citation tests |
| Exact forensic scope | `ForensicPackScope` totals/included/limitations | forensic scope tests |
| Optional cross-pack secret equality | project-keyed HMAC mode; unlinkable default | forensic HMAC tests |
| Unknown policy tokens surfaced/fail closed | vocabulary registry + lint diagnostics | lint tests and `boundary lint --gate` |
| Policy resolution explanations | per-token source, override, and order trace | lint/explain tests |
| Frozen versioned detector benchmark | committed scenario-fingerprint baseline | `boundary benchmark`; release qualification |
| Layer-labeled APIs and UI | API/MCP envelopes, incident/pack fields, dashboard labels | 1.8 release-contract integration test |
| 1.4–1.7 gates remain green | unchanged release suites plus additive 1.8 gate | `scripts/release-qualify-unix.sh` |

The frozen baseline is
`tests/fixtures/boundary_1_8/frozen_benchmark_v1.json`. A scenario edit changes
its SHA-256 fingerprint and fails qualification until the baseline receives an
explicit reviewed update.

Qualification on 2026-07-23: `cargo test --all-targets -- --quiet`,
`scripts/release-qualify-unix.sh --quick`, and the full
`scripts/release-qualify-unix.sh` passed with no failures for 1.8.0.
