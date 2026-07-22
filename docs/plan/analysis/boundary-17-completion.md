# Blackbox 1.7 issue-completion analysis

Issue #5 is the acceptance source. This audit closed the sensor, incident-flow,
adversarial-corpus, model-provenance, sanitized-exchange, and final-integration
gaps. The all-target matrix and Unix quick qualification were green on the
completion candidate; tagging and publication remain separate maintainer steps.

## Module decomposition

| Task | Module | Inputs | Outputs | Dependencies |
|---|---|---|---|---|
| boundary-17-sensors | `evidence` adapters | Kubernetes audit and cloud-audit JSON | normalized external evidence with correlation identities | evidence schema, correlation context |
| boundary-17-incidents | incident graph/storage tests | findings, evidence edges, run attachments | explicit delegation/credential/artifact flows and bounded graph | incident schema, evidence relations |
| boundary-17-adversarial | deterministic detection corpus | trace/external evidence fixtures | evidence-linked poison/persistence/swarm/deception findings | boundary detector API |
| boundary-17-integration | release/docs qualification | all three modules | issue-DoD matrix and permanent release gate | all module tasks |

## Integration enumeration

1. Evidence importer calls `map_sensor_event`; Kubernetes/cloud records must
   become `ExternalEvidenceEvent`, survive store import, and feed
   `correlate_external_event` using workload/principal/trace identity.
2. Stored `EvidenceEdge` values feed `build_incident_graph`; delegation,
   credential use, and artifact derivation must become typed graph flows with
   stable references and confidence.
3. CLI/store incident assembly must remain bounded when source counts exceed
   graph detail limits; aggregate totals must remain honest and truncation must
   be explicit.
4. `detector_corpus` feeds the permanent quality gate; every issue-required
   adversarial family and benign counterpart must be represented.
5. CI and `release-qualify-unix.sh` must exercise the new integration and scale
   gates before 1.7.0 can be tagged.

## Issue #5 Definition of Done matrix

| # | Acceptance claim | Permanent executable evidence |
|---|---|---|
| 1 | Governed run stores an immutable resolved boundary and policy hash | `boundary_contract::schema_migration_v9_and_roundtrip`, `boundary_contract::policy_hash_stable_and_inheritance` |
| 2 | Configured, enforced, verified, failed, and unknown remain distinct | `boundary_contract::containment_receipts_immutable_append`, containment unit tests |
| 3 | Missing evidence is insufficient rather than compliant | `boundary_contract::fail_closed_gate_rejects_missing_and_configured_only`, `boundary_1_7_completion` |
| 4 | Imports are versioned, transactional, idempotent, bounded, and integrity checked | `boundary_1_7_full`, `boundary_trust_integration`, `evidence_adversarial` |
| 5 | Correlation spans process, network/proxy, orchestration, and cloud evidence | `boundary_1_7_full`, `evidence_orchestration` |
| 6 | Missing or forged identifiers do not overstate attribution | `evidence_adversarial`, `evidence_orchestration`, correlation unit tests |
| 7 | Violations and transitions link back to evidence | `boundary_1_7_full`, `boundary_detector_quality` |
| 8 | Correct output can fail containment or provenance | `boundary_trust_integration`, `auto_provenance` |
| 9 | Incidents reconstruct discovery, reuse, delegation, credential use, artifact derivation, and earliest signal | `boundary_1_7_full`, `incident_graph_flow` |
| 10 | Forensic packs contain valid citations and no fixture secrets | forensic unit tests, `boundary_1_7_completion` |
| 11 | Model findings stay derived and reproducible, never original evidence | forensic model-provenance unit tests, `boundary_1_7_completion` |
| 12 | Sanitized exchange carries transformation and integrity evidence | incident export unit tests, `boundary_1_7_completion` |
| 13 | Adversarial and benign families are permanent fixtures | `boundary_detector_quality`, `evidence_adversarial` |
| 14 | High-volume incidents remain bounded and queryable | `incident_scale`, `incident_pagination`, `incident_graph_flow` |
| 15 | Docs state sensor requirements, limits, retention, and non-prevention boundary | operator security and boundary guides plus `docs_first_run`/link checker |
| 16 | Older trust and integrity gates stay green | full `cargo test --all-targets`; existing 1.4–1.6 gates in `release-qualify-unix.sh` |

The matrix names test binaries and stable test purposes rather than treating this
document as evidence. CI and the Unix qualification script execute the full 1.7
set, including orchestration/cloud mapping, typed flows, scale, and the completion
scenario.

## Qualification commands

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
python3 scripts/check_doc_links.py
cargo test --all-targets
./scripts/release-qualify-unix.sh --quick
cargo publish --dry-run
```

Do not mark issue #5 complete or tag 1.7.0 if any mandatory command fails.

## Delivery order

The three module tasks developed independently and were reviewed before this
integration task. Release qualification is the final dependency before issue
closure and tagging.
