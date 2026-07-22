# Blackbox 1.7 issue-completion analysis

Issue #5 is the acceptance source. The earlier implementation covers immutable
boundaries, containment honesty, transactional evidence, correlation confidence,
findings, provenance, forensic packs, sanitized exchange, and release gates.
This audit identified three independent module gaps plus one final integration
gate.

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

## Delivery order

The three module tasks have disjoint paths and can develop in parallel. The
integration task starts only after all three are reviewed and merged.
