# Boundary contract reference (`blackbox.boundary/v1`)

Machine-readable authorization and required-evidence contract for a governed run (Blackbox **1.7**).

Related: [plan](../plan/agent-boundary-1.7.md) · [claims](../claims.md) · [verification](../guide/verification.md) · epic [issue #5](https://github.com/wanazhar/blackbox/issues/5).

---

## What this is (and is not)

| Is | Is not |
|---|---|
| Record of what the agent was **authorized** to do | A sandbox, firewall, or EDR |
| Distinguishes **configured / enforced / verified** containment | Proof that every side effect was observed |
| Fail-closed **evidence gates** when required sensors are missing | Automatic process kill on violation (optional later) |
| Immutable **policy hash** stored with the run | A multi-tenant SIEM |

Blackbox remains a local-first evidence system. Missing sensors produce `insufficient_evidence` or `unknown`, never silently confirmed success.

---

## Schema

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
    "effects": ["workspace_write"],
    "provenance": ["declared_dataset"]
  },
  "prohibited": [
    "public_network",
    "production_credentials",
    "external_organizations",
    "undeclared_answer_sources"
  ],
  "dispositions": {
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
  "labels": {
    "environment": "eval",
    "eval_case": "sandbox-escape-01"
  },
  "extensions": {}
}
```

| Field | Notes |
|---|---|
| `schema` | Always `blackbox.boundary/v1` |
| `purpose` | Free-text purpose of the run under this contract |
| `allowed.*` | Explicit allow-lists (targets, network, identities, data_classes, tools, effects, provenance) |
| `prohibited` | Tokens default to disposition `hard_prohibition` |
| `dispositions` | Per-token override: `hard_prohibition` · `approval_required` · `allowed` · `observed_only` · `unknown` |
| `required_evidence` | Classes that must be present for a conclusive evaluation |
| `fail_closed` | When true, missing required evidence / unproven containment fails the gate |
| `parent_policy_hash` | Optional parent for inheritance / lineage |
| `labels` / `extensions` | Free-form metadata; extensions ignored unless registered |

Rust: `blackbox::boundary::BoundaryContract`. Resolved form: `ResolvedBoundary` (adds `policy_hash`, `resolved_at`, `run_id`, `inheritance_chain`).

### Policy hash

SHA-256 hex of the **canonical JSON** of the fully merged contract (not timestamps or run id). Same policy → same hash across runs.

### Inheritance

Experiment → run → delegated child: child wins on conflicts; `allowed` is unioned; child prohibitions remove matching allowed entries; `required_evidence` is unioned; `fail_closed` is OR.

---

## Containment receipts (`blackbox.containment.receipt/v1`)

Independent claims — configuration is never silently treated as verification.

| Claim state | Meaning |
|---|---|
| `configured` | Declared in launch/config |
| `enforced` | Control applied at launch |
| `verified` | Independent check confirmed the control |
| `observed_only` | Seen in telemetry only |
| `failed` | Attempted and failed |
| `unknown` | Cannot determine |
| `unavailable` | Not available on this platform |

| Result | Meaning |
|---|---|
| `held` | Restriction held under the declared method |
| `violated` | Escape or misconfiguration observed |
| `denied` | Command denied by policy |
| `unreachable` | Destination unreachable (≠ denied) |
| `inconclusive` | Check incomplete |
| `not_observed` | Sensor gap |
| `not_applicable` | Method N/A |

A **required** `containment_receipt` is satisfied only by a receipt with claim `verified` **and** result `held`. Task success is never consulted.

---

## Evidence evaluation (`blackbox.boundary.eval/v1`)

| Status | Meaning |
|---|---|
| `sufficient` | All required evidence present (or not applicable) |
| `insufficient_evidence` | Required class missing / unavailable / partial |
| `containment_unproven` | Receipts missing or not verified+held |
| `containment_violated` | A receipt reports `violated` |
| `no_boundary` | No contract on the run |
| `not_evaluated` | Skipped |

`gate_failed` is true only when `fail_closed` is set **and** status is a gate failure.

---

## External evidence (`blackbox.evidence.event/v1`)

Normalized NDJSON for process/network/proxy/Kubernetes/cloud/generic sensors. Built-in mappings cover Falco-like, HTTP proxy, process audit, Kubernetes audit, AWS CloudTrail, and GCP Audit Log records. Import is idempotent on `(source, source_event_id)`, bounded, and rejects absolute/traversal path attributes. Recognized sensor records missing required provider fields are rejected rather than defaulted.

```bash
blackbox evidence import events.ndjson --run <run|latest>
blackbox evidence import events.ndjson --run latest --reject-unverified
blackbox evidence list --run latest
```

## Correlation & trace identity

Each supervised run mints a random `TraceIdentity`. Correlation can combine process ID, host, workload, principal, trace ID, import context, and time. Edges never upgrade temporal proximity alone to `confirmed`. Matching cooperative `trace_id` alone is at most `strongly_correlated` (closed residual risk). Conflicting principals weaken attribution. A matching payload hash proves consistency but not source authenticity, so `hash_ok` is also capped below `confirmed`. Only evidence admitted by a trusted signature verifier can reach `confirmed`; NDJSON input cannot self-assert `signed_verified`.

## Detection & provenance

```bash
blackbox boundary detect <run> [--emit-events]
blackbox boundary provenance <run> --declared local-dataset --task-passed true --gate
```

Task correctness and provenance validity are independent: a correct answer with undeclared network still fails the provenance gate.

## Incidents & forensic packs

```bash
blackbox incident create --title "egress" --run r1 --run r2
blackbox incident show <inc-id> --graph
blackbox forensic pack <run> -o pack.json
blackbox forensic analyze pack.json --model local/model@sha256:... \
  --prompt-file exact-prompt.txt --configuration-file inference-config.json \
  --claim "derived claim" --cite event:<event-id>
```

Incident graph schema `blackbox.incident.graph/v2` carries typed delegation, credential-use, and artifact-derivation flows. `edge_count`, `flow_count`, `flow_counts`, `technique_count`, and `reuse_count` are exact source totals when `counts_exact=true`. `detail_limits` and `truncation` distinguish totals from serialized details. Deserialized v1 graphs have `counts_exact=false`; their list lengths are lower bounds and truncation is unknown.

Forensic packs recursively scan every serialized string and object key, including edges, pointers, optional incident graphs, external identity, findings, and model output. Citations must exactly equal a typed pointer already in `original_pointers`; suffix-only and ambiguous IDs reject. Before mutation, `analyze` validates schema, `pack_hash`, and citations. It computes SHA-256 fingerprints from exact `--prompt-file` and `--configuration-file` bytes; refusal and failure records carry the same provenance. A hash mismatch leaves the input file unchanged.

`blackbox.incident.export/v1` recursively scans every serialized incident/graph/reference string. Within one export, equal secret matches receive the same opaque token so structural links survive; tokens are namespaced per export and are not secret digests. The transformation ledger records scanned and actually redacted counts by field family. The document also records supplied attachment payload hashes, unresolved references, and `export_hash`. Validate the hash before trusting a received exchange. Attachment bodies are not embedded, so hashes remain citations to separately retained originals.

## CLI

```bash
blackbox boundary validate path/to/boundary.json
blackbox boundary set <run|latest> -f boundary.json
blackbox boundary show <run|latest>
blackbox boundary evaluate <run> --gate
blackbox boundary receipt <run> --claim verified --result held --method post_run_canary \
  --control network_egress --evidence-hash <sha256>
blackbox boundary detect <run> --emit-events
blackbox boundary provenance <run> --declared dataset://case --gate
blackbox evidence import proxy.ndjson --run latest
blackbox incident create --title swarm --run latest
blackbox forensic pack latest -o /tmp/pack.json
blackbox run --boundary boundary.json --boundary-fail-closed -- echo hi
```

Exit code **2** when `boundary evaluate --gate` or `boundary provenance --gate` fails closed.

---

## Storage

Schema versions:

| Ver | Tables |
|---|---|
| **v9** | `run_boundaries`, `containment_receipts` |
| **v10** | `external_evidence`, `evidence_edges`, `run_trace_identity`, `provenance_records`, `boundary_findings`, `incidents` |

---

## jq examples

```bash
jq -r '.data.policy_hash' <(blackbox --json boundary validate boundary.json)
jq -r '.data.status, .data.gate_failed' <(blackbox --json boundary evaluate latest)
jq -r '.data.report.provenance_status' <(blackbox --json boundary provenance latest --gate || true)
```
