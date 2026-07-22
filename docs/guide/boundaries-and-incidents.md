# Boundaries, evidence, and incidents

Record what an agent was **authorized** to do, import external telemetry, detect boundary crossings, and reconstruct multi-run incidents — without treating Blackbox as a sandbox, firewall, or SIEM.

Reference: [boundary.md](../reference/boundary.md) · Plan: [agent-boundary-1.7.md](../plan/agent-boundary-1.7.md).

---

## When to use

| Job | Command |
|---|---|
| Govern an eval / agent run | `run --boundary file.json` |
| Import host, proxy, Kubernetes, or cloud audit logs | `evidence import events.ndjson --run latest` |
| Check containment honesty | `boundary evaluate latest --gate` |
| Fail CI on provenance cheat | `boundary provenance latest --task-passed true --gate` |
| Swarm reconstruction | `incident create --run r1 --run r2` |
| Local IR pack | `forensic pack latest -o pack.json` |

**When not to:** expecting Blackbox to *block* egress or kill processes. Receipts and gates record evidence; they do not enforce policy by default.

---

## Boundary contract (quick start)

```bash
# Validate + hash
blackbox boundary validate tests/fixtures/boundary_1_7/eval_boundary.json

# Attach at launch
blackbox run --boundary tests/fixtures/boundary_1_7/eval_boundary.json \
  --boundary-fail-closed -- echo hi

# After the run: launch canaries are automatic; detect + evaluate
blackbox boundary detect latest
blackbox boundary evaluate latest --gate   # exit 2 if fail-closed failure
```

Postmortem JSON includes `boundary_trust`. `score.json` sets `failed=true` when fail-closed boundary/provenance gates fail or critical findings exist — even if exit code is 0.

---

## Evidence import

Supports native `blackbox.evidence.event/v1`, generic JSONL, and adapters for **Falco-like**, **HTTP proxy**, **process audit**, **Kubernetes audit**, **AWS CloudTrail**, and **GCP Audit Log** shapes. Kubernetes and cloud adapters preserve provider event IDs, principals, workloads, trace identities, actions, objects, outcomes, and source/observation times; malformed recognized records are rejected rather than filled with invented defaults.

```bash
blackbox evidence import tests/fixtures/boundary_1_7/proxy_events.ndjson --run latest
# Fail-closed IR: require locally checked payload hashes
blackbox evidence import events.ndjson --run latest --reject-unverified
blackbox evidence list --run latest
```

Import is transactional with its generated edges, idempotent on `(source, source_event_id)`, bounded, and rejects absolute/traversal path attributes. When `original_payload_hash` is present, the importer verifies sha256 of the `payload` / `raw` / `body` attribute (disable with `--no-verify-payload-hashes` only for private debugging). A matching hash proves consistency, not sensor authenticity, and remains below `confirmed`. NDJSON cannot self-assert `signed_verified`; that state is reserved for a trusted verifier.

### Sensor requirements

| Requirement | Why it matters |
|---|---|
| Stable `source_event_id` from the sensor | Enables idempotence and audit lookup; it is not a run ID |
| Reliable `occurred_at` and `observed_at` | Makes clock delay and ordering uncertainty visible |
| Principal, workload, process, or trusted trace identity | Provides independent correlation signals |
| Integrity set by a trusted verifier | Imported claims cannot promote themselves to `signed_verified` |
| Retention longer than the incident investigation window | Blackbox stores normalized evidence, not the sensor's full archive |

Do not use `--run` as proof of attribution. It records an import context. Cooperative trace IDs and claimed run IDs may be forged, so they remain below `confirmed` without independently verified integrity and corroborating signals.

---

## Provenance vs task success

```bash
# Correct answer obtained via prohibited network still fails provenance
blackbox boundary provenance latest \
  --declared local-dataset \
  --task-passed true \
  --gate
```

Experiment gates:

```bash
blackbox gate --experiment exp1 \
  --require-boundary-ok \
  --require-provenance-ok \
  --fail-on-critical-findings
```

---

## Incidents & forensic packs

```bash
blackbox incident create --title "egress-swarm" --run latest
blackbox incident list --limit 50
blackbox incident list --limit 50 --cursor <next_cursor>
blackbox incident show <inc-id>
blackbox incident export <inc-id> -o incident.json --sanitize

blackbox forensic pack latest -o pack.json
# Optional local model claims (citations required; never replace evidence)
blackbox forensic analyze pack.json --model local-llm \
  --prompt-fingerprint sha256:<prompt> \
  --configuration-fingerprint sha256:<config> \
  --claim "public egress after probe" --cite find-...
```

Dashboard: open `/incidents` and each run’s trust panel (findings + policy hash). Incident pages show a **reconstruction graph** (runs + technique reuse curves), earliest-signal banner, techniques table, findings timeline, and correlation edges. Graph v2 also exposes typed `delegation`, `credential_use`, and `artifact_derivation` flows. Serialized node, edge, flow, and technique detail is bounded; `counts_exact`, exact totals, limits, and `truncation` say what was omitted. Legacy v1 graphs provide included lower bounds only and cannot assert whether hidden detail was truncated.

Forensic model claims remain derived data. Every claim records the model identifier plus prompt and configuration fingerprints and must cite a pointer already present in the pack. Blackbox records caller-supplied output; it does not invoke a hosted model or claim deterministic inference replay.

Sanitized incident exports redact free text with the same secret scanner used by forensic packs, include hashes for supplied attachment payloads, record transformations and unresolved references, and protect the exchange document with `export_hash`. The export is an investigation copy, not a substitute for the original store. Keep the source store under the retention and access policy needed for citation resolution, and validate the export before sharing or importing it elsewhere.

Detector quality is gated in CI (`tests/boundary_detector_quality.rs`): the permanent corpus covers escape, probing, credential abuse, package/repository manipulation, privilege attempts, poisoned instructions, persistence, swarm/delegation, telemetry deception, transitions, and benign controls (min recall 0.85 / precision 0.80).

### Auto provenance from experiments

When you pass `--dataset-case` / `--task` / `--experiment` on `run`, Blackbox writes a provenance record automatically from declared dataset/task URIs and any observed network destinations. A successful exit with undeclared HTTP still fails score/provenance gates.

```bash
blackbox run --experiment exp1 --dataset-case case-9 --boundary eval.json -- ...
```

---

## MCP & dashboard

| Surface | Path |
|---|---|
| MCP | `blackbox_boundary`, `blackbox_evidence`, `blackbox_incident`, `blackbox_forensic` |
| API | `/api/runs/{id}/boundary`, `/findings`, `/evidence`, `/api/incidents` |

---

## Honesty limits

- Configured ≠ enforced ≠ verified containment  
- Cooperative `trace_id` alone is **never** confirmed attribution (closed by design; permanent unit gates)  
- Unverified / signed-invalid sensor integrity cannot reach `confirmed` correlation  
- Missing sensors → `insufficient_evidence`, not silent success  
- Kubernetes/cloud identities are correlation inputs, not authenticated agent identity by themselves
- Graph detail limits preserve exact v2 totals; a short list is not evidence that no other edges existed
- Sanitization reduces accidental disclosure but does not make an export safe for unrestricted distribution
- Blackbox is **not** an EDR/SIEM/firewall  

See also: [verification](verification.md) · [security](security.md) · [experiments](experiments.md).
