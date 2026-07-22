# Boundaries, evidence, and incidents

Record what an agent was **authorized** to do, import external telemetry, detect boundary crossings, and reconstruct multi-run incidents — without treating Blackbox as a sandbox, firewall, or SIEM.

Reference: [boundary.md](../reference/boundary.md) · Plan: [agent-boundary-1.7.md](../plan/agent-boundary-1.7.md).

---

## When to use

| Job | Command |
|---|---|
| Govern an eval / agent run | `run --boundary file.json` |
| Import proxy/process logs | `evidence import events.ndjson --run latest` |
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

Supports native `blackbox.evidence.event/v1`, generic JSONL, and adapters for **Falco-like**, **HTTP proxy**, and **process audit** shapes.

```bash
blackbox evidence import tests/fixtures/boundary_1_7/proxy_events.ndjson --run latest
# Fail-closed IR: require locally checked payload hashes
blackbox evidence import events.ndjson --run latest --reject-unverified
blackbox evidence list --run latest
```

Import is transactional with its generated edges, idempotent on `(source, source_event_id)`, bounded, and rejects absolute/traversal path attributes. When `original_payload_hash` is present, the importer verifies sha256 of the `payload` / `raw` / `body` attribute (disable with `--no-verify-payload-hashes` only for private debugging). A matching hash proves consistency, not sensor authenticity, and remains below `confirmed`. NDJSON cannot self-assert `signed_verified`; that state is reserved for a trusted verifier.

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
  --claim "public egress after probe" --cite find-...
```

Dashboard: open `/incidents` and each run’s trust panel (findings + policy hash). Incident pages show a **reconstruction graph** (runs + technique reuse curves), earliest-signal banner, techniques table, findings timeline, and correlation edges.

Detector quality is gated in CI (`tests/boundary_detector_quality.rs`): expanded corpus covers escape, probe, credential, package, privilege, transition, and benign controls (min recall 0.85 / precision 0.80).

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
- Blackbox is **not** an EDR/SIEM/firewall  

See also: [verification](verification.md) · [security](security.md) · [experiments](experiments.md).
