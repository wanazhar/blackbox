# Boundary 1.7 integration review 01

**Reviewed commit:** `ab566cbd71522c41309f7494ef8c5d8f2df8ed63`  
**Issue:** [#5 — Agent boundaries, containment evidence, and incident reconstruction](https://github.com/wanazhar/blackbox/issues/5)  
**Verdict:** **BLOCKED**  
**Release recommendation:** Do not close issue #5, tag 1.7.0, or publish until the P1 findings are fixed and covered by adversarial tests.

The integration, orchestration, incident-flow, detector-quality, and scale gates are real executable tests. The Unix quick qualifier is green on this commit. However, three issue-level acceptance claims marked complete in `docs/plan/analysis/boundary-17-completion.md` are not met by the serialized artifacts that operators would share or analyze.

## Findings

### P1 — `--sanitize` leaves secret-bearing incident and graph fields unchanged

`build_incident_export(..., sanitize=true)` scans only `incident.title`, `incident.summary`, and graph node labels (`src/incident/export.rs:47-80`). It serializes the rest of the cloned incident and graph unchanged (`src/incident/export.rs:84-90`). Unscanned free-text or identity-bearing fields include:

- incident tags, attachment `ref_id`, and attachment `reason` (`src/incident/model.rs:39-64`);
- graph edge IDs, endpoints, and reasons;
- flow endpoint IDs and reasons;
- technique strings and first/reuse references;
- earliest-signal summary and references (`src/incident/graph.rs:26-44`, `src/incident/graph.rs:76-90`, `src/incident/graph.rs:187-201`).

An independent temporary integration probe constructed an incident containing an OpenAI-shaped fixture secret in `tags` and an attachment `reason`, called `build_incident_export(..., true)`, serialized the result, and confirmed that the exact secret remained present. The probe passed as a vulnerability demonstration:

```text
test sanitized_incident_still_serializes_secret_bearing_free_text ... ok
```

The committed tests seed secrets only in title/summary (`src/incident/export.rs:156-181`, `tests/boundary_1_7_completion.rs:159-192`), exactly the two incident fields that are scanned. They do not exercise attachments, tags, graph edges/flows, techniques, or earliest-signal text.

This blocks DoD 12 and invalidates the broad operator claim that sanitized exports “redact free text” (`docs/guide/boundaries-and-incidents.md:112`). The safety caveat at line 143 is good, but it does not make a known scanner bypass an acceptable sanitized-exchange contract.

Required closure:

1. Apply recursive, field-aware sanitization to every serialized incident/graph string that may contain source- or operator-controlled content while preserving explicitly structural IDs according to a documented policy.
2. Add adversarial secrets to attachment reasons/tags, edge and flow reasons/endpoints, techniques, and earliest-signal fields; assert the complete serialized document contains none.
3. Make the transformation ledger accurately describe the fields actually transformed, and retain tamper tests over the complete sanitized document.

### P1 — forensic packs copy unredacted edges and model output into a supposedly redacted pack

`build_forensic_pack` redacts event metadata, selected finding text, and external destinations, but copies `EvidenceEdge` values verbatim (`src/forensic/pack.rs:237-249`). `apply_model_analysis` also stores caller-controlled model IDs, claim text, and failure text verbatim (`src/forensic/pack.rs:349-409`). `incident_graph`, if populated by a consumer, is likewise an unredacted serializable field (`src/forensic/pack.rs:93-99`).

An independent temporary probe placed the fixture secret in an edge endpoint/reason and in a cited model claim, built the pack, applied analysis, and confirmed the complete serialized pack still contained the secret:

```text
test forensic_pack_still_serializes_secret_edges_and_model_output ... ok
```

The permanent no-secret checks seed only trace metadata (`src/forensic/pack.rs:502-527`, `tests/boundary_1_7_completion.rs:128-157`) and use safe edge/model strings, so they cannot support matrix row 10’s artifact-wide “no fixture secrets” claim (`docs/plan/analysis/boundary-17-completion.md:46`). This also contradicts the “residual risk closed” statement in `docs/guide/security.md:259-267`.

Required closure:

1. Redact all serialized pack fields that can carry untrusted or operator text, including edges, optional graphs, model claims/failures/model metadata, findings beyond summary/recommendation, external source/sensor identity, and pointer/ID fields under an explicit structural-ID policy.
2. Run one adversarial corpus secret through every field family and scan the complete JSON bytes, not selected vectors.
3. Recompute and validate `pack_hash` after sanitization and after derived claims are added.

### P1 — caller-supplied non-empty labels are accepted as reproducibility fingerprints

The CLI requires two strings, but `apply_model_analysis` validates only that model, prompt fingerprint, and configuration fingerprint are non-empty (`src/forensic/pack.rs:318-346`). Values such as `not-a-hash` and `also-not-a-hash` are accepted and serialized as provenance. The permanent test uses placeholders such as `sha256:prompt` rather than a digest (`src/forensic/pack.rs:549-572`, `tests/boundary_1_7_completion.rs:217-248`). No exact prompt/configuration artifact is stored or referenced, no canonical bytes are defined, and Blackbox neither computes nor validates a digest.

In addition, `forensic analyze` deserializes a pack and immediately mutates it without first checking the existing `pack_hash` (`src/cli_ext.rs:2528-2548`). A modified input pack can therefore receive a newly computed hash while attaching a claim, erasing the signal that its original evidence shard was tampered with.

These fields are provenance labels, not verifiable fingerprints. They do not establish the issue requirement to record model, prompt, configuration, and derived output sufficiently for a reproducible derived claim, so DoD 11 remains open despite matrix row 11 (`docs/plan/analysis/boundary-17-completion.md:47`). The docs correctly avoid claiming deterministic inference replay, but “reproducibility fingerprints validate” (`docs/guide/security.md:275`) is not true for arbitrary unchecked strings.

Required closure:

1. Define canonical prompt/configuration bytes and compute hashes inside Blackbox, or strictly validate an algorithm-tagged digest and record resolvable immutable artifact pointers for the hashed inputs.
2. Record sufficient model/runtime identity and output provenance to distinguish exact inputs from a caller assertion.
3. Validate the incoming pack schema and `pack_hash` before analysis; reject tampered packs without rewriting them.
4. Add negative tests for malformed/non-hash labels, changed prompt/configuration artifacts, and a tampered input pack.

### P2 — citation validation uses suffix matching instead of exact typed pointers

Both claim insertion and later validation accept a citation when an original pointer merely `ends_with` the supplied text (`src/forensic/pack.rs:388-393`, `src/forensic/pack.rs:425-430`). A short citation such as `1` can resolve to any `event:...1`, and collisions are ambiguous. This is weaker than “validate every cited evidence pointer” and can associate derived claims with unintended evidence.

Require exact canonical typed pointers (`event:<id>`, `external:<id>`, `finding:<id>`) or an exact unambiguous ID lookup. Add collision and suffix-only rejection tests.

### P2 — the scale gate bounds serialized detail but does not demonstrate bounded working memory

`incident_scale` is meaningful for cursor correctness, exact totals, visible truncation, and 10k-scale behavior. It is not a memory-bound qualification: the graph test deliberately allocates all 10,000 external events and all 10,000 edges before reconstruction (`tests/incident_scale.rs:79-130`) and records no peak-memory or allocation bound. The wall-clock assertions (`tests/incident_scale.rs:56`, `tests/incident_scale.rs:164`) are host-speed thresholds and may be brittle under contended CI.

Matrix row 14 should say “bounded serialized graph detail and cursor-query behavior” unless a streaming/limited assembly path and reproducible memory measurement are added. Keep the exact-total and pagination assertions; move soft timing to reported measurements or use a generous environment-aware budget.

### P3 — the transformation ledger records attempted categories, not actual transformations

When sanitization is enabled, `summary_redacted`, `title_redacted`, and `graph_labels_redacted` are appended whenever those fields/categories exist even if `SecretScanner` changed no bytes (`src/incident/export.rs:47-80`). This is a coarse operation ledger, not exact transformation history. Either name entries as scans (for example, `title_scanned`) or record before/after hashes/counts for actual redactions.

## Definition-of-Done audit

| # | Result | Evidence / limitation |
|---|---|---|
| 1 | Pass | Immutable stored resolved policy and stable inheritance hash are exercised by `boundary_contract`. |
| 2 | Pass | Claim-state vocabulary and append-only receipt storage remain distinct; configured does not satisfy verified. |
| 3 | Pass | Missing sensors/receipts produce insufficient or containment-unproven fail-closed results. |
| 4 | Pass | Version/schema, atomic store insertion, idempotence, input bounds, path safety, and payload integrity have behavior tests. |
| 5 | Pass | Process/network/proxy plus Kubernetes and AWS/GCP mappings and stored correlation paths are exercised. |
| 6 | Pass | Forged/cooperative IDs and unverified integrity are confidence-capped by behavior tests. |
| 7 | Pass | Deterministic findings retain evidence IDs; detector corpus exercises first-class violation/transition output. |
| 8 | Pass | Successful execution can fail provenance/containment independently. |
| 9 | Pass | Discovery/reuse/earliest signal and typed delegation/credential/artifact flows have executable graph tests. |
| 10 | **Blocked** | Citations exist, but suffix matching is weak and serialized pack fields leak fixture secrets. |
| 11 | **Blocked** | Claims remain derived, but arbitrary labels and unchecked input-pack integrity do not provide reproducibility evidence. |
| 12 | **Blocked** | Hash tamper detection works, but sanitization misses multiple exported field families and the ledger is incomplete. |
| 13 | Pass | Permanent imported fixtures cover required adversarial families and benign controls; quality gate is behavioral. |
| 14 | Partial | 10k cursor/detail tests are meaningful; serialized detail is bounded, but bounded working memory is not demonstrated. |
| 15 | Partial | Sensor/non-prevention/partial-observability limits are strong; sanitization and closed-risk statements overclaim current coverage. |
| 16 | Pass | The Unix quick trust/integrity/boundary suite is green on the reviewed commit. |

## Verification performed

```text
cargo test --test boundary_1_7_completion -- --nocapture
  PASS: 2 passed

cargo test --lib forensic::pack::tests -- --nocapture
  PASS: 4 passed

cargo test --lib incident::export::tests -- --nocapture
  PASS: 3 passed

python3 scripts/check_doc_links.py
  PASS: checked 483 file links + 89 anchors in 64 markdown files

cargo fmt --check
  PASS

cargo clippy --all-targets -- -D warnings
  PASS

./scripts/release-qualify-unix.sh --quick
  PASS: 0 failed; report sha256 dde1ffead075708a743db20fe93fe19447af6d497b43c6ec148d64fba7b9f84c
```

The temporary adversarial probe contained two behavior tests, passed as vulnerability demonstrations, and was removed before this review commit. No implementation files were changed.

## Conclusion

The release integration is structurally strong and its new CI/release gates exercise runtime behavior rather than searching source text. It is nevertheless **blocked**: the artifacts advertised as redacted/sanitized can serialize known fixture secrets, and model-analysis provenance is not yet independently verifiable or protected against a tampered input pack. Rows 10–12 and the implementation-complete status must remain open until the P1 closure criteria above have permanent regression coverage.
