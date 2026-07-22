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

---

## Re-review after `d4664e8`

**Re-reviewed commit:** `d4664e8` (`fix(boundary): close 1.7 integration review blockers`)

**Re-review verdict:** **PASS**

**Release recommendation:** The integration review no longer blocks closing issue #5 or proceeding to the remaining release steps, provided the final release qualification remains green on the exact release commit.

The original findings above are retained as the historical review record. This section supersedes the original blocked verdict for the fixed commit.

### Finding dispositions

#### RESOLVED — P1 sanitized incident export coverage

`build_incident_export` now resolves attachment payloads against original IDs before sanitization, converts the full incident, graph, attachment-hash labels, and unresolved-reference list to JSON values, and recursively scans every string value and object key with one per-export stable opaque replacement map. This includes tags, attachment IDs/reasons, graph nodes, evidence edges, typed flows, techniques, earliest-signal fields, hashes, and unresolved references. Equal secret substrings receive the same replacement, preserving internal references without exposing a reusable secret digest.

The permanent `sanitized_export_scans_every_string_and_preserves_references` test places the fixture secret across all incident/graph field families, asserts absence from the complete serialized document, checks incident/graph/edge/flow/technique/signal references after replacement, and validates the export hash. An independent re-review probe used differently prefixed IDs and reasons and reached the same result: no raw fixture secret and all checked references remained equal.

#### RESOLVED — P1 forensic pack whole-artifact redaction

Pack construction now performs a recursive serialization-boundary scan over the complete `ForensicPack`, including event keys/values, external source/sensor fields, findings, edge endpoints/reasons, original pointers, coverage notes, and an optional incident graph. Model identity, claim text, and failure text are scanned again after analysis before the pack hash is recomputed.

The permanent `complete_pack_serialization_redacts_every_hostile_field_family` test covers the previously missed edge, graph, external, finding, pointer, model-claim, and model-failure families and scans the complete serialized bytes. The independent re-review probe also placed the fixture secret in event IDs/metadata keys, edge endpoints/reasons, model identity, and model output; the complete pack contained no raw secret, its typed citation still resolved, and `validate_forensic_pack` passed.

The documented limitation remains correct: `SecretScanner` and configured patterns reduce disclosure risk but are not declassification or a guarantee against novel secret formats.

#### RESOLVED — P1 prompt/configuration provenance and incoming pack integrity

The CLI no longer accepts caller-supplied fingerprint labels. It requires `--prompt-file` and `--configuration-file`, reads the exact bytes, and the library computes lowercase `sha256:<64 hex>` fingerprints internally. Empty inputs reject, malformed fingerprints on deserialized model claims reject, and different prompt/configuration bytes produce different recorded digests. The derived output remains caller-supplied and covered by the recomputed pack hash; documentation explicitly avoids claiming model invocation attestation or deterministic replay.

`forensic analyze` now validates schema, exact citations, and the existing `pack_hash` before mutation. Both library and CLI tests prove a mismatched hash rejects without changing the in-memory pack or file. The independent probe separately computed SHA-256 over the supplied bytes and matched both recorded fingerprints, then confirmed a post-hash mutation rejected before analysis.

#### RESOLVED — P2 exact citation resolution

Citation creation uses canonical typed pointers (`event:`, `external:`, `finding:`), and insertion/validation now requires exact `original_pointers.contains(...)` equality. Suffix-only input rejects mutation-free in the permanent test and the independent probe. The earlier `ends_with` ambiguity is gone.

#### RESOLVED — P2 meaningful memory qualification and timing brittleness

The fixed wall-time assertions were removed from `incident_scale`; elapsed time is diagnostic only. The correctness tests still exercise 10,000 tied incident rows, cursor exhaustion, exact totals, stable ordering, bounded serialized detail, and CLI truncation honesty.

The new Linux-only `incident_memory_bound` binary installs a tracking allocator, materializes the independently import-bounded 10,000 evidence/10,000 edge input before its baseline, then measures incremental graph-assembly peak allocation. It verifies exact totals and 64-item detail caps under a 32 MiB assembly-growth budget. The re-review run measured **4,114,804 bytes**, comfortably below the permanent budget. Documentation accurately limits this claim to Linux incremental assembly memory and does not claim total-process RSS or unbounded streaming.

#### RESOLVED — P3 transformation-ledger accuracy

The export ledger now records deterministic per-field value counts as either `redacted:<path>:<changed>/<scanned>` or `scanned_unchanged:<path>:<scanned>`, plus `sanitize:enabled`. It no longer reports unchanged fields as redacted. The exhaustive export test requires both a changed path and an unchanged path, and `export_hash` covers the ledger with the complete artifact.

### Re-audit of Definition of Done

| # | Re-review result | Evidence / limitation |
|---|---|---|
| 1 | Pass | Immutable stored resolved boundary and stable policy inheritance/hash tests remain unchanged and green. |
| 2 | Pass | Containment states remain independently represented; configured cannot satisfy verified containment. |
| 3 | Pass | Missing required sensors/receipts remains fail-closed as insufficient or containment-unproven. |
| 4 | Pass | Versioned, bounded, atomic/idempotent import and integrity/path validation gates remain green. |
| 5 | Pass | Process, network/proxy, Kubernetes, AWS, and GCP mapping/correlation behavior remains covered. |
| 6 | Pass | Forged/cooperative identifiers and unverified integrity remain confidence-capped. |
| 7 | Pass | Evidence-linked deterministic violation/transition tests remain green. |
| 8 | Pass | Task correctness remains independently gateable from containment and provenance. |
| 9 | Pass | Discovery/reuse/earliest-signal and typed delegation/credential/artifact flow reconstruction remains covered. |
| 10 | Pass | Complete hostile pack serialization is secret-free under current scanner rules; typed citations resolve exactly and pack integrity validates. |
| 11 | Pass | Derived claims retain origin/model/output, internally computed exact-input fingerprints, exact citations, and mutation-free pre-analysis integrity validation. This records inputs/output; it does not attest that a model actually consumed them. |
| 12 | Pass | Incident exchange recursively sanitizes all serialized content/reference fields, preserves internal references, records accurate transformations, and detects post-export tampering. |
| 13 | Pass | Permanent imported adversarial and benign fixture families and quality thresholds remain in the 1.7 suite. |
| 14 | Pass | 10k storage/query/detail correctness plus measured Linux incremental assembly memory are permanent CI/release gates; wall time is diagnostic. |
| 15 | Pass | Docs state sensor, retention, partial-capture, sanitization, local-model, memory-measurement, and non-prevention limitations without claiming complete observability or declassification. |
| 16 | Pass | The exact fixed commit passes focused gates, clippy/format/docs, and the full Unix quick trust/integrity/boundary qualifier. |

### Re-review verification

```text
cargo test --test boundary_1_7_completion -- --nocapture
  PASS: 3 passed

cargo test --lib forensic::pack::tests -- --nocapture
  PASS: 7 passed

cargo test --lib incident::export::tests -- --nocapture
  PASS: 3 passed

cargo test --test incident_memory_bound -- --nocapture
  PASS: 1 passed; measured peak assembly growth 4,114,804 bytes / 33,554,432-byte budget

cargo test --test incident_scale -- --nocapture
  PASS: 3 passed; timing diagnostic only

independent temporary hostile re-review probe
  PASS: 3 passed (deep incident/reference sanitization; forensic/model sanitization and exact input hashes; pre-analysis tamper rejection)
  The probe was removed before this review-only commit.

cargo clippy --all-targets -- -D warnings
  PASS

cargo fmt --check
  PASS

python3 scripts/check_doc_links.py
  PASS: checked 483 file links + 89 anchors in 65 Markdown files

./scripts/release-qualify-unix.sh --quick
  PASS: 0 failed
  report: release-artifacts/qualify-20260722T161839Z.md
  report sha256: 7dab422b98496201fa1f555ea9f5249cca563486de6b3d314c197b0e90f402e6
```

### Final conclusion

All original P1, P2, and P3 findings are resolved with production behavior and permanent adversarial tests. DoD rows 10–15 now have executable evidence aligned with their documented limitations, and the overall 16-item audit passes on `d4664e8`. **Boundary 1.7 integration review 01 is PASS.**
