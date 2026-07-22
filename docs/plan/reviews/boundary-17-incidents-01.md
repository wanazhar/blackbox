# Review: boundary-17-incidents-01

| Field | Value |
|---|---|
| Task | `boundary-17-incidents` |
| Implementation | `983be0432c11253f84ed5dfd28af8777c0491022` |
| Reviewer verdict | **Blocked** |
| Date | 2026-07-22 |

The implementation correctly projects delegation, credential-use, and
artifact-derivation edges into typed flows while preserving endpoint kinds and
IDs, run attribution, confidence, reasons, edge ID, and time. Its keyset cursor
also exhausts 10,000 tied-timestamp incidents exactly once. The task is blocked
because the production CLI summary still derives aggregates from truncated
detail, and the unchanged v1 schema gives legacy graphs false zero totals.

## Findings

### P1 — blocking: production incident aggregates understate truncated totals

`IncidentGraph` now exposes exact `technique_count` and `reuse_count` values
before detail truncation (`src/incident/graph.rs:425-430` and `463-467`). The
CLI consumer does not use them. `incident show` recomputes reuse over
`g.techniques` and passes `g.techniques.len()` into the aggregate builder
(`src/cli_ext.rs:2255-2270`). Both values describe only the serialized prefix
when `detail_limits.techniques` is exceeded.

The human output likewise prints `g.techniques.len()` and does not surface the
truncation state (`src/cli_ext.rs:2294-2306`). Thus a large incident can return
an exact graph total and an understated aggregate/human summary in the same
response. This violates the task requirement that CLI/store incident assembly
remain bounded “without understating aggregate counts”
(`docs/plan/tasks/boundary-17-incidents.md:11-12`) and the completion contract
(`docs/plan/analysis/boundary-17-completion.md:26-28`).

Required resolution: use `g.technique_count` and `g.reuse_count` for aggregates
and human output, and explicitly display truncation whenever
`g.truncation.is_truncated()`.

### P2 — blocking: legacy v1 graphs deserialize to dishonest zero totals

The graph schema remains `blackbox.incident.graph/v1`
(`src/incident/graph.rs:451-452`) and the new count, limit, and truncation fields
all use Serde defaults (`src/incident/graph.rs:205-219`). A graph produced by
the prior v1 implementation can contain non-empty `edges` and `techniques`, yet
deserialize with `edge_count = 0`, `technique_count = 0`, default 2,000-item
limits, and zero truncation. That is wire-compatible decoding but not honest
backward-compatible semantics.

No legacy-v1 deserialization case exists in the graph unit or integration tests
(`src/incident/graph.rs:473-560`; `tests/incident_graph_flow.rs:33-176`).

Required resolution: either version the changed aggregate contract or provide
legacy-aware deserialization/normalization that derives known totals from the
included vectors and represents unknowable truncation as unknown. Add a frozen
pre-change v1 fixture.

### P2 — blocking: the 10k graph gate does not exercise truncated technique/reuse honesty

The 10k reconstruction fixture creates 10,000 external records without
destinations and cycles its edges among four relations
(`tests/incident_scale.rs:72-103`). The graph therefore produces only one
technique (`credential_use`) and no cross-run reuse. Although the test configures
`techniques: 32`, it never crosses that limit and does not assert
`technique_count`, `reuse_count`, or technique truncation
(`tests/incident_scale.rs:105-137`). This leaves the exact path used by the P1
consumer bug outside high-volume qualification.

Required resolution: make the 10k fixture produce more than the technique
limit, include reuse across multiple attached runs, and assert exact aggregate
totals plus explicit technique truncation. A CLI/store assembly assertion should
consume those exact fields.

### P3 — non-blocking: truncated edge/flow detail lacks a deterministic tie order

The bounded graph retains the first input edges and flows
(`src/incident/graph.rs:431-440`). Production edge retrieval orders only by
`created_at`, with no ID tie-breaker (`src/storage/sqlite.rs:2536-2545`). Equal
timestamps can therefore select a different serialized detail prefix while
reporting identical totals. The 10k graph test bypasses storage and supplies an
already deterministic vector (`tests/incident_scale.rs:72-119`).

Add `id` as a stable tie-breaker in edge retrieval or sort by `(created_at, id)`
before applying graph limits. This does not corrupt totals, so it is
non-blocking for evidence honesty but should be fixed for reproducible exports.

## Verified behavior

- Typed flows preserve the originating edge ID, both endpoint references and
  kinds, run ID, confidence, reasons, and timestamp
  (`src/incident/graph.rs:113-127`; `tests/incident_graph_flow.rs:33-112`).
- Flow counts are computed over all source edges before detail truncation
  (`src/incident/graph.rs:433-448`).
- Node, edge, flow, and technique detail vectors have explicit limits and
  total/included/truncated metadata (`src/incident/graph.rs:130-184`).
- SQLite incident pagination uses `(created_at, id)` keyset ordering and fetches
  one extra row to calculate `has_more`
  (`src/storage/sqlite.rs:2762-2823`).
- The 10k cursor test found no duplicate or lost incident IDs, including the
  tied-timestamp case (`tests/incident_scale.rs:19-60`).

## Verification

Executed from the isolated `boundary-17-incidents` worktree:

```text
cargo test --lib incident::graph
  2 passed; 0 failed

cargo test --test incident_graph_flow --test incident_scale -- --nocapture
  incident_graph_flow: 2 passed; 0 failed
  incident_scale: 2 passed; 0 failed
  10k graph reconstruction: 12.97 ms
  10k storage pagination: 1.05 s

cargo clippy --all-targets -- -D warnings
  passed

cargo fmt --check
  passed

git diff 983be04^ 983be04 --check
  passed
```

## Conclusion

**Blocked.** The core typed-flow and cursor mechanics pass, but release-level
aggregate honesty is not complete in the production consumer, legacy v1 graph
payloads acquire false zero totals, and the 10k gate misses the truncated
technique/reuse path where the consumer defect occurs. Resolve the P1 and P2
findings before merging this task into the 1.7 completion branch.

---

## Re-review after `4a0668ff885c98908903ee407955dcda38be9091`

| Field | Value |
|---|---|
| Re-review date | 2026-07-22 |
| Remediation | `4a0668ff885c98908903ee407955dcda38be9091` |
| Final verdict | **Pass** |

The remediation was inspected independently and every original finding is
resolved.

### P1 production aggregate understatement — resolved

The graph now exposes optional pre-truncation totals and marks newly built
graphs with `counts_exact = true` under the new
`blackbox.incident.graph/v2` schema
(`src/incident/graph.rs:187-265`, `src/incident/graph.rs:484-534`). Both
production consumers call `compute_incident_aggregates_from_graph`, which uses
`technique_total()` and `reuse_total()` rather than serialized vector lengths
(`src/incident/page.rs:100-120`, `src/cli_ext.rs:2253-2258`,
`src/serve.rs:971-980`). Human CLI and dashboard output also expose complete,
truncated, or unknown-legacy detail state (`src/cli_ext.rs:2282-2314`,
`src/serve.rs:981-1020`).

The CLI-backed regression inserts 1,001 unique destination techniques into
SQLite, runs the actual `blackbox incident show --graph` command, and verifies:

- serialized detail contains 1,000 techniques;
- graph and aggregate totals both report 1,001;
- `counts_exact` is true;
- JSON reports one truncated technique;
- human output reports both `techniques=1001` and
  `techniques=1000/1001`.

This closes the production-consumer gap, not merely the graph-builder unit
path (`tests/incident_scale.rs:169-255`).

### P2 legacy v1 zero totals — resolved

The changed aggregate contract is versioned as
`blackbox.incident.graph/v2`. Aggregate fields, limits, and truncation are
optional on decode; a pre-change v1 payload therefore retains included-vector
lower bounds rather than acquiring asserted zeros. `counts_exact = false` and
`is_detail_truncated() = None` explicitly represent the unknowable legacy
remainder (`src/incident/graph.rs:205-265`). Aggregates propagate that honesty
bit (`src/incident/page.rs:100-120`).

The frozen v1 fixture contains one legacy edge and one reused technique, then
asserts lower bounds of one edge, one flow, one technique, and one reuse while
retaining unknown truncation and non-exact aggregates
(`tests/incident_graph_flow.rs:183-230`). This is honest backward compatibility.

### P2 10k technique/reuse truncation gate — resolved

The scale fixture now creates 10,000 external records across two attached runs
with 250 repeating destinations and four edge relations. Independent count
verification matches the test:

- 250 distinct destination techniques, all observed in both runs;
- one `credential_use` technique, also observed in both runs;
- 251 exact techniques and 251 exact reuse entries;
- 7,500 typed flows, split evenly across delegation, credential use, and
  artifact derivation;
- only 32 technique details retained, with 219 explicitly truncated.

The regression asserts those exact totals and passes the graph to the same
aggregate helper used by CLI/dashboard consumers
(`tests/incident_scale.rs:63-166`). Graph construction remained bounded and
completed in 28.64 ms in this re-review run.

### P3 deterministic tied edge/flow detail — resolved

Graph construction sorts edges by `(created_at, id)` before applying edge and
flow limits (`src/incident/graph.rs:439-503`), and SQLite retrieval uses the
same stable tie-breaker (`src/storage/sqlite.rs:2541-2547`). Technique first
discovery and earliest-signal selection also use stable reference-ID
tie-breakers (`src/incident/graph.rs:278-320`, `src/incident/graph.rs:397-405`).

The regression shuffles eight equal-timestamp edges and obtains the same
`edge-00`, `edge-01`, `edge-02` prefix and matching flow prefix both times
(`tests/incident_graph_flow.rs:232-288`). The 10,000-incident tied-timestamp
storage cursor still exhausts every ID exactly once in descending ID order.

## Re-review verification

Commands executed from the isolated incident worktree:

```text
cargo test --lib incident::graph
cargo test --test incident_graph_flow --test incident_scale -- --nocapture
cargo clippy --all-targets -- -D warnings
cargo fmt --check
git diff 875b6de..4a0668f --check
```

Results:

```text
incident::graph: 2 passed; 0 failed
incident_graph_flow: 4 passed; 0 failed
incident_scale: 3 passed; 0 failed
10k graph reconstruction: 28.641133 ms
10k storage pagination: 1.064377496 s
clippy, formatting, and diff checks: passed
```

## Final conclusion

**Pass.** Exact production aggregates, legacy v1 honesty, high-volume
technique/reuse truncation, and deterministic tied ordering now have direct
executable coverage. No blocking or non-blocking findings remain from this
review.
