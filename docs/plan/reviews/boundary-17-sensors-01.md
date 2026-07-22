# Review: boundary-17-sensors-01

| Field | Value |
|---|---|
| Task | `boundary-17-sensors` |
| Implementation | `075a92ff75ba318ae81fb280470b752268af227a` |
| Reviewer verdict | **Blocked** |
| Date | 2026-07-22 |

The Kubernetes, AWS CloudTrail, and GCP audit adapters map the committed valid
fixtures without inventing required source-event IDs. The focused tests and
static quality gates pass. The task is nevertheless blocked because the
completion contract requires principal-aware orchestration correlation, while
the implemented correlation path cannot consume principal identity. Two
schema-honesty gaps also remain.

## Findings

### P1 — blocking: mapped principal identity does not participate in correlation

The completion contract says Kubernetes/cloud events must feed correlation
using workload, principal, and trace identity
(`docs/plan/analysis/boundary-17-completion.md:20-22`). The adapters preserve
principal values (`src/evidence/adapters.rs:70-71`, `143-153`, and `194-208`),
but `CorrelationContext` has no principal field and the correlator only scores
trace ID, run ID, import link, host, workload, and PID
(`src/boundary/correlate.rs:137-145` and `162-203`).

The integration test consequently establishes correlation with a cooperative
trace annotation, a workload annotation, and a caller-supplied
`default_run_id` (`tests/evidence_orchestration.rs:120-146`). It asserts that
the principal was mapped, but never demonstrates that principal contributes to
the edge. No cloud event is correlated either. This does not meet the stated
principal-aware integration requirement.

Required resolution: extend the correlation context and confidence reasons to
consume an expected principal (with an appropriate trust/confidence policy),
then add a Kubernetes or cloud test showing principal participation. Retain the
existing trace-only confidence cap.

### P1 — blocking: malformed cloud outcome fields can become `success`

AWS mapping treats any record whose `errorCode` is absent **or not a string** as
successful (`src/evidence/adapters.rs:530-540`). GCP mapping similarly treats a
missing status and a present status whose `code` is not an integer identically
as successful (`src/evidence/adapters.rs:543-549`). Thus malformed telemetry
such as `"errorCode": 7` or `"status":{"code":"7"}` is silently promoted to
success instead of `unknown` or rejection. This violates the task's outcome
preservation and schema-honesty objective
(`docs/plan/tasks/boundary-17-sensors.md:8-13`).

The malformed fixture only covers missing required identity/action/timestamp
fields (`tests/fixtures/boundary_1_7/orchestration/malformed.ndjson:1-3`), so
the false-success cases are not exercised.

Required resolution: distinguish an absent provider error/status field from a
present field with an invalid type or value. Invalid representations must be
rejected or map honestly to `unknown`, with permanent fixtures for AWS and GCP.

### P2 — blocking: the documented store-survival integration is untested

The completion enumeration requires normalized events to “survive store import”
before correlation (`docs/plan/analysis/boundary-17-completion.md:20-22`). The
new tests call the in-memory NDJSON parser and correlate its returned vector
directly (`tests/evidence_orchestration.rs:18-19`, `62`, and `120-134`). They do
not insert or retrieve an event through `TraceStore`, nor exercise the atomic
evidence batch path. Adapter parsing is covered, but the documented persistence
boundary is not.

Required resolution: add a SQLite-backed round-trip that imports at least one
Kubernetes or cloud event, reads it back with identity/action/outcome intact,
and correlates the stored value.

### P2 — blocking: Kubernetes `sourceIPs` validation accepts invalid element types

The adapter declares `sourceIPs` required but validates only that it is a
non-empty array (`src/evidence/adapters.rs:122-128`). A value such as
`"sourceIPs":[42]` is accepted and copied into normalized attributes
(`src/evidence/adapters.rs:107`), even though it is not a schema-valid list of
source address strings. The malformed coverage tests only omission, not wrong
types (`tests/evidence_orchestration.rs:106-117`).

Required resolution: require at least one non-empty string and reject malformed
elements, with a wrong-type fixture.

### P3 — non-blocking: malformed diagnostics discard the actionable field list

`mark_malformed` records the precise missing/invalid fields in
`coverage_notes`, then clears `source` so the generic event validator rejects
the event (`src/evidence/adapters.rs:565-576`). The importer reports only the
validator error, so callers receive `source is required`; the integration test
locks in that indirect diagnostic (`tests/evidence_orchestration.rs:113-116`).
The actionable field list is discarded with the rejected event.

Prefer a fallible adapter result or propagate the coverage-note reason into the
import rejection. This does not by itself invalidate stored evidence because
the malformed records are rejected.

## Verification

Executed from the isolated `boundary-17-sensors` worktree:

```text
cargo test --lib evidence::adapters
  3 passed; 0 failed

cargo test --test evidence_orchestration
  4 passed; 0 failed

cargo clippy --all-targets -- -D warnings
  passed

cargo fmt --check
  passed

git diff 075a92f^ 075a92f --check
  passed
```

## Conclusion

**Blocked.** The adapters cover representative valid and missing-field
fixtures and preserve the tested identity fields, but principal-aware
correlation is absent and malformed cloud outcomes can be asserted as success.
Resolve both P1 findings and the schema/store P2 acceptance gaps before merging
this task into the 1.7 completion branch.
