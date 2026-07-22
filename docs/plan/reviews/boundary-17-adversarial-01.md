# Review: boundary-17-adversarial

| Field | Value |
|---|---|
| Review | `boundary-17-adversarial-01` |
| Implementation | `8db853274086bbd59232599c404bec24e58b8e35` |
| Scope | Deterministic adversarial detectors, corpus, fixtures, and quality gate |
| Verdict | **Blocked** |

The focused tests, formatting gate, and Clippy gate pass. The committed quality
report is internally consistent: 20 TP + 0 FN gives recall 1.0; 20 TP + 0 FP
gives precision 1.0; 20 TP + 12 TN accounts for all 32 cases. That score does
not establish production-path correctness for the new detectors, however.

## Findings

### P1 — Blocking: ordinary child-process exits can become critical persistence findings

Locations:

- `src/boundary/detect.rs:560-574`
- `src/boundary/detect.rs:578-616`
- `src/boundary/corpus.rs:326-353`
- `src/boundary/corpus.rs:821-862`
- `src/boundary/detect.rs:919-951`

`detect_persistence_after_exit` treats every `ProcessExit` record as the end of
the parent/run signal. `same_execution` then accepts equality of any one of
`trace_id`, `run_id`, or `session`; it does not require a parent process
identity, terminal run marker, parent PID relationship, or independently
verified linkage. A normal run in which one traced child process exits and a
later traced process executes, writes a file, starts a container, or listens on
a socket therefore produces a **critical** `persistence_after_exit` finding.
Cooperative trace identity alone is also forgeable.

The positive corpus reproduces exactly the weak condition: two records share
only a trace ID. The service-startup and parallel-build controls contain no
preceding child exit, so neither exercises the false-positive path. The unit
test is positive-only as well.

Required resolution: distinguish a terminal parent/run exit from an arbitrary
process exit, require a causal parent/descendant or independently supported
lifecycle relationship, and add a strict-clean control containing a normal
child exit followed by later activity in the same run/trace.

### P1 — Blocking: telemetry-deception cases cannot reach the detector through normal import and detection

Locations:

- `src/boundary/detect.rs:705-771`
- `src/boundary/corpus.rs:382-423`
- `src/evidence/import.rs:146-185`
- `src/storage/sqlite.rs:755-771`
- `src/storage/sqlite.rs:2317-2355`
- `src/cli_ext.rs:1872-1887`

Both telemetry-deception positives bypass the production evidence lifecycle by
constructing conflicting records directly in memory:

1. `SignedInvalid` is rejected by the default importer before persistence.
2. A repeated `(source, source_event_id)` is discarded by the importer within
   a batch and is also prohibited by the SQLite unique constraint across
   imports.

`boundary detect` reads only persisted external evidence, so it cannot observe
either the rejected invalid-signature event or both sides of a source-identity
collision. The corpus can pass while `telemetry_integrity_invalid` and
`telemetry_identity_conflict` never produce findings in the normal CLI path.

Required resolution: preserve a bounded rejection/conflict record or emit and
persist the corresponding finding at import time, then qualify both cases from
NDJSON import through storage and `boundary detect`.

### P2 — Non-blocking after the P1 repairs: the parallel-build control does not exercise fan-out grouping

Locations:

- `src/boundary/detect.rs:621-700`
- `src/boundary/corpus.rs:356-379`
- `src/boundary/corpus.rs:840-862`

The abnormal-fan-out detector groups `ProcessExec` records when a sensor
provides `delegator`, `parent_workload`, or `parent_process`, counts every
distinct child over the entire input, and fires at eight. The 16-process benign
parallel-build control omits all three parent attributes, so it is excluded
before counting. If a realistic process sensor supplies the common parent, its
16 distinct `rustc` objects meet the detector threshold and become a high
finding. There is also no time window or policy/baseline signal separating an
abnormal burst from ordinary fan-out over a long run.

Required resolution: make the benign build control carry the same parent
relationship used by the positive, and refine the detector until that control
remains clean while the swarm case still fires.

### P2 — Non-blocking: persistence finding time is rewritten to the exit time

Locations:

- `src/boundary/detect.rs:157-170`
- `src/boundary/detect.rs:187-205`
- `src/boundary/detect.rs:603-616`

The persistence detector initially timestamps the finding at the continued
activity, which is when persistence becomes knowable. The subsequent global
normalizer replaces it with the minimum time among both citations, namely the
earlier exit marker. This moves the signal backward in the incident timeline.
The positive test checks citations but not the finding timestamp.

Required resolution: retain the continued-activity time for a transition whose
proof requires an ordered pair, and add an assertion covering it.

### P3 — Non-blocking: the fixture is a label manifest, not independent evidence input

Locations:

- `tests/fixtures/boundary_1_7/adversarial/corpus.json:1-12`
- `tests/boundary_detector_quality.rs:72-115`
- `src/boundary/corpus.rs:279-423`

The JSON fixture contains case IDs, expected detector names, and benign flags;
the actual evidence is generated in the same Rust module as the corpus. This is
permanent coverage, but it cannot catch decoder/import/storage incompatibility
and helped conceal the unreachable telemetry cases. Provider-neutral NDJSON
fixtures exercised through the importer would make the qualification more
independent.

## Benign-control assessment

| Required control | Present | Meaningful against new detector path |
|---|---:|---:|
| Legitimate dependency use | Yes | Yes — allowed install with verified artifact stays strict-clean |
| Service startup | Yes | Partial — single start does not test post-exit persistence or near-threshold fan-out |
| Parallel builds | Yes | No — omits the parent metadata that enables fan-out grouping |
| Unsigned telemetry | Yes | Yes — verifies `unverified` is not treated as invalid signature |

## Verification

Commands run:

```text
cargo test --lib boundary::detect
cargo test --lib boundary::corpus
cargo test --test boundary_detector_quality -- --nocapture
cargo clippy --all-targets -- -D warnings
cargo fmt --check
git diff --check
```

All commands passed. The task document's repeated `--lib` invocation was split
into two valid focused commands.

Observed quality output:

```text
cases=32 TP=20 FP=0 FN=0 TN=12 recall=1.000 precision=1.000 benign_fp=0
```

## Conclusion

**Blocked.** The deterministic implementations and metric arithmetic work on
the in-memory corpus, but the persistence detector has a material benign false
positive and the telemetry-deception detectors are unreachable through the
normal importer/store/detect path. Those P1 findings must be repaired and
covered end to end before this task can satisfy the 1.7 issue-completion gate.
