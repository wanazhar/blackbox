id: boundary-17-adversarial
scope: deterministic adversarial detection qualification
status: in-progress
depends-on: []

## objective

Add deterministic, evidence-linked detectors and permanent corpus cases for
poisoned input/supply-chain material, persistence beyond the parent/run signal,
swarm or abnormal fan-out, and deceptive/invalid telemetry. Add benign controls
for legitimate dependency use, service startup, parallel builds, and unsigned
telemetry. Maintain the committed precision/recall thresholds and ensure model
interpretation is not required.

## context

- `docs/plan/agent-boundary-1.7.md`
- `docs/plan/analysis/boundary-17-completion.md`
- `docs/reference/boundary.md`
- `AGENTS.md`

## path

- `src/boundary/detect.rs`
- `src/boundary/corpus.rs`
- `tests/boundary_detector_quality.rs`
- `tests/fixtures/boundary_1_7/adversarial/`

## verification

- `cargo test --lib boundary::detect --lib boundary::corpus`
- `cargo test --test boundary_detector_quality`
- `cargo clippy --all-targets -- -D warnings`
