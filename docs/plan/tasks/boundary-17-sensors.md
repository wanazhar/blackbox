id: boundary-17-sensors
scope: external evidence adapters and orchestration correlation
status: done
depends-on: []

## objective

Add schema-safe Kubernetes audit and cloud-audit sensor adapters, fixtures, and
an end-to-end importer-to-correlation test. Preserve source identity, principal,
workload/container/namespace, action, destination/object, outcome, and source
event identity. Unknown or malformed required fields must not be silently
invented. Demonstrate correlation for at least one orchestration/cloud source
without allowing cooperative trace identity alone to become confirmed.

## context

- `docs/plan/agent-boundary-1.7.md`
- `docs/plan/analysis/boundary-17-completion.md`
- `docs/reference/boundary.md`
- `AGENTS.md`

## path

- `src/evidence/adapters.rs`
- `tests/evidence_orchestration.rs`
- `tests/fixtures/boundary_1_7/orchestration/`

## verification

- `cargo test --lib evidence::adapters`
- `cargo test --test evidence_orchestration`
- `cargo clippy --all-targets -- -D warnings`
