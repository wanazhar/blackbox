id: boundary-17-incidents
scope: incident flow reconstruction and scale honesty
status: ready
depends-on: []

## objective

Extend incident reconstruction with explicit typed delegation, credential-use,
and artifact-derivation flows derived from evidence edges. Preserve endpoint
references, run attribution, confidence, and reasons. Add explicit graph detail
limits/truncation totals so large incidents remain bounded without understating
aggregate counts. Qualify cursor/storage and graph behavior at at least 10,000
records with deterministic pagination and no duplicate/lost IDs.

## context

- `docs/plan/agent-boundary-1.7.md`
- `docs/plan/analysis/boundary-17-completion.md`
- `docs/reference/boundary.md`
- `AGENTS.md`

## path

- `src/incident/graph.rs`
- `src/incident/page.rs`
- `tests/incident_graph_flow.rs`
- `tests/incident_scale.rs`

## verification

- `cargo test --lib incident::graph`
- `cargo test --test incident_graph_flow --test incident_scale`
- `cargo clippy --all-targets -- -D warnings`
