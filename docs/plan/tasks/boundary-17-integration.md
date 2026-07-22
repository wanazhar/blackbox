id: boundary-17-integration
scope: issue #5 end-to-end qualification and release documentation
status: in-progress
depends-on: [boundary-17-sensors, boundary-17-incidents, boundary-17-adversarial]

## objective

Audit every issue #5 Definition of Done item against executable evidence, add a
single end-to-end integration fixture where needed, update operator/reference
documentation and release gates, and change the plan status to implementation
complete only when every criterion is supported by a passing test or an explicit
documented non-goal consistent with the issue.

## context

- `docs/plan/agent-boundary-1.7.md`
- `docs/plan/analysis/boundary-17-completion.md`
- `docs/ROADMAP.md`
- `CHANGELOG.md`
- `AGENTS.md`

## path

- `tests/boundary_1_7_completion.rs`
- `src/forensic/pack.rs`
- `src/cli_ext.rs`
- `docs/plan/agent-boundary-1.7.md`
- `docs/guide/boundaries-and-incidents.md`
- `docs/guide/security.md`
- `docs/reference/boundary.md`
- `docs/reference/cli.md`
- `docs/ROADMAP.md`
- `CHANGELOG.md`
- `.github/workflows/ci.yml`
- `scripts/release-qualify-unix.sh`

## verification

- `cargo test --test boundary_1_7_completion`
- `cargo test --all-targets`
- `cargo clippy --all-targets -- -D warnings`
- `cargo fmt --check`
- `python3 scripts/check_doc_links.py`
- `./scripts/release-qualify-unix.sh --quick`
