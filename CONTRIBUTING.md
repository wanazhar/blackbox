# Contributing

Thanks for improving blackbox.

## Setup

```bash
git clone <this-repo>
cd blackbox
cargo test
cargo clippy --all-targets -- -D warnings
```

Stable Rust (edition 2021). No extra system libraries beyond a normal Rust toolchain (SQLite is bundled via `rusqlite`).

## Workflow

1. Keep changes focused — one concern per commit when practical.
2. Match existing style (`cargo fmt`).
3. Prefer `anyhow::Result` at CLI boundaries; keep redaction defaults safe.
4. Add or extend tests for redaction, storage, export/import, and sync behavior.
5. Do not commit runtime stores: `.blackbox/`, `blackbox.db`, `*.db-wal`, `*.db-shm`.

## Architecture pointers

See [`AGENTS.md`](AGENTS.md) for module map and quality bar.  
Open product work lives in [`docs/ROADMAP.md`](docs/ROADMAP.md) — ignore `docs/history/` as a backlog.

## License

By contributing, you agree that your contributions are dual-licensed under MIT OR Apache-2.0, the same as the project.
