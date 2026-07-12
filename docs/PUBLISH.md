# Publishing blackbox-recorder

The **Cargo package name** is `blackbox-recorder` (the `blackbox` name is taken on crates.io).  
The **CLI binary** and **Rust library path** remain `blackbox`.

## Prerequisites

1. crates.io account: https://crates.io  
2. API token: https://crates.io/settings/tokens  
3. Export the token (never commit it):

```bash
export CARGO_REGISTRY_TOKEN=cio_...
```

## Dry-run (safe)

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo publish --dry-run
```

## Publish

```bash
cargo publish
```

After publish:

```bash
cargo install blackbox-recorder
# provides `blackbox` on PATH
```

## Optional: GitHub release

```bash
git tag v0.1.0
git push origin v0.1.0
# attach release binaries via CI if desired
```

## Note on renaming

If you prefer a different crates.io name, change only:

```toml
[package]
name = "your-name-here"
```

Keep `[lib] name = "blackbox"` and `[[bin]] name = "blackbox"` so the CLI and `use blackbox::…` stay stable.
