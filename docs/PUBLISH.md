# Publishing blackbox-recorder

The **Cargo package name** is `blackbox-recorder` (the name `blackbox` is taken on crates.io).  
The **CLI binary** and **Rust library path** remain `blackbox` (`use blackbox::…`).

## Prerequisites

1. crates.io account: https://crates.io  
2. API token: https://crates.io/settings/tokens  
3. Export the token (never commit it):

```bash
export CARGO_REGISTRY_TOKEN=cio_...
```

4. Confirm package metadata in `Cargo.toml` (`version`, `description`, `license`, `readme`).  
   Add `repository` / `homepage` when a public git remote exists — do not leave placeholder URLs.

## Pre-flight

```bash
# Clean workspace of local run artifacts (never ship these)
rm -rf .blackbox blackbox.db blackbox.db-wal blackbox.db-shm

cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo publish --dry-run
```

`cargo publish --dry-run` packs the crate the same way a real publish does. Skim the file list: no `.blackbox/`, no `*.db`, no secrets.

## Publish

```bash
# Bump version in Cargo.toml + CHANGELOG.md first if needed
cargo publish
```

After publish:

```bash
cargo install blackbox-recorder
# provides `blackbox` on PATH
blackbox --version
blackbox doctor
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

## Dual license

The crate is dual-licensed **MIT OR Apache-2.0**. Source tree includes:

- `LICENSE-MIT`
- `LICENSE-APACHE`

`Cargo.toml` must keep `license = "MIT OR Apache-2.0"`.
