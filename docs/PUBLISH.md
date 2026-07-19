# Publishing blackbox-recorder

> **Maintainer checklist** for crates.io releases — not an operator guide.  
> Users: [README.md](https://github.com/wanazhar/blackbox/blob/master/README.md). Docs quality before release: `python3 scripts/check_doc_links.py` and `cargo test --test docs_first_run --test docs_cli_envelope`.

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

# 1.4+ preferred: one Unix qualification command (checksummed report → release-artifacts/)
./scripts/release-qualify-unix.sh
# optional release-mode timed smoke:
# ./scripts/release-qualify-unix.sh --release

# Equivalent manual steps (still valid):
cargo fmt --check
cargo clippy --all-targets -- -D warnings
python3 scripts/check_doc_links.py
cargo test --all-targets
cargo test --test docs_first_run
# Docs live in-repo under docs/ (no GitHub Pages deploy).
# Optional local preview only: pip install -r requirements-docs.txt && mkdocs serve
cargo publish --dry-run
```

Do **not** tag a 10/10 Trust Proof release while any mandatory qualify gate is RED.

`cargo publish --dry-run` packs the crate the same way a real publish does. Skim the file list: no `.blackbox/`, no `*.db`, no secrets, no `release-artifacts/`.

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
git tag v1.4.0
git push origin v1.4.0
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
