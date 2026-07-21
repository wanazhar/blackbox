# Install

How to get a `blackbox` binary on PATH, verify it, and what to check when install fails.

---

## Requirements

- **OS:** macOS or Linux for full PTY supervision; Windows is supported with documented soft/hard kill and PowerShell install paths (see CLI help / troubleshooting for platform notes).
- **No Rust required** for the binary install script.
- **Rust toolchain** only if you build from crates.io or source (`cargo install` / `cargo build`).

---

## Binary install (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/wanazhar/blackbox/master/install.sh | sh
```

The script installs a prebuilt `blackbox` when available for your platform, or falls back per script logic. Ensure the install location is on your `PATH` (the script usually prints where it put the binary).

---

## crates.io

```bash
cargo install blackbox-recorder
```

The **package name** is `blackbox-recorder`; the **binary name** is `blackbox`.

From a git checkout:

```bash
cargo install --path . --locked
# or
cargo build --release
# binary: target/release/blackbox
```

---

## Verify

```bash
blackbox --version
# example: blackbox-recorder 1.2.0

blackbox doctor
```

`doctor` reports store discovery, schema, encryption/backup tips, daily-driver score notes, and common misconfigurations. JSON form: `blackbox doctor --json`.

Shell completions (optional):

```bash
blackbox completions bash   # or zsh, fish
```

---

## Install failed?

| Symptom | Check |
|---|---|
| `command not found` | PATH; rehash shell; confirm install dir |
| Wrong/old binary | `which -a blackbox`; version string |
| crates.io build errors | Rust stable, edition 2021; full log from `cargo install -v` |
| Permission denied on install dir | Install prefix writable, or use `cargo install --root …` |

More cases: [troubleshooting.md](troubleshooting.md).

---

## Next

1. Read the [mental model](what-is-blackbox.md) if you have not already.
2. Enable a project and record a run: [getting-started.md](getting-started.md).
