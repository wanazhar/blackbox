# Getting started

A step-by-step walkthrough to install blackbox, enable a project, record your first run, inspect it, and use the Agent Memory Bus.

---

## 1. Install

### Binary (no Rust required)

```bash
curl -fsSL https://raw.githubusercontent.com/wanazhar/blackbox/master/install.sh | sh
```

### From crates.io

```bash
cargo install blackbox-recorder
```

### Verify

```bash
blackbox --version
# Should print: blackbox-recorder 1.2.0
blackbox doctor
# Should show store path, schema version, and environment
```

---

## 2. Enable a project

Create a new project or use an existing one:

```bash
cd ~/my-project

# Enable blackbox for this project + install shell wrappers
blackbox enable --install-shell

# With memory bus (recommended for new projects)
blackbox enable --memory-bus --install-shell
```

What `enable` does:
1. Creates the `.blackbox/` directory structure
2. Writes a default `.blackbox/config.toml`
3. Sets `capture.continuity = "always"` (with `--memory-bus`)
4. Installs shell wrappers for common agent harnesses (claude, codex, aider, etc.)

### Shell wrappers

Shell wrappers are managed blocks in your `~/.bashrc`, `~/.zshrc`, or PowerShell profile. They look like:

```bash
# >>> blackbox >>>
command blackbox maybe-run -- <name> "$@"
# <<< blackbox <<<
```

Wrappers never hard-fail: if `blackbox` is missing from PATH, the bare command is invoked.

---

## 3. Record your first run

```bash
# Run a command under observation
blackbox run -- echo hello world

# Output:
# [handoff hint when failure attention is needed]
# Run completed: <short-id>  (succeeded)
```

### What happens

1. Blackbox creates a new `Run` record
2. Capture layers start: **PTY** (terminal I/O), **Git** (snapshot), **Filesystem** (file writes), **Process** (child lifecycle)
3. The command runs under a pseudo-terminal
4. All output is captured, normalized (ANSI stripped), and redacted for secrets
5. Large output is stored as content-addressed blobs
6. On completion: run is updated, checkpoint is written, memory pack is refreshed, attention is computed

### Record a CI job

```bash
blackbox run --ci --artifact-dir ./artifacts -- npm test
```

`--ci` propagates the child exit code. `--artifact-dir` writes `run.json`, `postmortem.json`, and `portable.json` to the specified directory.

---

## 4. Inspect the result

```bash
# List recent runs
blackbox runs

# Show details of a specific run
blackbox show <short-id>

# View the event timeline
blackbox timeline <short-id>

# Inspect a specific event
blackbox timeline <short-id> --kind tool.call
blackbox inspect <event-id>
```

### With JSON output

```bash
blackbox runs --json
blackbox show <short-id> --json
blackbox timeline <short-id> --json
```

All commands accept `--json` for machine-readable output wrapped in the `blackbox.cli/v1` envelope.

---

## 5. Postmortem a failed run

When a run fails, blackbox sets `attention_level = continue` and provides rich context:

```bash
# Quick failure analysis
blackbox postmortem latest --json

# Contains: headline, attention_reason, failed_tools, errors_top, side_effects, summary
```

The handoff command packages this for the next agent:

```bash
blackbox handoff --json
# Returns: status + project_memory + resume_pack (when attention needed)
```

---

## 6. Use the Memory Bus

If you enabled with `--memory-bus`, every supervised launch delivers project memory:

```bash
# View the current project memory pack
blackbox memory show --json

# Set a project goal and open items
blackbox memory set --goal "Fix CI pipeline" --open "Fix flaky test" --open "Update README"

# Acquire a project claim (prevents concurrent agent conflicts)
blackbox claim acquire --holder "my-agent"

# Release when done
blackbox claim release

# Clear an unresolved failure
blackbox resolve

# With --clear-wip (also clears open items and goal)
blackbox resolve --clear-wip
```

---

## 7. Next steps

| Guide | What it covers |
|---|---|
| [Configuration](configuration.md) | All CLI flags, env vars, config.toml options |
| [Security](security.md) | Redaction model, what's captured, safe defaults |
| [Export and sync](export-and-sync.md) | Export formats, sync push/pull to dir/S3/HTTP |
| [Troubleshooting](troubleshooting.md) | Common issues, FAQ, doctor diagnostics |

### CLI reference

For a complete list of all subcommands with arguments, examples, and JSON schemas, see the [CLI reference](../reference/cli.md).

### Architecture

For contributors and deep-dive readers, the [architecture doc](../internals/architecture.md) describes the full data flow and module structure.
