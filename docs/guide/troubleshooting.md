# Troubleshooting

Common issues, diagnostics, and recovery procedures for blackbox.

---

## 1. Diagnostics

### Health check

```bash
blackbox doctor
```

Shows: store path, schema version, run count, database size, blob count and size, and any storage warnings.

### With JSON output

```bash
blackbox doctor --json
```

Returns all fields in machine-readable format for programmatic inspection.

### Stats

```bash
blackbox stats
```

Shows: total runs, events, blobs, storage sizes, and retention auto_apply status.

---

## 2. Common issues

### "blackbox: command not found"

The binary is not in PATH:

```bash
# Binary install
curl -fsSL https://raw.githubusercontent.com/wanazhar/blackbox/master/install.sh | sh

# Or from crates.io
cargo install blackbox-recorder

# Verify
blackbox --version
```

### "No project found"

Blackbox could not find an enabled project. Ensure you're in a project directory that has been enabled:

```bash
# Check if enabled
blackbox status

# Enable if not
blackbox enable
```

Blackbox walks ancestors from the current working directory looking for `.blackbox/`. If your project root is above the current directory, it will be found.

### Store path resolution unexpected

If `blackbox doctor` shows a different store path than expected, check:

1. `BLACKBOX_DB` env var is not set unexpectedly
2. No leftover `./blackbox.db` from an older version (legacy path takes priority over `.blackbox/`)
3. `--store` flag was not passed to a previous command

### "Continuity not working as expected"

```bash
# Check current continuity mode
blackbox status --json | grep continuity

# Check effective mode (after precedence resolution)
# Precedence: CLI flag > BLACKBOX_CONTINUITY > BLACKBOX_AUTO_RESUME > config > project default
```

If `continuity=always` but no inject is happening:
- Check `BLACKBOX_OFF` is not set
- Check you're in an enabled project
- Check the harness is in the wrap list

### "Attention level stuck on 'continue' after successful run"

This is **M6 by design** — an unrelated success does not clear an unresolved failure. To clear:

```bash
blackbox resolve
```

If the issue is a dirty git tree showing `.blackbox/` as dirty, ensure `.blackbox/` is in `.gitignore` or update to the latest version (1.2.0) which filters `.blackbox/` paths from the porcelain check.

### "Memory pack is empty or degraded"

A `degraded = true` pack means the store could not be opened. Possible causes:
- Store file locked by another process
- Store file corrupted (run `blackbox doctor` to check)
- Build exceeded 2-second hard degrade threshold

The pack is still injected — degraded means sticky-only, no store data.

### "Blobs growing unbounded"

Configure retention to auto-clean:

```toml
# .blackbox/config.toml
[retention]
auto_apply = true
keep_runs = 50
```

Or manually GC:

```bash
blackbox purge --keep 50
blackbox scrub --gc
```

---

## 3. Recovery

### Recover from crash

If blackbox was killed during recording, the run will be marked as `Failed` on the next store open. This happens automatically — no action needed.

```bash
blackbox doctor
# Should show: "Recovered N abandoned runs"
```

### Re-apply redaction to historical runs

If new secret patterns have been added:

```bash
blackbox scrub
```

This re-applies the current `SecretScanner` rules to all historical events without touching blob content.

### Re-import from backup

```bash
blackbox import trace.json
```

Reconstructs the full store from a portable export.

---

## 4. FAQ

**Q: Does blackbox slow down my agent?**  
A: The overhead is minimal — ~50ms for continuity=always on a `true` run (tested in `tests/overhead_smoke.rs`). Git porcelain has a 500ms timeout; if it fails, `dirty=false` is used.

**Q: Can I use blackbox without installing shell wrappers?**  
A: Yes. Shell wrappers enable ambient capture (auto-record when you run `claude` in the project). Without them, you must use `blackbox run -- <command>` explicitly.

**Q: Does blackbox work with Windows?**  
A: Partially. Unix PTY is supported on Linux/macOS. Windows has soft/hard kill via `taskkill` and PowerShell profile install. Interactive TUI parity is a low-priority post-1.2 item.

**Q: How do I share a trace with someone?**  
A: Use `blackbox export <run-id> -o trace.json`. The export is redacted by default — no secrets leak. The recipient imports it with `blackbox import trace.json`.

**Q: What happens when my project has no `.blackbox/` directory?**  
A: `blackbox status` shows "not enabled". Run `blackbox enable` to create it.

**Q: How is this different from just recording terminal output?**  
A: Blackbox provides structured events (tool calls, file writes, git state), harness adapter parsing, secret redaction, side-effect classification, search, and the continuity plane — it's a structured trace, not a raw text log.

**Q: Why "blackbox-recorder" on crates.io but "blackbox" everywhere else?**  
A: The name `blackbox` is already taken on crates.io. The binary, library, and CLI are all `blackbox`; only the package name had to change.
