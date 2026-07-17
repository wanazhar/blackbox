# Troubleshooting

**Answers:** How to diagnose install/store/ambient/continuity problems, recover abandoned runs, reclaim disk, and distinguish “capture is broken” from “the agent failed.”

| If the problem is… | Go here instead |
|---|---|
| Agent logic failed but capture looks fine | [debug-a-failure.md](debug-a-failure.md) |
| Install only | [install.md](install.md) |
| Ambient policy questions | [leave-it-on.md](leave-it-on.md) |
| Secrets / permissions | [security.md](security.md) |
| Doctor score / capture quality fields | [doctor-and-capture.md](doctor-and-capture.md) |
| Interpreting handoff JSON | [examples.md](examples.md) |

---

## 1. Always start with diagnostics

```bash
blackbox --version
which -a blackbox
blackbox doctor
blackbox doctor --json
blackbox stats
blackbox status
```

### What to look for in `doctor`

| Signal | Meaning |
|---|---|
| Store path | Unexpected path → env legacy db / `--store` (see config) |
| Schema version | Migration or corrupt open issues |
| Run count / DB + blob sizes | Growth / retention |
| Permission warnings | Group/other-readable store |
| `encrypt_blobs` / key path | Crypto on? External key? |
| Orphan `Running` runs | Crash mid-run; recovered on open as `Failed` |
| Capture quality notes | Last run coverage/lag warnings |
| Daily-driver score notes | Soft score + tips (ambient, vault, eval, …) |

Field-level guide: [doctor-and-capture.md](doctor-and-capture.md). `stats` summarizes runs/events/blobs and retention auto-apply.

---

## 2. Common problems (Q → fix)

### `blackbox: command not found`

Binary not on `PATH`.

```bash
curl -fsSL https://raw.githubusercontent.com/wanazhar/blackbox/master/install.sh | sh
# or
cargo install blackbox-recorder
hash -r 2>/dev/null; rehash 2>/dev/null
blackbox --version
```

### Wrong binary / old version

```bash
which -a blackbox
blackbox --version
type blackbox
```

Remove stale copies or put the intended install directory first on `PATH`.

### “No project found” / not enabled

Discovery walks ancestors for `.blackbox/`.

```bash
pwd
blackbox status
blackbox enable                 # or enable --memory-bus --install-shell
ls -la .blackbox/config.toml
```

If you expected a parent project, `cd` there or pass project/store overrides.

### Store path is not what I think

Priority: `--store` → `BLACKBOX_DB` → legacy `./blackbox.db` if present → `.blackbox/blackbox.db`.

```bash
echo "BLACKBOX_DB=${BLACKBOX_DB-}"
ls -la blackbox.db .blackbox/blackbox.db 2>/dev/null
blackbox doctor
```

A leftover root `blackbox.db` **wins** over `.blackbox/` — delete or migrate deliberately.

### Ambient wrap does nothing

Checklist:

1. `blackbox enable --install-shell` and restart shell / source rc  
2. Harness **basename** is on `capture.wrap`  
3. `BLACKBOX_OFF` unset  
4. Not nested under `BLACKBOX_ACTIVE_RUN`  
5. Project enabled and discovery finds it  
6. `blackbox` on PATH (else wrapper runs bare command silently)

```bash
echo "OFF=${BLACKBOX_OFF-} ACTIVE=${BLACKBOX_ACTIVE_RUN-}"
blackbox maybe-run -- true    # policy-dependent; prefer real harness test
blackbox runs
```

Normative order: [../ambient-contract.md](../ambient-contract.md).

### Continuity / memory not injecting

| Check | Notes |
|---|---|
| Ambient vs explicit | Wrappers never inject; use `blackbox run -- …` |
| `observe_only` | Config or `--observe-only` / `--eval` disables inject |
| Continuity mode | `status --json`, config `continuity`, env `BLACKBOX_CONTINUITY` |
| `BLACKBOX_OFF` | Disables ambient; can also confuse workflows |
| Harness cooperation | Inject is env/files/preamble — model must read it |

```bash
blackbox status --json
# inspect capture / attention / memory fields in the view
```

### Attention stuck on `continue` after a success

**By design:** unrelated success does not clear an unresolved failure.

```bash
blackbox resolve
blackbox resolve --clear-wip
```

If git is noisy because `.blackbox/` is dirty, gitignore it (porcelain checks also filter `.blackbox/` in current releases).

### Memory pack empty or `degraded`

`degraded = true` means pack built without full store (sticky-only). Causes:

- Store open failure / lock
- Corruption (doctor)
- Hard time budget exceeded during pack build

Pack may still be delivered; fidelity is reduced. Fix store access, then re-run to refresh.

### Claim conflicts

```bash
blackbox claim status
blackbox claim release          # if you own it
# or acquire with your holder after coordination
blackbox claim acquire --holder "$USER"
```

`gate_mode = require_ack` on explicit run: set `BLACKBOX_ACK=1` or `blackbox ack`.

### Dashboard unauthorized / empty

```bash
# token required for non-loopback; Bearer only
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:7788/api/runs
curl -s -H "Authorization: Bearer $BLACKBOX_SERVE_TOKEN" http://127.0.0.1:7788/api/runs
```

### Blobs / DB growing without bound

```toml
[retention]
auto_apply = true
keep_runs = 50
```

```bash
blackbox stats
blackbox purge --keep 50      # see CLI help for exact flags
blackbox scrub --gc
blackbox gc
```

Also consider `store_git_diffs = false`, `env_capture = "allowlist"`, `native_log_scope = "project"`.

### Encrypted blobs unreadable

Missing key: set `BLACKBOX_STORE_KEY` / `BLACKBOX_STORE_KEY_FILE` or restore `store.key`. Without key, encrypted blobs cannot be opened — by design.

### Import / sealed pack fails

```bash
blackbox import pack.json --passphrase '…'
# ensure format is portable or sealed v1; wrong passphrase fails closed
```

---

## 3. Recovery procedures

### Crash mid-run (1.4 recovery)

On next store open, abandoned `Running` rows become **`Failed`** (never success). Notes record that the supervisor was **interrupted** and that final events/checkpoints may be incomplete. Committed events and blobs are preserved.

```bash
blackbox doctor          # orphan Running count / daily-driver notes
blackbox runs
blackbox show <id>        # inspect partial timeline
blackbox postmortem <id>  # will not invent a successful outcome
```

Capture backpressure: merge lag samples and send_failures appear on `capture.coverage` metadata (`backpressure`); the merge path does **not** silently drop events under normal operation.

### Re-redact history

```bash
blackbox scrub --gc
```

### Restore from portable export

```bash
blackbox import trace.json
# sealed:
blackbox import trace.sealed.json --passphrase '…'
```

### Restore from store backup

```bash
blackbox restore vault.bbx.json --passphrase '…'
```

### Nuclear: disable ambient, keep data

```bash
blackbox disable
blackbox enable --uninstall-shell
# data remains under .blackbox/
```

---

## 4. FAQ

**Does blackbox slow my agent down?**  
Overhead is designed for ambient use. Soft budgets live in `tests/overhead_smoke.rs` / `overhead_bench`. Git porcelain is time-bounded (failure → conservative dirty=false). See [overhead.md](overhead.md).

**Can I use blackbox without shell wrappers?**  
Yes. Explicit `blackbox run -- <cmd>` only.

**Windows?**  
Partial: PowerShell install, process kill paths; full PTY fidelity is strongest on Unix. Check current CLI notes for platform limits.

**How do I share a run?**  
`blackbox export <id> -o trace.json` (redacted). Recipient: `blackbox import trace.json`. Or sealed passphrase export.

**Why crates.io name `blackbox-recorder`?**  
Package name collision; binary and crate path remain `blackbox`.

**Is postmortem an LLM summary?**  
No. Deterministic analysis over the event stream (headline, evidence, anomalies, …).

**Diff vs postmortem?**  
Postmortem explains one run; `diff` compares two runs’ trajectories.

**JSON shape?**  
[../reference/json-api.md](../reference/json-api.md).

---

## 5. Still stuck?

1. `blackbox doctor --json` and `blackbox status --json`  
2. Minimal repro: `blackbox run --observe-only -- true` then `show latest`  
3. File an issue with doctor JSON (redact hosts/paths if needed), OS, version, and whether ambient or explicit run  

Contributor internals: [../internals/architecture.md](../internals/architecture.md).
