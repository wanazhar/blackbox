# Security

Blackbox runs on machines that may hold secrets — API keys, tokens, passwords, environment variables. The entire design is built around **redact-before-write**: secrets are scrubbed before they touch disk.

---

## 1. Redaction model

| Surface | Redacted by default? | What is redacted |
|---|---|---|
| **argv** (command + process tree) | ✅ Yes | Arguments that match secret patterns |
| **Environment variables** | ✅ Yes | Name denylist **and** value pattern scan (keys, connection strings, tokens) |
| **Git diffs** | ✅ Yes | Diff text scanned before blob/preview storage |
| **Terminal output** | ✅ Yes | Inline strings matching secret patterns |
| **Tool inputs/outputs** | ✅ Yes | Parameters and results matching secret patterns |
| **Run IDs** | ❌ No | UUIDs — structural identifiers survive |
| **Blob keys** | ❌ No | SHA-256 hashes — structural identifiers survive |
| **Timestamps** | ❌ No | Temporal metadata |

### SecretScanner

The `SecretScanner` (`src/redaction/scanner.rs`) is a multi-strategy scanner:

| Strategy | Example matches |
|---|---|
| Known env var names | `API_KEY=...`, `TOKEN=...`, `SECRET=...`, `PASSWORD=...` |
| Cloud / provider keys | `sk-...` (OpenAI), `sk-ant-...`, `ghp_` / `github_pat_`, `AKIA...`, `xoxb-...`, `AIza...`, `xai-...`, npm/pypi tokens |
| Auth headers / cookies | `Bearer ...`, `Basic ...`, `Set-Cookie`, `sessionid=` |
| Connection strings | `postgres://user:pass@...`, `https://user:pass@host` |
| Signed URL params | `X-Amz-Signature=...`, `access_token=...` |
| PEM private keys | `-----BEGIN … PRIVATE KEY-----` |
| JSON payload scanning | Nested string values in tool metadata |

**Stream redaction:** PTY capture uses `StreamRedactor` with an overlap window so secrets split across chunk boundaries are still detected before write.

**Structural IDs never scarred:** git SHAs, blob keys (SHA-256 hex), UUIDs, and event kinds are not matched by whole-string base64/hex patterns.

**Adversarial corpus:** `tests/redaction_adversarial.rs` is the permanent regression gate (chunk splits, export, mixed SHA+secret).

Redacted values are replaced with `[REDACTED]`. Event metadata may include a `redactions` count.

### Known limitations

- Perfect redaction is not guaranteed for novel secret formats; defaults are conservative.
- Secrets only present in raw PTY blobs under `--insecure-raw` are stored unredacted by design.
- Overlap window is finite (default 256 bytes); extremely long tokens split with a larger gap may still miss (prefer coalesced storage + scrub).
- Opt-in danger flags: `--insecure-raw`, `--no-redact` (never enable on shared machines).
- **Blackbox is not a vault.** Same-UID malware, unlocked-disk theft, and backup exfil of `.blackbox/` still see every redacted-at-best trace. There is no at-rest encryption (yet).

---

## 2. Safe defaults

### Capture

```bash
# Default: redacted
blackbox run -- npm test

# Unsafe: raw PTY bytes stored as blobs
blackbox run --insecure-raw -- npm test

# Unsafe: no redaction at all
blackbox run --no-redact -- npm test
```

### Export

```bash
# Default: redacted
blackbox export <run-id> --format portable -o trace.json

# Unsafe: full unredacted trace
blackbox export <run-id> --format portable -o trace.json --no-redact
```

### Sync

```bash
# Default: redacted
blackbox sync push --dir /mnt/backup

# Unsafe: raw data
blackbox sync push --dir /mnt/backup --no-redact
```

---

## 3. Flags

| Flag | Effect | When to use |
|---|---|---|
| `--insecure-raw` | Store raw PTY bytes as blobs in addition to redacted output | Debugging adapter parsing; **never** on machines with secrets |
| `--no-redact` | Disable all redaction on capture, export, or sync | Private offline analysis on a trusted machine; **never** when sharing traces |

Both flags require explicit opt-in. They are purposefully named to discourage casual use.

---

## Overhead benchmarks (local)

Ambient capture must stay cheap enough to leave on. Soft budgets ship in tests; the full suite is **local-only** (not a hard CI gate):

```bash
# Soft always-on smoke (debug-friendly budgets)
cargo test --test overhead_smoke
cargo test --test overhead_bench soft_true event_write

# Full local bench with p50/p95 tables (ignored by default)
cargo test --test overhead_bench -- --ignored --nocapture
```

`blackbox stats` reports average events/run and blob bytes/run for storage cost visibility.

---

## 4. At-rest redaction

Historical runs may contain secrets if captured with `--no-redact` or before new redaction patterns were added.

```bash
# Re-apply current redaction rules to all historical events
blackbox scrub

# Also GC orphaned blob files
blackbox scrub --gc
```

`scrub` re-reads events, re-applies the `SecretScanner` patterns, and rewrites **event I/O blobs** (input/output/error) plus metadata strings. Prefer `blackbox scrub --gc` afterward so replaced secret blobs are deleted. Environment/diff metadata-key blobs are still a residual gap — treat old stores as potentially hot until scrubbed under a current build.

---

## 4b. Store file permissions (multi-user)

On Unix, blackbox sets **owner-only** modes when creating store artifacts:

| Path | Mode |
|---|---|
| `.blackbox/` and `blobs/` | `0700` |
| `blackbox.db`, blob files, `state.json`, `MEMORY.*` | `0600` |

`blackbox doctor` warns (and best-effort hardens) if the store is group/other-readable. This blocks **other local UIDs** with a default umask — not the same user, not root, and not an unlocked stolen disk.

---

## 5. Export and sync

Export and sync operations are **redacted by default**:

```bash
# Portable export (redacted)
blackbox export <run-id> -o trace.json

# Sync to directory (redacted)
blackbox sync push --dir /backup

# Sync to S3 (redacted)
blackbox sync push --s3 s3://my-bucket/traces/
```

Pass `--no-redact` only for private offline analysis:

```bash
blackbox export <run-id> -o trace.json --no-redact
```

---

## 6. Serve security

The dashboard binds to `127.0.0.1:7788` by default (localhost only):

```bash
blackbox serve
# Listening on http://127.0.0.1:7788
```

**Non-loopback binds refuse to start without a token** (`--bind 0.0.0.0:7788` requires `--token` / `BLACKBOX_SERVE_TOKEN`). Loopback without a token still warns: any local user can `curl 127.0.0.1:7788` and read full history.

### Token authentication

```bash
blackbox serve --token my-secret-token
# Or via env:
BLACKBOX_SERVE_TOKEN=my-secret-token blackbox serve
```

Prefer the Authorization header (query `?token=` is deprecated and may leak into logs):

```bash
curl -H "Authorization: Bearer my-secret-token" http://host:7788/api/status
```

### Network binding

```bash
# Listen on all interfaces (dangerous without a token)
blackbox serve --bind 0.0.0.0:7788 --token <token>
```

---

## 7. What blackbox does NOT capture

| Not captured | Reason |
|---|---|
| Keylogging or keystroke-level input | PTY captures are output only |
| Network packets | No eBPF or packet capture layer |
| Browser CDP events | No Chrome DevTools Protocol integration |
| System-wide recording | Only project-enabled harness commands |
| Other processes' secrets | Only the supervised command's environment |
