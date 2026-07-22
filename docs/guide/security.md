# Security

What is redacted before disk, which flags disable protection, multi-user file modes, serve auth, residual threats (same-UID, disk theft, novel secrets), historical scrub, and optional at-rest encryption / sealed backup.

Related: [configuration.md](configuration.md) (keys and env), [export-and-sync.md](export-and-sync.md) (share path), [overhead.md](overhead.md) (cost of capture).

---

## Threat model (read this first)

| Adversary / situation | Default protection | Gap |
|---|---|---|
| Accidental commit of agent scrollback with API keys | Redact-before-write + gitignore `.blackbox/` | You can still force `--no-redact` |
| Colleague on same machine, **other UID** | `0700` / `0600` store modes | Mis-set umask historically → `doctor` hardens |
| Colleague / malware, **same UID** | None special | Can read store + key files you can read |
| Stolen laptop, disk unlocked | Optional blob encrypt + sealed sticky; offline backup vault | Live `blackbox.db` metadata is not SQLCipher |
| Stolen laptop, sealed offline vault only | Passphrase-sealed `backup` | Passphrase strength is yours |
| Shared export JSON | Redacted export default | `--no-redact` or sealed-open with passphrase |
| Dashboard on LAN | Non-loopback requires token | Loopback without token = any local user with network to 127.0.0.1 |

**Blackbox is not a vault by default.** It is a redacting flight recorder with optional crypto layers.

---

## 1. Redact-before-write

Invariant: matching secrets are scrubbed **before** SQLite rows and blob files are written (unless danger flags say otherwise).

| Surface | Default | What is scanned |
|---|---|---|
| argv / process tree | On | Secret-like arguments |
| Environment | On | Name denylist **and** value patterns; capture mode allowlist vs full (see config) |
| Git diffs | On | Diff text before blob/preview |
| Terminal (PTY) | On | **Holdback** stream redaction before blob write |
| Tool I/O | On | Nested JSON string values in metadata |
| Native harness logs | On | Line redacted before parse + metadata re-scan |
| Run UUIDs, blob SHA-256 keys, timestamps, event kinds | **Not** redacted | Structural IDs must survive for debugging |

Replacement token: `[REDACTED]`. Events may carry a `redactions` count in metadata.

### Scanner strategies (implementation)

`SecretScanner` (`src/redaction/scanner.rs`) combines:

| Strategy | Examples |
|---|---|
| Env-style names | `API_KEY=`, `TOKEN=`, `PASSWORD=`, … |
| Provider keys | `sk-…`, `sk-ant-…`, `ghp_` / `github_pat_`, `AKIA…`, `xoxb-…`, `AIza…`, `xai-…`, npm/pypi tokens |
| Auth headers / cookies | `Bearer`, `Basic`, `Set-Cookie`, `sessionid=` |
| Connection strings | `postgres://user:pass@…`, embedded basic-auth URLs |
| Signed URL params | `X-Amz-Signature=`, `access_token=` |
| PEM private keys | `BEGIN … PRIVATE KEY` |
| Nested JSON | Tool metadata string leaves |

### Holdback stream redaction (1.4 S1)

PTY output is **not** redacted per-chunk with immediate write. `StreamRedactor` (`src/redaction/stream.rs`):

1. Appends each normalized chunk to an unredacted **pending** buffer
2. Scans the full pending buffer for secret spans
3. Emits only the prefix **older than the holdback window** (default **1024** bytes), after redaction
4. Pulls the emit cursor back when a span still crosses the holdback boundary
5. On end-of-stream, `finish()` redacts and flushes the remainder

So a secret split as `sk-abc…` / `…rest` never persists the first fragment alone. Pending is capped (`DEFAULT_MAX_PENDING`) to bound RAM; excess is force-flushed after redaction.

Invalid UTF-8 is lossy-decoded (`U+FFFD`) so binary-like PTY bytes remain scannable without bypassing the redactor.

**Structural IDs not scarred:** whole-string hex/base64 matchers are constrained so git SHAs, blob keys, and UUIDs survive. Regression: `tests/redaction_gate.rs`, `tests/redaction_adversarial.rs` (incl. exhaustive split positions), `tests/redaction_store_scan.rs` (SQLite/WAL/blob byte scan).

### Limitations (honest)

- Novel secret formats can slip; defaults are conservative but not omniscient.
- `--insecure-raw` stores raw PTY material by design (bypasses the safe path).
- Holdback window is finite; secrets longer than the window that never complete a match may still force-flush under the RAM cap (still redacted when patterns match).
- **Logical redaction ≠ physical secure erase.** Scrub rewrites logical content; SQLite WAL pages, SSD wear-leveling, and COW filesystems may retain prior bytes until the OS reclaims them. Do not promise media-level wipe.
- Old stores captured under older scanners remain hot until `blackbox scrub`.
- Live SQLite **run/event metadata** is not column-encrypted; blob encrypt + sealed backup are the practical vault path (no live SQLCipher).

---

## 2. Danger flags

| Flag | Effect | When it is justified |
|---|---|---|
| `--insecure-raw` | Keep raw PTY bytes as blobs (in addition to normal pipeline) | Adapter debugging on a machine with **no** secrets |
| `--no-redact` | Disable redaction on capture **or** export/sync (per command) | Private offline forensics on a trusted host; **never** for shares |

```bash
# Default — redacted
blackbox run -- npm test
blackbox export latest --format portable -o trace.json
blackbox sync push --dir /backup

# Explicitly unsafe
blackbox run --insecure-raw -- …
blackbox run --no-redact -- …
blackbox export latest -o raw.json --no-redact
```

Names are intentionally ugly.

---

## 3. Historical scrub

If patterns improved or you once used `--no-redact`:

```bash
blackbox scrub
blackbox scrub --gc    # re-redact + delete orphan blob keys
```

Rewrites event I/O blobs (input/output/error) and metadata strings under current rules. Prefer `--gc` so replaced secret blobs do not linger. Treat pre-scrub stores as potentially sensitive.

---

## 4. Filesystem permissions

On Unix, create paths with owner-only modes when blackbox creates them:

| Path | Mode |
|---|---|
| `.blackbox/`, `blobs/` | `0700` |
| `blackbox.db`, blobs, `state.json`, `MEMORY.*`, `store.key` | `0600` |

`blackbox doctor` warns and best-effort hardens group/other-readable stores. This stops **other UIDs**, not root, not same-UID malware, not an unlocked disk image.

---

## 5. At-rest encryption and offline vault

Live SQLCipher on the DB is **intentionally not** wired (key UX + FTS complexity). Layered practical path:

| Layer | Mechanism |
|---|---|
| Blob encryption | `encrypt_blobs = true` → ChaCha20-Poly1305; content hash remains SHA-256 of **plaintext** |
| Key material | `.blackbox/store.key` **or** `BLACKBOX_STORE_KEY` / `BLACKBOX_STORE_KEY_FILE` / `~/.config/blackbox/default.key` |
| Sticky seal | With key present: seal `state.json` + `MEMORY.json` (markdown may stay plain for preambles) |
| Sealed export | `export --format portable --passphrase …` or `--encrypt` (store key) |
| Offline vault | `blackbox backup` / `restore` — DB + sticky; optional blobs; **passphrase preferred**; `store.key` not embedded |

```toml
# .blackbox/config.toml
[capture]
encrypt_blobs = true
```

```bash
export BLACKBOX_STORE_KEY_FILE=~/.config/blackbox/default.key   # outside project tree

blackbox backup -o ~/vaults/proj.bbx.json --passphrase '…' --include-db
# optional: --include-blobs (size-capped)

blackbox restore ~/vaults/proj.bbx.json --passphrase '…'
```

**Losing the key loses encrypted blobs.** Back up key material separately from the project tree when using file keys.

Native logs default to **project** scope so home harness dirs (`~/.claude`, …) are not copied into the store unless `native_log_scope = "home"`.

### Hardened project profile (`--harden`)

One-shot trust defaults without SQLCipher. Prefer this over hand-editing knobs:

```bash
blackbox setup --harden
# or on an existing project:
blackbox enable --harden
```

| Setting | Value |
|---|---|
| `capture.encrypt_blobs` | `true` |
| `capture.native_log_scope` | `project` |
| `capture.env_capture` | `allowlist` |
| `retention.auto_apply` | `true` |
| `retention.keep_runs` | at least `50` if previously `0` |
| Key material | Prefer `~/.config/blackbox/default.key` (mode-hardened); fall back to project `store.key` |
| Tip file | `.blackbox/HARDEN.txt` — key path + `BLACKBOX_STORE_KEY_FILE` + backup one-liner |

Then:

```bash
export BLACKBOX_STORE_KEY_FILE=~/.config/blackbox/default.key
blackbox backup -o ~/vaults/proj.bbx.json --passphrase '…' --include-db
blackbox doctor   # tips should look clean for crypto posture
```

Harden does **not** force a backup passphrase or wipe existing plaintext blobs already on disk. Re-run capture under encrypt for new blobs; use `backup` for cold vault.

---

## 6. Export, sync, and share

Defaults redact. Portable import reconstructs runs on another machine. Sealed packs use envelope format `blackbox.export.sealed/v1` (ciphertext + optional PBKDF2 salt).

Sync backends (dir / HTTP / S3) inherit redaction defaults; portable path re-scans blobs (H-08) similarly to CLI export.

Workflow detail: [export-and-sync.md](export-and-sync.md).

---

## 7. Serve / dashboard

```bash
blackbox serve                          # auto-generates a one-shot token (printed once)
blackbox serve --token "$TOKEN"
BLACKBOX_SERVE_TOKEN="$TOKEN" blackbox serve --bind 0.0.0.0:7788
blackbox serve --allow-anonymous        # danger: loopback only, no auth
```

| Rule | Behavior |
|---|---|
| No token supplied | **Auto-generates** a random token and prints it (fail-closed default) |
| Explicit `--token` / `BLACKBOX_SERVE_TOKEN` | Uses that secret |
| `--allow-anonymous` | Loopback/unix only; any local user can read history (danger flag) |
| Non-loopback bind | **Refuses** without a token (auto or explicit); never with `--allow-anonymous` alone |
| Auth | `Authorization: Bearer <token>` only (no query API auth) |
| Browser | One-shot `?token=` may be migrated into `sessionStorage` then stripped from URL |

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:7788/api/status
```

SSE streams and JSON APIs share the same auth middleware.

---

## 8. What blackbox does **not** capture

| Not captured | Why |
|---|---|
| Keystroke-level input | PTY path is process I/O, not a keylogger product |
| Network packets | No eBPF/pcap layer |
| Browser CDP | No DevTools protocol integration |
| System-wide all processes | Project-enabled / supervised commands only |
| Other users’ processes | Only the supervised tree |

---

## 8b. Boundaries & external evidence (1.7)

| Topic | Default |
|---|---|
| External NDJSON import | Bounded size/count; idempotent; rejects loadable absolute/`..` path **attributes** |
| Payload integrity | When `original_payload_hash` is present, sha256 of `payload`/`raw`/`body` is verified; false `hash_ok` claims demoted |
| Fail-closed IR import | `evidence import --reject-unverified` keeps only `hash_ok` / `signed_verified` |
| Correlation confidence | Cooperative `trace_id` alone ≤ strongly_correlated; unverified integrity never Confirmed |
| Process `object` paths | Absolute exe paths are allowed as labels (never opened) |
| Containment “verified” | Requires verified+held on a real control — process-only absence of egress does **not** satisfy |
| Forensic packs | `SecretScanner` + substring patterns + truncation; model claims need citations |
| Incidents / dashboard | Same auth as other `serve` APIs; HTML escapes free text |

Guide: [boundaries-and-incidents.md](boundaries-and-incidents.md).

### Residual risks closed by design (1.7)

| Risk | Closure |
|---|---|
| Unverified sensor feed treated as proof | Integrity caps correlation; payload hash verify on import; optional `--reject-unverified` |
| Forensic pack leaks fixture secrets | Packs run the same `SecretScanner` as capture/export before write |
| Anonymous loopback `serve` | Token auto-generated unless `--allow-anonymous` (loopback-only danger) |
| Forged cooperative `trace_id` → Confirmed | Permanent unit gates; multi-signal + integrity required |

---

## 9. Operational checklist

1. Keep `.blackbox/` gitignored.
2. Never enable `--no-redact` / `--insecure-raw` on shared or secret-bearing hosts.
3. Run `blackbox doctor` after enable; fix permission and encryption tips.
4. Prefer `BLACKBOX_STORE_KEY_FILE` outside the repo if `encrypt_blobs` is on.
5. Use passphrase `backup` for cold storage; test `restore` once.
6. Prefer pinned `--token` / `BLACKBOX_SERVE_TOKEN` for `serve`; avoid `--allow-anonymous` on multi-user hosts.
7. After expanding scanner patterns: `blackbox scrub --gc`.
8. Treat imported external evidence as untrusted telemetry unless integrity is `hash_ok` / `signed_verified`.

---

## 10. Related tests and code

| Asset | Role |
|---|---|
| `tests/redaction_gate.rs` | Structural IDs live; secrets die |
| `tests/redaction_adversarial.rs` | Chunk splits, export, mixed SHA+secret |
| `tests/boundary_detector_quality.rs` | Detector FP/FN permanent gate |
| `src/redaction/` | Scanner + stream redactor |
| `src/crypto.rs` | Blob seal, sealed packs |
| `src/backup.rs` | Store vault |
| `src/privacy.rs` | Path modes, bind checks |
| `src/evidence/` | Import validation, payload-hash verify, path-attr rejection |
| `src/boundary/correlate.rs` | Confidence caps (trace_id / integrity) |
| `src/forensic/` | SecretScanner forensic packs |
