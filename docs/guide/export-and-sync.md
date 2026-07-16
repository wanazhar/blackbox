# Export and sync

**Answers:** How to export a run (JSONL / HTML / portable), import archives, sync to dir/HTTP/S3, seal packs with a passphrase, and vault a whole store offline.

**Default:** export and sync are **redacted**. Use `--no-redact` only on a trusted machine for private analysis. Threat model: [security.md](security.md).

---

## Quick decision table

| Goal | Command |
|---|---|
| Share one run with a human (browser) | `export --format html -o report.html` |
| Share / archive one run (re-importable) | `export --format portable -o trace.json` |
| Stream into log tooling | `export --format jsonl -o trace.jsonl` |
| Hide plaintext on disk while sharing | portable + `--passphrase` / `--encrypt` |
| Copy many runs to a folder or S3 | `sync push --dir …` / `--s3 …` |
| Cold-vault DB + sticky (+ optional blobs) | `backup` / `restore` |

---

## 1. Export formats

### JSONL

One JSON object per line (NDJSON). Good for streaming and external analytics.

```bash
blackbox export <run-id> --format jsonl -o trace.jsonl
```

### HTML

Self-contained report: metadata, filterable timeline, tools, errors, side effects.

```bash
blackbox export <run-id> --format html -o report.html
```

### Portable

JSON archive re-importable into another blackbox store. Schema: [portable-format.md](../reference/portable-format.md).

```bash
# Redacted (default)
blackbox export <run-id> --format portable -o trace.json

# Include blob bytes inline (larger)
blackbox export <run-id> --format portable --inline-blobs -o trace.json

# Import
blackbox import trace.json
```

`latest` and short ids work where the CLI accepts run ids.

---

## 2. Sealed portable packs

Avoid leaving plaintext JSON on USB or chat:

```bash
# Passphrase (PBKDF2 + ChaCha20-Poly1305) — preferred for sharing
blackbox export latest --format portable --passphrase 'long random phrase' -o run.bbx.json
blackbox import run.bbx.json --passphrase 'long random phrase'

# Or seal with project store key (requires encrypt_blobs / key present)
blackbox export latest --format portable --encrypt -o run.bbx.json
```

Envelope format: `blackbox.export.sealed/v1` (`ciphertext_b64`, optional salt). Wrong passphrase fails closed.

Env convenience: `BLACKBOX_EXPORT_PASSPHRASE`.

---

## 3. Sync backends

Push/pull redacted portable-style payloads depending on backend.

```bash
# Directory (local disk, NFS, USB)
blackbox sync push --dir /mnt/backup/traces
blackbox sync pull --dir /mnt/backup/traces

# HTTP endpoint implementing the sync API
blackbox sync push --remote https://example/sync
blackbox sync pull --remote https://example/sync

# S3
blackbox sync push --s3 s3://bucket/prefix/
blackbox sync pull --s3 s3://bucket/prefix/
```

Serve also exposes sync routes when the dashboard is up (`/api/sync/…`) — protect with a token. See [CLI serve](../reference/cli.md#21-serve).

Unsafe: append `--no-redact` (same meaning as export).

---

## 4. Store backup / restore (offline vault)

Different from per-run export: seals **project sticky state + optional full DB + optional blobs** for cold storage or machine migration.

```bash
blackbox backup -o vault.bbx.json --passphrase '…' --include-db
blackbox backup -o vault.bbx.json --passphrase '…' --include-db --include-blobs

blackbox restore vault.bbx.json --passphrase '…'
```

| Flag | Role |
|---|---|
| `--passphrase` / env | Recommended seal |
| `--store-key` | Seal with existing store crypto instead |
| `--include-db` | Embed SQLite (default on in typical usage) |
| `--include-blobs` | Embed blob files (size-capped) |

**`store.key` is never embedded** in the archive. Prefer passphrase vaults so the archive is usable without shipping the key file. Live DB pages are still plaintext on a running machine — this is the **offline** control.

---

## 5. Redaction rules on the wire

| Mode | Behavior |
|---|---|
| Default | SecretScanner applied; structural IDs kept |
| `--no-redact` | Full residual content — private forensics only |
| Sealed | Encryption of the already-chosen plaintext (redacted or not) |

Regression gate: `tests/redaction_gate.rs`. Portable export re-scans blobs (H-08) so share path does not silently resurrect secrets from older raw blobs.

---

## 6. Use cases

| Scenario | Approach |
|---|---|
| PR review of a failure | HTML export or `serve` link on loopback |
| External collaborator | Redacted portable or passphrase-sealed portable |
| CI artifact | `run --ci/--eval --artifact-dir` (includes postmortem/anomalies) |
| Nightly offsite | `sync push --s3 …` or directory sync |
| Laptop theft prep | `encrypt_blobs` + regular passphrase `backup` |

---

## See also

- [security.md](security.md) — residual risk, key placement
- [configuration.md](configuration.md) — `BLACKBOX_EXPORT_PASSPHRASE`, encrypt flags
- [../reference/portable-format.md](../reference/portable-format.md)
- [../reference/cli.md](../reference/cli.md) — export/import/backup/sync flags
