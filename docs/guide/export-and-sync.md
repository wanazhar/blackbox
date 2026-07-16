# Export and sync

**Answers:** How to export a run (JSONL / HTML / portable), import portable archives, sync to dir/HTTP/S3, and use sealed packs / store backup.

Both export and sync are **redacted by default**. Pass `--no-redact` only for private offline analysis on a trusted machine. Threat model: [security.md](security.md).

---

## 1. Export formats

### JSONL

One JSON object per line. Suitable for streaming and log aggregation tools.

```bash
blackbox export <run-id> --format jsonl -o trace.jsonl
```

Each line is one event (terminal output, tool call, tool result, etc.). The file is NDJSON (newline-delimited JSON).

### HTML

A self-contained human-readable HTML report.

```bash
blackbox export <run-id> --format html -o report.html
```

Includes: run metadata, event timeline with filtering, tool call details, error highlights, side-effect classifications.

### Portable

A JSON archive that can be imported back into blackbox. See the [Portable format reference](../reference/portable-format.md) for schema details.

```bash
# Redacted (default)
blackbox export <run-id> --format portable -o trace.json

# Include blob content inline
blackbox export <run-id> --format portable --inline-blobs -o trace.json

# Import on another machine
blackbox import trace.json
```

---

## 2. Sync backends

Sync push/pull through three backends:

### Directory sync

```bash
# Push to a local or mounted directory
blackbox sync push --dir /mnt/backup/traces/

# Pull from a directory
blackbox sync pull --dir /mnt/backup/traces/
```

### HTTP remote

```bash
# Push to a remote HTTP endpoint
blackbox sync push --remote https://example.com/api/traces

# Pull from a remote
blackbox sync pull --remote https://example.com/api/traces
```

### S3

```bash
# Push to S3
blackbox sync push --s3 s3://my-bucket/traces/

# Pull from S3
blackbox sync pull --s3 s3://my-bucket/traces/
```

---

## 3. Redaction

All export and sync operations are **redacted by default**:

| Mode | Behavior |
|---|---|
| Default | Secrets redacted in all exported/synced content |
| `--no-redact` | Raw, unredacted data (for private offline analysis only) |

The redaction gate is tested in `tests/redaction_gate.rs`: structural IDs (SHA, blob keys, UUIDs) must survive redaction, while planted secrets are removed.

---

## 4. Use cases

| Scenario | Format | Command |
|---|---|---|
| Share a trace with a colleague | Portable JSON | `blackbox export <id> -o trace.json` |
| Import trace from another machine | Portable → import | `blackbox import trace.json` |
| Stream events for analysis | JSONL | `blackbox export <id> --format jsonl` |
| Generate a visual report | HTML | `blackbox export <id> --format html` |
| Backup all local traces | Sync → directory | `blackbox sync push --dir /mnt/backup` |
| Share via S3 bucket | Sync → S3 | `blackbox sync push --s3 s3://bucket/traces/` |
| Offline passphrase vault (DB + sticky) | Sealed backup | `blackbox backup` / `restore` (see below) |

---

## 5. Sealed export packs and store backup

Portable export can be **sealed** (passphrase or store key):

```bash
blackbox export <run-id> --format portable --passphrase '…' -o trace.sealed.json
blackbox import trace.sealed.json --passphrase '…'
```

Whole-store offline vault (not live SQLCipher):

```bash
blackbox backup -o vault.bbx.json --passphrase '…'
blackbox restore vault.bbx.json --passphrase '…'
```

`store.key` is never embedded in backups by default. Prefer passphrase-sealed archives for cold storage away from the machine. Details and threat model: [security.md](security.md) § at-rest.
