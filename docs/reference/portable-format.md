# Portable format reference

**Answers:** Schema for import/export archives (`blackbox.portable/v1|v2`), blob embedding rules, redaction defaults, and how sealed envelopes wrap portable JSON.

Operator workflow: [../guide/export-and-sync.md](../guide/export-and-sync.md). Threat model: [../guide/security.md](../guide/security.md).

---

## Quick answers

| Question | Answer |
|---|---|
| Default redaction? | **On** — pass `--no-redact` only for private forensics |
| Re-importable format? | `--format portable` |
| Current schema? | Prefer **v2** (`blackbox.portable/v2`) |
| Sealed share? | Portable JSON inside `blackbox.export.sealed/v1` envelope |
| Whole store vault? | `backup` / `restore` (different format family) |

---

## 1. Export

```bash
blackbox export <run-id> --format portable -o trace.json
blackbox export <run-id> --format portable -o trace.json --inline-blobs
blackbox export <run-id> --format portable -o trace.json --no-redact   # dangerous
blackbox export <run-id> --format portable --passphrase '…' -o sealed.bbx.json
```

### Logical archive shape (v2)

```json
{
  "schema": "blackbox.portable/v2",
  "exported_at": "2026-07-12T12:00:00Z",
  "source": "blackbox-recorder/1.2.0",
  "runs": [ ],
  "blobs": {
    "<sha256-key>": { "size": 1234, "compressed": false, "data": "<base64-or-null>" }
  }
}
```

### v1 vs v2

| Feature | v1 | v2 |
|---|---|---|
| Schema string | `blackbox.portable/v1` | `blackbox.portable/v2` |
| Blobs | Often inline base64 | Optional inline; key-referenced |
| Dedup | Weak | Shared blob keys |
| Metadata | Minimal | Richer (adapter, …) |
| Redaction | Default on | Default on |

Import accepts both generations where possible.

### Directory layout (streaming-friendly)

For large runs, prefer a directory archive:

```bash
blackbox export <run-id> --format portable-dir -o ./trace-dir
blackbox import ./trace-dir
```

Library: `export_portable_dir` / `import_portable_dir`.

```text
manifest.json     # format blackbox.portable.dir/v1
run.json
events.jsonl      # one event per line
blobs/<sha256>    # raw bytes; filename must equal content SHA-256
```

Import validates each blob hash before permanent writes (same integrity rules as JSON v2).

---

## 2. Import

```bash
blackbox import trace.json
blackbox import sealed.bbx.json --passphrase '…'
blackbox import trace.json --keep-ids
```

Import reconstructs:

1. Runs, events, checkpoints  
2. Blobs via store APIs  
3. Key fixups when archive key ≠ content hash (migration paths)  
4. Sequence numbers preserved for timeline fidelity  

---

## 3. Blob handling

| Mode | Behavior |
|---|---|
| Without `--inline-blobs` | Events keep keys; blob bytes may be omitted (lighter file) |
| With `--inline-blobs` | Bytes embedded (base64) under `blobs` |
| On import | Re-store blobs; `move_blob` for key mismatches |

Large traces: prefer sync backends or vault backup over huge single JSON files.

---

## 4. Redaction

- Terminal, env, argv scanned before archive write  
- Structural ids (run UUID, blob SHA, event ids) survive  
- Portable export re-scans blobs (share path must not casually revive raw secrets)  
- `--no-redact` disables protection for that export only  

---

## 5. Sealed envelope

When `--passphrase` or `--encrypt` is used, the portable **plaintext** JSON is encrypted and wrapped:

| Field (conceptual) | Role |
|---|---|
| `format` | `blackbox.export.sealed/v1` |
| `ciphertext_b64` | ChaCha20-Poly1305 payload |
| salt / kdf params | Present for passphrase (PBKDF2) packs |

Open with matching passphrase or store key. Wrong key fails closed.

---

## 6. Related

- [cli.md](cli.md) — export/import/backup flags  
- [stream-protocol.md](stream-protocol.md) — harness NDJSON (not this archive)  
- Recipe: [../guide/recipes.md](../guide/recipes.md#9-share-a-redacted-failure-with-a-colleague)  
