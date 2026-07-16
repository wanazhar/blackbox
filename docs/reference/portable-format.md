# Portable format reference

**Wire format for import/export archives.** Operator workflow: [../guide/export-and-sync.md](../guide/export-and-sync.md). Sealed packs and passphrase sealing are covered there and in [../guide/security.md](../guide/security.md).


Blackbox can export traces to a portable JSON archive and import them back. This is useful for sharing traces between projects, machines, or debugging offline.

---

## 1. Export

```bash
# Export a run as portable JSON (redacted by default)
blackbox export <run-id> --format portable -o trace.json

# Full raw trace (no redaction)
blackbox export <run-id> --format portable -o trace.json --no-redact

# Export with blobs as inline base64
blackbox export <run-id> --format portable -o trace.json --inline-blobs
```

### Export format

```json
{
  "schema": "blackbox.portable/v2",
  "exported_at": "2026-07-12T12:00:00Z",
  "source": "blackbox-recorder/1.2.0",
  "runs": [ /* Run objects */ ],
  "blobs": {
    "<sha256-key>": { "size": 1234, "compressed": false, "data": "<base64-or-null>" }
  }
}
```

### v1 vs v2

| Feature | v1 | v2 |
|---|---|---|
| Schema | `blackbox.portable/v1` | `blackbox.portable/v2` |
| Blobs | Inline base64 | Optional inline; blobs can be side-loaded |
| Deduplication | None | Shared blobs referenced by key |
| Metadata | Minimal | Richer metadata, adapter info |
| Redaction | Default | Default (same behavior) |

---

## 2. Import

```bash
blackbox import trace.json
```

Import reconstructs the store:
1. Creates runs, events, checkpoints
2. Stores blobs from the archive
3. Renames blob keys when the archive's expected key differs from content hash
4. Preserves run IDs and sequence numbers

---

## 3. Blob handling

During export:
- Large blobs are stored in the archive (inline as base64 or side-car)
- Blob `key` references are preserved in event records
- With `--inline-blobs`: all blobs included in the archive JSON
- Without `--inline-blobs`: blobs skipped (only references exported)

During import:
- Blobs are re-stored via `TraceStore::store_blob()`
- `move_blob()` handles key mismatches (used during v1→v2 migration)

---

## 4. Redaction

Export is **redacted by default**:
- Terminal output is scanned for secrets before writing to the archive
- Environment variables and argv are redacted
- Structural identifiers (run IDs, blob keys, UUIDs) survive
- Pass `--no-redact` for a full unredacted copy (private offline analysis only)
