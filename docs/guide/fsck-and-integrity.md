# Store integrity and `fsck`

**Commands first.** Use these when you suspect missing events, orphan blobs, or crash residue.

```bash
# Fast metadata/reference validation
blackbox fsck

# Load, decompress/decrypt, and re-hash every referenced blob
blackbox fsck --deep

# Show repair plan, write a recovery artifact, apply auto-safe repairs
blackbox fsck --repair

# Machine-readable report (blackbox.cli/v1 envelope when combined with --json)
blackbox fsck --json
blackbox fsck --deep --json
```

## What is checked

| Section | Fast | Deep |
|---|---|---|
| Store open / schema | yes | yes |
| Runs (including stale `Running`) | yes | yes |
| Events, parent refs, sequences | yes | yes |
| Aggregates vs event counts | yes | yes |
| Checkpoint blob keys | yes | yes |
| Blob load + content hash | no | yes |
| Orphan blob files on disk | no | info |
| Recovery spool pending/torn | yes | yes |

## Durable ingest spool

Live capture appends micro-batches to `.blackbox/spool/pending/` **before** SQLite commit. A producer-visible success after a barrier flush means the batch is recoverability-safe even if the process dies mid-commit.

On the next `blackbox run` (and during `fsck --repair`), pending spool batches are replayed idempotently by event id.

```bash
# After a crash, either start a new run or:
blackbox fsck --repair
```

## Repair safety

Auto-safe repairs only:

- Recompute missing/mismatched aggregates
- Mark abandoned `Running` runs as `Failed`
- Count spool replay as planned

**Not** auto-repaired: inventing missing events, replacing corrupted blob bytes, deleting orphans without grace policy (`scrub --gc`).

## Related

- [security.md](security.md) — redaction before spool/SQLite
- [export-and-sync.md](export-and-sync.md) — portable integrity
- [claims.md](../claims.md) — classified guarantees
