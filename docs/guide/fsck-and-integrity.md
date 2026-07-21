# Store integrity and `fsck`

Check the store when you suspect missing events, orphan blobs, or crash residue.

```bash
# Fast metadata / reference validation
blackbox fsck

# Load, decompress/decrypt, and re-hash every referenced blob
blackbox fsck --deep

# Plan + apply auto-safe repairs; write a recovery artifact under .blackbox/
blackbox fsck --repair

# Machine-readable report
blackbox fsck --json
blackbox fsck --deep --repair --json
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
| Orphan blob files on disk | no | info (repairable) |
| FTS probe / rebuild offer | yes | deep offers rebuild |
| Recovery spool pending/torn | yes | yes |

## Durable ingest spool

Live capture can append micro-batches to `.blackbox/spool/` **before** SQLite
commit. A producer-visible success after a barrier flush means the batch is
recoverable even if the process dies mid-commit.

On the next open (and during `fsck --repair`), pending spool batches are
replayed **idempotently by event id**. Torn records are detected and reported;
they are not invented into success.

```bash
# After a hard crash, either start a new supervised run or:
blackbox fsck --repair
```

## Repair safety

Auto-safe under `--repair`:

| Action | Effect |
|---|---|
| `recompute_aggregates` | Rebuild per-run aggregate payloads from events |
| `mark_run_failed` | Abandoned `Running` → `Failed` with a note |
| `replay_spool` | Planned; CLI also recovers spool on open |
| `rebuild_fts` | Rebuild `events_fts` from the events table |
| `gc_orphan_blob` | Delete blob files not referenced by events/checkpoints |

**Not** auto-repaired: inventing missing events, replacing corrupted blob bytes
with guessed content.

## Related

- [security.md](security.md) — redaction before spool/SQLite
- [export-and-sync.md](export-and-sync.md) — portable integrity
- [claims.md](../claims.md) — classified guarantees
