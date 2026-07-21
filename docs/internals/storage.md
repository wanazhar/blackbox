# Storage layer

> **Contributor / deep-dive.** Store paths for operators: [../guide/configuration.md](../guide/configuration.md). At-rest crypto: [../guide/security.md](../guide/security.md).

On-disk layout, `TraceStore` / `SqliteStore`, blob addressing, FTS5, retention/GC, and encryption hooks.

Blackbox stores trace data in a **project-local directory** (`.blackbox/` by default) using SQLite for structured metadata and a content-addressed file store for large payloads.

---

## 1. Store layout

```
<project>/
└── .blackbox/
    ├── blackbox.db          # SQLite database (runs, events, checkpoints, tags, blobs index)
    ├── blackbox.db-wal      # SQLite WAL (concurrent read optimization)
    ├── blackbox.db-shm      # SQLite shared memory (WAL mode)
    ├── blobs/
    │   ├── ab/
    │   │   ├── cdef1234...  # Content-addressed blob (SHA-256, sharded by first 2 hex chars)
    │   │   └── ...
    │   ├── 01/
    │   └── ...
    ├── state.json           # Sticky project state (continuity plane)
    ├── state.lock           # Exclusive flock for state.json RMW
    ├── MEMORY.md            # Human-readable project memory pack
    ├── MEMORY.json          # Machine-readable project memory pack
    ├── RESUME.md            # Legacy copy (backward compat with 1.0 auto-resume)
    ├── RESUME.json          # Legacy copy
    ├── config.toml          # Optional project configuration
    ├── pricing.toml         # Optional pricing overrides
    └── AGENT.md             # Agent notes file
```

## 2. Store path resolution

Paths are resolved in priority order. First match wins:

| Priority | Source | Example |
|---|---|---|
| 1 | CLI `--store` flag | `blackbox run --store /custom/path/db.sqlite` |
| 2 | `BLACKBOX_DB` env var | `export BLACKBOX_DB=/custom/path/db.sqlite` |
| 3 | Legacy `./blackbox.db` | If the file already exists in the project root |
| 4 | Default project layout | `.blackbox/blackbox.db` + `.blackbox/blobs/` |

> **Tip:** Delete or move any leftover `./blackbox.db` if you want the modern `.blackbox/` layout.

## 3. The `TraceStore` trait

The `TraceStore` trait (`src/storage/store.rs`) defines the storage contract. The primary implementation is `SqliteStore`.

```rust
#[async_trait]
pub trait TraceStore: Send + Sync + 'static {
    // ── Runs ──
    async fn insert_run(&self, run: &Run) -> anyhow::Result<()>;
    async fn update_run(&self, run: &Run) -> anyhow::Result<()>;
    async fn get_run(&self, run_id: &str) -> anyhow::Result<Option<Run>>;
    async fn list_runs(&self) -> anyhow::Result<Vec<Run>>;
    async fn delete_run(&self, run_id: &str) -> anyhow::Result<bool>;

    // ── Events ──
    async fn insert_event(&self, event: &TraceEvent) -> anyhow::Result<()>;
    async fn get_events(&self, run_id: &str) -> anyhow::Result<Vec<TraceEvent>>;
    async fn get_events_limited(&self, run_id: &str, limit: usize)
        -> anyhow::Result<(Vec<TraceEvent>, bool)>;
    async fn get_event(&self, event_id: &str) -> anyhow::Result<Option<TraceEvent>>;
    async fn update_event(&self, event: &TraceEvent) -> anyhow::Result<()>;
    async fn count_events(&self, run_id: &str) -> anyhow::Result<usize>;
    async fn insert_events_batch(&self, events: &[TraceEvent]) -> anyhow::Result<()>;

    // ── Checkpoints ──
    async fn insert_checkpoint(&self, cp: &Checkpoint) -> anyhow::Result<()>;
    async fn get_checkpoints(&self, run_id: &str) -> anyhow::Result<Vec<Checkpoint>>;

    // ── Blobs ──
    async fn store_blob(&self, data: &[u8]) -> anyhow::Result<BlobReference>;
    async fn load_blob(&self, reference: &BlobReference) -> anyhow::Result<Vec<u8>>;
    async fn move_blob(&self, from_key: &str, to_key: &str) -> anyhow::Result<()>;
    async fn all_blob_keys(&self) -> anyhow::Result<Vec<String>>;
    async fn delete_blob_keys(&self, keys: &[String]) -> anyhow::Result<usize>;

    // ── Search ──
    async fn fts_event_ids(&self, query: &str, limit: usize)
        -> anyhow::Result<Option<Vec<(String, String, f64)>>>;
}
```

### Default implementations

- `get_events_limited` — loads all events then selects the tail N for postmortem signal; backends SHOULD override with SQL `LIMIT`
- `insert_events_batch` — falls back to individual inserts; backends SHOULD override with transactional batch for atomicity
- `move_blob`, `all_blob_keys`, `delete_blob_keys`, `fts_event_ids` — no-ops by default

## 4. `SqliteStore` implementation

### Schema versioning

The database carries a `schema_version` (currently **v6**). On open, the store checks the version and runs migrations sequentially. Migrations are wrapped in transactions — a failed migration rolls back cleanly.

### Key tables

| Table | Purpose | Key columns |
|---|---|---|
| `runs` | Run records | `id`, `status`, `command`, `cwd`, `started_at`, `ended_at`, `exit_code`, `parent_run_id`, `adapter`, `session_id`, `input_tokens`, `output_tokens`, etc. |
| `events` | Trace events | `id`, `run_id`, `sequence`, `source`, `kind`, `status`, `timestamp`, `side_effect`, `output_blob`, `total_redactions`, etc. |
| `blobs` | Blob metadata | `key`, `size`, `compressed`, `content_type` |
| `tags` | Run tag associations | `run_id`, `tag` (composite PK) |
| `checkpoints` | Run checkpoints | `id`, `run_id`, `event_id`, `git_commit`, `git_diff_blob`, `created_at` |

### WAL mode

SQLite is opened in **WAL (Write-Ahead Logging)** mode. This allows concurrent reads during writes — useful for the dashboard and TUI viewing a live recording.

### Recovery

When the store is opened, it marks all runs with `status = 'Running'` as `status = 'Failed'`. This is the crash-recovery mechanism: if the `blackbox` process was killed, in-flight runs are gracefully closed on the next access.

## 5. Content-addressed blob storage

Large payloads (terminal output, tool results, file contents, environment snapshots) are stored as content-addressed blobs.

### Addressing

The blob **key** is the SHA-256 hex digest of the content:

```
key = sha256hex(content)
```

Two identical payloads produce the same key and are stored once (deduplication).

### On-disk layout

Blobs are sharded by the first 2 hex characters:

```
.blackbox/blobs/<first-2>/<remaining-62>
```

For key `abcdef123456...` → `.blackbox/blobs/ab/cdef123456...`

### Compression

Blobs may optionally be compressed with **Zstandard** (`zstd`). The `BlobReference.compressed` flag indicates whether decompression is needed on read.

### BlobReference

```rust
pub struct BlobReference {
    pub key: String,               // SHA-256 hex digest
    pub size: u64,                 // Uncompressed size in bytes
    pub compressed: bool,          // Whether stored with Zstandard compression
    pub content_type: Option<String>,  // MIME type hint
}
```

Key validation is strict: `BlobReference::new()` panics if the key is not a valid 64-character lowercase hex string. This prevents path traversal attacks.


## 6. Full-text search (FTS5)

The SQLite store maintains an **FTS5 virtual table** over events. This enables fast keyword search across all recorded runs.

### Indexed fields

| Field | Source |
|---|---|
| `kind` | Event kind string (e.g. `tool.call`, `terminal.output`) |
| `source` | Event source enum variant name |
| `metadata` | JSON metadata (tool names, file paths, error messages) |
| `output` | Short preview text |
| `error` | Error message text |

### Search workflow

1. `blackbox search "<query>"` calls `fts_event_ids()`
2. FTS5 returns ranked `(event_id, run_id, rank)` tuples
3. Matching events are loaded and displayed

If the backend doesn't support FTS, the caller falls back to scanning events with pattern matching.

## 7. Retention and GC

### Run deletion

`blackbox rm <run-id>` deletes a run and its events/checkpoints from SQLite. Blob files on disk are **not** removed — they may be referenced by other runs.

### Purge

`blackbox purge` removes multiple runs by policy:

| Policy | Behavior |
|---|---|
| `--keep N` | Keep the N most recent runs, delete older ones |
| `--status failed` | Delete all failed runs |
| `--older-than <duration>` | Delete runs ended before the given duration |

### Scrub + GC

`blackbox scrub` performs two operations:

1. **Re-redaction** — re-applies the current redaction rules to historical events. Useful when new secret patterns are added.
2. **Blob GC** (`--gc`) — finds blob metadata rows that have no surviving event/checkpoint references, removes the metadata rows, and deletes the orphaned blob files from `.blackbox/blobs/`.

### Auto-apply retention

By default, retention policy is applied automatically after each run. Configure via `.blackbox/config.toml`:

```toml
[retention]
auto_apply = true
keep_runs = 100
```

## 8. Portable export/import

### Export

`blackbox export <run-id> --format portable` produces a JSON archive that includes:
- Run metadata
- All events (with blob content inlined or referenced)
- Checkpoints
- Tags

The export is **redacted by default** — pass `--no-redact` for the full raw trace.

### Import

`blackbox import <file>` reconstructs a store from a portable JSON archive. It imports runs, events, checkpoints, and blobs, renaming blob keys when the archive's expected key differs from the content hash.

### Versions

- **v1**: Original export format (inline blobs as base64)
- **v2**: Improved format with blob deduplication and metadata

## 9. Storage costs

| Store element | Typical size | Notes |
|---|---|---|
| SQLite (100 runs) | ~5–50 MB | Depends on event count and metadata |
| Blobs | 0–500 MB+ | Large terminal output dominates |
| state.json | ~2–10 KB | Single JSON file |
| MEMORY files | ~5–50 KB | Regenerated each run |

Use `blackbox doctor --json` or `blackbox stats --json` to see live storage usage.

## References

- [`TraceStore` trait](https://github.com/wanazhar/blackbox/blob/main/src/storage/store.rs)
- [`SqliteStore` implementation](https://github.com/wanazhar/blackbox/blob/main/src/storage/sqlite.rs)
- [`BlobReference` model](https://github.com/wanazhar/blackbox/blob/main/src/core/blob.rs)
- [`scrub` module](https://github.com/wanazhar/blackbox/blob/main/src/scrub.rs)
- [`retention` module](https://github.com/wanazhar/blackbox/blob/main/src/retention.rs)

