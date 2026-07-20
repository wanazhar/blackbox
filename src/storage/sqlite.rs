use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;
use std::sync::LazyLock;

use parking_lot::Mutex;
use std::path::{Path, PathBuf};

use anyhow::Context;
use rusqlite::{params, Connection};
use tokio::task;

use crate::aggregates::RunAggregates;
use crate::core::blob::BlobReference;
use crate::core::checkpoint::Checkpoint;
use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::storage::TraceStore;

/// Current schema version. Bump when migrations change.
/// Current on-disk schema version (also reported by `doctor --json`).
pub const SCHEMA_VERSION: i32 = 7;

/// Default scanner for redacting secrets in FTS index content.
static FTS_SCANNER: LazyLock<SecretScanner> =
    LazyLock::new(|| SecretScanner::new(RedactionConfig::default()));

/// Pre-serialized event fields for batch inserts.
/// Storing the serialized JSON strings avoids repeated unwrap_or_default()
/// fallbacks inside the transaction hot path.
struct SerializedEvent {
    source: String,
    status: String,
    side_effect: String,
    metadata: String,
}

/// SQLite-backed trace store with content-addressed blob storage.
///
/// Metadata lives in SQLite; large payloads (blobs) are stored as
/// files in a content-addressed directory (`blob_dir/<sha256>`).
///
/// A single `parking_lot::Mutex<Connection>` serializes access and
/// avoids SQLITE_BUSY races from concurrent open-per-call connections.
///
/// **Known limitation:** The `Mutex` blocks the tokio worker thread
/// for the duration of every synchronous SQLite call. This is acceptable
/// for the current single-dashboard + CLI usage pattern but will need
/// replacement with `tokio::sync::Mutex` (or an r2d2 pool) if the
/// server faces concurrent write-heavy workloads.
/// M-14: There is currently no garbage-collection pass for orphaned blobs.
/// Blobs whose referencing rows are deleted remain on disk.  A future
/// `gc_blobs()` method should cross-reference the `blobs` table against
/// `events` / `checkpoints` rows and prune unreferenced entries.
pub struct SqliteStore {
    conn: Mutex<Connection>,
    blob_dir: PathBuf,
    db_path: PathBuf,
    /// Optional ChaCha20-Poly1305 at-rest encryption for blob files.
    blob_crypto: Option<crate::crypto::BlobCrypto>,
}

impl SqliteStore {
    /// Open or create a SQLite database at the given path.
    ///
    /// Blob directory is derived via [`crate::config::BlackboxPaths`].
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let paths = crate::config::BlackboxPaths::from_db_path(path.as_ref().to_path_buf());
        Self::open_with_blobs(&paths.db_path, &paths.blob_dir)
    }

    /// Open with an explicit blob directory (used by path resolver / tests).
    pub fn open_with_blobs(
        db_path: impl AsRef<Path>,
        blob_dir: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        Self::open_with_blobs_crypto(db_path, blob_dir, None)
    }

    /// Open with optional blob encryption.
    pub fn open_with_blobs_crypto(
        db_path: impl AsRef<Path>,
        blob_dir: impl AsRef<Path>,
        blob_crypto: Option<crate::crypto::BlobCrypto>,
    ) -> anyhow::Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        let blob_dir = blob_dir.as_ref().to_path_buf();

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).context("failed to create database directory")?;
            crate::privacy::restrict_dir(parent);
            // Also restrict grandparent `.blackbox` if present
            if let Some(grand) = parent.parent() {
                if grand.file_name().map(|n| n == ".blackbox").unwrap_or(false) {
                    crate::privacy::restrict_dir(grand);
                }
            }
        }
        std::fs::create_dir_all(&blob_dir).context("failed to create blob directory")?;
        crate::privacy::restrict_dir(&blob_dir);

        let conn = Connection::open(&db_path).context("failed to open SQLite database")?;
        crate::privacy::restrict_file(&db_path);
        // WAL/SHM sidecars if already present
        crate::privacy::restrict_file(&PathBuf::from(format!("{}-wal", db_path.display())));
        crate::privacy::restrict_file(&PathBuf::from(format!("{}-shm", db_path.display())));

        // Cap page cache (~8 MiB) so ambient capture stays light on shared machines.
        // Negative cache_size is KiB units in SQLite.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             PRAGMA busy_timeout=5000;
             PRAGMA cache_size=-8192;
             PRAGMA temp_store=MEMORY;",
        )
        .context("failed to set pragmas")?;

        // Checkpoint any leftover WAL from a previous session so we
        // start with a clean baseline.
        conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")
            .context("failed to WAL checkpoint")?;

        let store = Self {
            conn: Mutex::new(conn),
            blob_dir,
            db_path,
            blob_crypto,
        };
        store.migrate()?;
        // After migrations, checkpoint the WAL so growth from schema changes is reclaimed.
        if let Err(e) = store.wal_checkpoint() {
            tracing::warn!(error = %e, "post-migration WAL checkpoint failed (non-fatal)");
        }
        store.recover_stale_runs()?;
        Ok(store)
    }

    /// Path to the SQLite file.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Path to the blob directory.
    pub fn blob_dir(&self) -> &Path {
        &self.blob_dir
    }

    /// Whether at-rest blob encryption is active for new writes.
    pub fn blob_encryption_enabled(&self) -> bool {
        self.blob_crypto.is_some()
    }

    /// Attach / replace blob crypto after open (e.g. when config enables it).
    pub fn with_blob_crypto(mut self, crypto: Option<crate::crypto::BlobCrypto>) -> Self {
        self.blob_crypto = crypto;
        self
    }

    /// Mark abandoned `Running` runs as `Failed` (interrupted recovery).
    ///
    /// Called on open so a killed supervisor does not leave ghost sessions.
    /// Never infers success: status becomes Failed and notes record that final
    /// events/checkpoints may be incomplete (1.4 Phase D / WS9).
    fn recover_stale_runs(&self) -> anyhow::Result<()> {
        let conn = self.lock();
        let now = chrono::Utc::now().to_rfc3339();
        let note = "recovered: interrupted (supervisor exited while status=Running); final events/checkpoints may be incomplete";
        let n = conn.execute(
            "UPDATE runs
             SET status = ?1,
                 ended_at = COALESCE(ended_at, ?2),
                 notes = CASE
                     WHEN notes IS NULL OR notes = '' THEN ?4
                     WHEN notes LIKE '%recovered:%' THEN notes
                     ELSE notes || '; ' || ?4
                 END
             WHERE status = ?3",
            params![
                serde_json::to_string(&crate::core::run::RunStatus::Failed)
                    .unwrap_or_else(|_| "\"Failed\"".into()),
                now,
                serde_json::to_string(&crate::core::run::RunStatus::Running)
                    .unwrap_or_else(|_| "\"Running\"".into()),
                note,
            ],
        )?;
        if n > 0 {
            tracing::warn!(
                count = n,
                "recovered abandoned Running runs as Failed (interrupted)"
            );
        }
        Ok(())
    }

    /// Open an in-memory SQLite database (for testing).
    pub fn open_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory SQLite")?;

        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;")
            .context("failed to set pragmas")?;

        let blob_dir =
            std::env::temp_dir().join(format!("blackbox-test-blobs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&blob_dir).context("failed to create test blob directory")?;

        let store = Self {
            conn: Mutex::new(conn),
            blob_dir,
            db_path: PathBuf::from(":memory:"),
            blob_crypto: None,
        };
        store.migrate()?;
        Ok(store)
    }

    /// WAL checkpoint: flush WAL to main database file and truncate the WAL.
    ///
    /// Should be called periodically after write-heavy operations to prevent
    /// unbounded WAL growth. Uses TRUNCATE checkpoint for maximum effect.
    pub fn wal_checkpoint(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .context("failed to WAL checkpoint")?;
        Ok(())
    }

    fn lock(&self) -> parking_lot::MutexGuard<'_, Connection> {
        self.conn.lock()
    }

    /// Run schema migrations up to `SCHEMA_VERSION`.
    fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.lock();

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            );",
        )
        .context("failed to create schema_version table")?;

        let current: i32 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if current < 1 {
            let tx = conn
                .unchecked_transaction()
                .context("failed to start transaction for v1 migration")?;
            Self::migrate_v1(&tx)?;
            tx.execute("INSERT INTO schema_version (version) VALUES (1)", [])
                .context("failed to record v1 version")?;
            tx.commit().context("failed to commit v1 migration")?;
        }

        if current < 2 {
            let tx = conn
                .unchecked_transaction()
                .context("failed to start transaction for v2 migration")?;
            Self::migrate_v2(&tx, &self.blob_dir)?;
            tx.execute("INSERT INTO schema_version (version) VALUES (2)", [])
                .context("failed to record v2 version")?;
            tx.commit().context("failed to commit v2 migration")?;
        }

        if current < 3 {
            let tx = conn
                .unchecked_transaction()
                .context("failed to start transaction for v3 migration")?;
            Self::migrate_v3(&tx)?;
            tx.execute("INSERT INTO schema_version (version) VALUES (3)", [])
                .context("failed to record v3 version")?;
            tx.commit().context("failed to commit v3 migration")?;
        }
        if current < 4 {
            let tx = conn
                .unchecked_transaction()
                .context("failed to start transaction for v4 migration")?;
            Self::migrate_v4(&tx)?;
            tx.execute("INSERT INTO schema_version (version) VALUES (4)", [])
                .context("failed to record v4 version")?;
            tx.commit().context("failed to commit v4 migration")?;
        }
        if current < 5 {
            let tx = conn
                .unchecked_transaction()
                .context("failed to start transaction for v5 migration")?;
            Self::migrate_v5(&tx)?;
            tx.execute("INSERT INTO schema_version (version) VALUES (5)", [])
                .context("failed to record v5 version")?;
            tx.commit().context("failed to commit v5 migration")?;
        }
        if current < 6 {
            let tx = conn
                .unchecked_transaction()
                .context("failed to start transaction for v6 migration")?;
            Self::migrate_v6(&tx)?;
            tx.execute("INSERT INTO schema_version (version) VALUES (6)", [])
                .context("failed to record v6 version")?;
            tx.commit().context("failed to commit v6 migration")?;
        }
        if current < 7 {
            let tx = conn
                .unchecked_transaction()
                .context("failed to start transaction for v7 migration")?;
            Self::migrate_v7(&tx)?;
            tx.execute("INSERT INTO schema_version (version) VALUES (7)", [])
                .context("failed to record v7 version")?;
            tx.commit().context("failed to commit v7 migration")?;
        }

        // Ensure we never claim a higher version than we support
        let applied: i32 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if applied > SCHEMA_VERSION {
            anyhow::bail!(
                "database schema version {} is newer than this binary supports (max {})",
                applied,
                SCHEMA_VERSION
            );
        }

        Ok(())
    }

    /// V3: FTS5 index over events for structured full-text search.
    fn migrate_v3(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(
            "
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                event_id UNINDEXED,
                run_id UNINDEXED,
                kind,
                source,
                status,
                body,
                tokenize = 'porter unicode61'
            );
            ",
        )
        .context("failed to create events_fts")?;

        // Backfill from existing events in batches to avoid loading
        // the entire table into memory at once.
        const BATCH: i64 = 500;
        let mut offset: i64 = 0;
        let mut total: usize = 0;
        loop {
            let mut stmt = conn
                .prepare(
                    "SELECT id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at,
                            duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata
                     FROM events
                     ORDER BY rowid
                     LIMIT ?1 OFFSET ?2",
                )
                .context("failed to prepare events backfill")?;
            let batch: Vec<TraceEvent> = stmt
                .query_map(params![BATCH, offset], event_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            if batch.is_empty() {
                break;
            }
            for ev in &batch {
                fts_upsert(conn, ev)?;
            }
            total += batch.len();
            offset += BATCH;
        }
        tracing::info!(count = total, "FTS index backfilled");
        Ok(())
    }

    /// Rebuild the full-text index from scratch (e.g. after bulk import).
    pub fn reindex_fts(&self) -> anyhow::Result<usize> {
        let conn = self.lock();
        // Clear existing FTS data and rebuild from events table.
        conn.execute("DELETE FROM events_fts", [])?;
        const BATCH: i64 = 500;
        let mut offset: i64 = 0;
        let mut total: usize = 0;
        loop {
            let mut stmt = conn.prepare(
                "SELECT id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at,
                        duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata
                 FROM events
                 ORDER BY rowid
                 LIMIT ?1 OFFSET ?2",
            )?;
            let batch: Vec<TraceEvent> = stmt
                .query_map(params![BATCH, offset], event_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            if batch.is_empty() {
                break;
            }
            for ev in &batch {
                fts_upsert(&conn, ev)?;
            }
            total += batch.len();
            offset += BATCH;
        }
        Ok(total)
    }
    /// V4: Composite index on events, checkpoints FK, contentless FTS5.
    fn migrate_v4(conn: &Connection) -> anyhow::Result<()> {
        // Fix-8: Composite index for get_events ORDER BY run_id, sequence.
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_events_run_sequence ON events(run_id, sequence);",
        )
        .context("failed to create composite index idx_events_run_sequence")?;

        // Fix-9: Add FK constraint on checkpoints.event_id referencing events(id).
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS checkpoints_new (
                id                          TEXT PRIMARY KEY,
                run_id                      TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                event_id                    TEXT REFERENCES events(id) ON DELETE SET NULL,
                git_commit                  TEXT,
                git_diff_blob               TEXT,
                filesystem_manifest_blob    TEXT,
                cwd                         TEXT NOT NULL,
                environment_blob            TEXT,
                transcript_blob             TEXT,
                harness_session_id          TEXT,
                created_at                  TEXT NOT NULL
            );
            INSERT INTO checkpoints_new
                (id, run_id, event_id, git_commit, git_diff_blob,
                 filesystem_manifest_blob, cwd, environment_blob,
                 transcript_blob, harness_session_id, created_at)
                SELECT id, run_id, event_id, git_commit, git_diff_blob,
                       filesystem_manifest_blob, cwd, environment_blob,
                       transcript_blob, harness_session_id, created_at
                FROM checkpoints;
            DROP TABLE checkpoints;
            ALTER TABLE checkpoints_new RENAME TO checkpoints;
            CREATE INDEX IF NOT EXISTS idx_checkpoints_run_id ON checkpoints(run_id);
            CREATE INDEX IF NOT EXISTS idx_checkpoints_event_id ON checkpoints(event_id);
            ",
        )
        .context("failed to recreate checkpoints table with FK")?;

        // Fix-10: Rebuild FTS index (content='' is incompatible with our SELECT pattern;
        // content doubling is the necessary trade-off for working FTS).
        // Drop and recreate FTS table to pick up any schema changes.
        conn.execute_batch(
            "
            DROP TABLE IF EXISTS events_fts;
            CREATE VIRTUAL TABLE events_fts USING fts5(
                event_id UNINDEXED,
                run_id UNINDEXED,
                kind,
                source,
                status,
                body,
                tokenize = 'porter unicode61'
            );
            ",
        )
        .context("failed to recreate events_fts")?;

        // Rebuild FTS index from events table.
        const BATCH: i64 = 500;
        let mut offset: i64 = 0;
        let mut total: usize = 0;
        loop {
            let mut stmt = conn.prepare(
                "SELECT id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at,
                        duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata
                 FROM events
                 ORDER BY rowid
                 LIMIT ?1 OFFSET ?2",
            )?;
            let batch: Vec<TraceEvent> = stmt
                .query_map(params![BATCH, offset], event_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            if batch.is_empty() {
                break;
            }
            for ev in &batch {
                fts_upsert(conn, ev)?;
            }
            total += batch.len();
            offset += BATCH;
        }
        tracing::info!(count = total, "v4 FTS index rebuilt");
        Ok(())
    }

    /// V5: Add missing indexes on events.parent_event_id and checkpoints.event_id.
    fn migrate_v5(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_events_parent_event_id ON events(parent_event_id);
             CREATE INDEX IF NOT EXISTS idx_checkpoints_event_id   ON checkpoints(event_id);",
        )
        .context("failed to create v5 indexes")?;
        tracing::info!(
            "v5: added missing indexes on events.parent_event_id and checkpoints.event_id"
        );
        Ok(())
    }

    /// V6: run-level metrics (duration, adapter, tokens, model).
    fn migrate_v6(conn: &Connection) -> anyhow::Result<()> {
        // SQLite ALTER ADD COLUMN is idempotent enough if we check; use IF NOT EXISTS pattern
        // via try each column (ignore duplicate column errors for re-runs in tests).
        let cols = [
            "ALTER TABLE runs ADD COLUMN duration_ms INTEGER",
            "ALTER TABLE runs ADD COLUMN adapter TEXT",
            "ALTER TABLE runs ADD COLUMN session_id TEXT",
            "ALTER TABLE runs ADD COLUMN input_tokens INTEGER",
            "ALTER TABLE runs ADD COLUMN output_tokens INTEGER",
            "ALTER TABLE runs ADD COLUMN total_tokens INTEGER",
            "ALTER TABLE runs ADD COLUMN estimated_cost_usd REAL",
            "ALTER TABLE runs ADD COLUMN model TEXT",
        ];
        for sql in cols {
            match conn.execute(sql, []) {
                Ok(_) => {}
                Err(e) if e.to_string().contains("duplicate column") => {}
                Err(e) => return Err(e).context("v6 ALTER TABLE runs")?,
            }
        }
        // Best-effort duration backfill from timestamps (seconds precision via julianday)
        let _ = conn.execute(
            "UPDATE runs SET duration_ms = CAST(
                (julianday(ended_at) - julianday(started_at)) * 86400000 AS INTEGER
             ) WHERE ended_at IS NOT NULL AND duration_ms IS NULL",
            [],
        );
        tracing::info!("v6: runs metrics columns (duration/adapter/tokens/model)");
        Ok(())
    }

    /// V7: incremental run aggregates + indexes for salient event queries (1.5 L1).
    fn migrate_v7(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS run_aggregates (
                run_id               TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
                payload              TEXT NOT NULL,
                events_total         INTEGER NOT NULL DEFAULT 0,
                last_sequence        INTEGER NOT NULL DEFAULT 0,
                aggregates_complete  INTEGER NOT NULL DEFAULT 1,
                updated_at           TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_run_status ON events(run_id, status);
            CREATE INDEX IF NOT EXISTS idx_events_run_kind ON events(run_id, kind);
            ",
        )
        .context("failed to create v7 run_aggregates / indexes")?;
        tracing::info!("v7: run_aggregates table + event status/kind indexes");
        Ok(())
    }

    /// V1: core tables (runs, events, checkpoints, blobs metadata).
    fn migrate_v1(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS runs (
                id              TEXT PRIMARY KEY,
                name            TEXT,
                command         TEXT NOT NULL,
                cwd             TEXT NOT NULL,
                project_dir     TEXT NOT NULL,
                tags            TEXT NOT NULL DEFAULT '[]',
                notes           TEXT,
                status          TEXT NOT NULL DEFAULT 'Pending',
                started_at      TEXT NOT NULL,
                ended_at        TEXT,
                exit_code       INTEGER,
                parent_run_id   TEXT,
                next_sequence   INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS events (
                id              TEXT PRIMARY KEY,
                run_id          TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                parent_event_id TEXT,
                sequence        INTEGER NOT NULL DEFAULT 0,
                source          TEXT NOT NULL,
                kind            TEXT NOT NULL,
                started_at      TEXT NOT NULL,
                ended_at        TEXT,
                duration_ms     INTEGER,
                status          TEXT NOT NULL DEFAULT 'Pending',
                side_effect     TEXT NOT NULL DEFAULT 'Unknown',
                input_blob      TEXT,
                output_blob     TEXT,
                error_blob      TEXT,
                metadata        TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_events_run_id ON events(run_id);
            CREATE INDEX IF NOT EXISTS idx_events_parent_event_id ON events(parent_event_id);
            CREATE INDEX IF NOT EXISTS idx_events_run_sequence ON events(run_id, sequence);

            CREATE TABLE IF NOT EXISTS checkpoints (
                id                          TEXT PRIMARY KEY,
                run_id                      TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                event_id                    TEXT REFERENCES events(id) ON DELETE SET NULL,
                git_commit                  TEXT,
                git_diff_blob               TEXT,
                filesystem_manifest_blob    TEXT,
                cwd                         TEXT NOT NULL,
                environment_blob            TEXT,
                transcript_blob             TEXT,
                harness_session_id          TEXT,
                created_at                  TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_checkpoints_run_id ON checkpoints(run_id);
            CREATE INDEX IF NOT EXISTS idx_checkpoints_event_id ON checkpoints(event_id);

            CREATE TABLE IF NOT EXISTS blobs (
                key             TEXT PRIMARY KEY,
                size            INTEGER NOT NULL,
                compressed      INTEGER NOT NULL DEFAULT 0,
                content_type    TEXT
            );
            ",
        )
        .context("failed to create v1 tables")?;

        Ok(())
    }

    /// V2: migrate legacy in-DB blob storage to on-disk content-addressed files.
    ///
    /// Older schemas stored `data BLOB NOT NULL` inside the blobs table.
    /// Extract those bytes to disk and drop the column by rebuilding the table.
    fn migrate_v2(conn: &Connection, blob_dir: &Path) -> anyhow::Result<()> {
        // Detect whether the old `data` column exists
        let has_data_col: bool = conn
            .prepare("PRAGMA table_info(blobs)")
            .and_then(|mut stmt| {
                let cols: Vec<String> = stmt
                    .query_map([], |row| row.get::<_, String>(1))?
                    .filter_map(|r| r.ok())
                    .collect();
                Ok(cols.iter().any(|c| c == "data"))
            })
            .unwrap_or(false);

        if has_data_col {
            // Extract blob data to disk before rebuilding the table
            let mut stmt = conn
                .prepare("SELECT key, data FROM blobs")
                .context("failed to prepare blob extract")?;
            let rows = stmt
                .query_map([], |row| {
                    let key: String = row.get(0)?;
                    let data: Vec<u8> = row.get(1)?;
                    Ok((key, data))
                })
                .context("failed to query legacy blobs")?;

            for row in rows {
                let (key, data) = row.context("failed to read legacy blob row")?;
                let path = blob_dir.join(&key);
                if !path.exists() {
                    std::fs::write(&path, &data)
                        .with_context(|| format!("failed to write blob {}", key))?;
                }
            }

            // Rebuild blobs table without the data column
            conn.execute_batch(
                "
                CREATE TABLE blobs_new (
                    key             TEXT PRIMARY KEY,
                    size            INTEGER NOT NULL,
                    compressed      INTEGER NOT NULL DEFAULT 0,
                    content_type    TEXT
                );
                INSERT INTO blobs_new (key, size, compressed, content_type)
                    SELECT key, size, compressed, content_type FROM blobs;
                DROP TABLE blobs;
                ALTER TABLE blobs_new RENAME TO blobs;
                ",
            )
            .context("failed to rebuild blobs table for v2")?;
        } else {
            // Ensure the table exists in the correct shape
            conn.execute_batch(
                "
                CREATE TABLE IF NOT EXISTS blobs (
                    key             TEXT PRIMARY KEY,
                    size            INTEGER NOT NULL,
                    compressed      INTEGER NOT NULL DEFAULT 0,
                    content_type    TEXT
                );
                ",
            )
            .context("failed to ensure blobs table")?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl TraceStore for SqliteStore {
    async fn insert_run(&self, run: &Run) -> anyhow::Result<()> {
        let run = run.clone();
        {
            let conn = self.lock();
            let command_json =
                serde_json::to_string(&run.command).context("failed to serialize command")?;
            let tags_json = serde_json::to_string(&run.tags).context("failed to serialize tags")?;
            let status_json =
                serde_json::to_string(&run.status).context("failed to serialize status")?;
            conn.execute(
                "INSERT INTO runs (id, name, command, cwd, project_dir, tags, notes, status, started_at, ended_at, exit_code, parent_run_id, next_sequence,
                 duration_ms, adapter, session_id, input_tokens, output_tokens, total_tokens, estimated_cost_usd, model)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
                params![
                    run.id,
                    run.name,
                    command_json,
                    run.cwd,
                    run.project_dir,
                    tags_json,
                    run.notes,
                    status_json,
                    run.started_at.to_rfc3339(),
                    run.ended_at.map(|t| t.to_rfc3339()),
                    run.exit_code,
                    run.parent_run_id,
                    run.next_sequence as i64,
                    run.duration_ms.map(|v| v as i64),
                    run.adapter,
                    run.session_id,
                    run.input_tokens.map(|v| v as i64),
                    run.output_tokens.map(|v| v as i64),
                    run.total_tokens.map(|v| v as i64),
                    run.estimated_cost_usd,
                    run.model,
                ],
            )
            .context("failed to insert run")?;
        }
        tokio::task::yield_now().await;
        Ok(())
    }

    async fn update_run(&self, run: &Run) -> anyhow::Result<()> {
        let run = run.clone();
        {
            let conn = self.lock();
            let command_json =
                serde_json::to_string(&run.command).context("failed to serialize command")?;
            let tags_json = serde_json::to_string(&run.tags).context("failed to serialize tags")?;
            let status_json =
                serde_json::to_string(&run.status).context("failed to serialize status")?;
            conn.execute(
                "UPDATE runs SET name=?2, command=?3, cwd=?4, project_dir=?5, tags=?6, notes=?7, status=?8, started_at=?9, ended_at=?10, exit_code=?11, parent_run_id=?12, next_sequence=?13,
                 duration_ms=?14, adapter=?15, session_id=?16, input_tokens=?17, output_tokens=?18, total_tokens=?19, estimated_cost_usd=?20, model=?21
                 WHERE id=?1",
                params![
                    run.id,
                    run.name,
                    command_json,
                    run.cwd,
                    run.project_dir,
                    tags_json,
                    run.notes,
                    status_json,
                    run.started_at.to_rfc3339(),
                    run.ended_at.map(|t| t.to_rfc3339()),
                    run.exit_code,
                    run.parent_run_id,
                    run.next_sequence as i64,
                    run.duration_ms.map(|v| v as i64),
                    run.adapter,
                    run.session_id,
                    run.input_tokens.map(|v| v as i64),
                    run.output_tokens.map(|v| v as i64),
                    run.total_tokens.map(|v| v as i64),
                    run.estimated_cost_usd,
                    run.model,
                ],
            )
            .context("failed to update run")?;
        }
        tokio::task::yield_now().await;
        Ok(())
    }

    async fn get_run(&self, run_id: &str) -> anyhow::Result<Option<Run>> {
        let run_id = run_id.to_string();
        let result = {
            let conn = self.lock();
            let mut stmt = conn.prepare(
                "SELECT id, name, command, cwd, project_dir, tags, notes, status, started_at, ended_at, exit_code, parent_run_id, next_sequence,
                 duration_ms, adapter, session_id, input_tokens, output_tokens, total_tokens, estimated_cost_usd, model
                 FROM runs WHERE id = ?1",
            )?;
            match stmt.query_row(params![run_id], run_from_row) {
                Ok(run) => Ok(Some(run)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e.into()),
            }
        };
        tokio::task::yield_now().await;
        result
    }

    async fn list_runs(&self) -> anyhow::Result<Vec<Run>> {
        let result = {
            let conn = self.lock();
            let mut stmt = conn.prepare(
                "SELECT id, name, command, cwd, project_dir, tags, notes, status, started_at, ended_at, exit_code, parent_run_id, next_sequence,
                 duration_ms, adapter, session_id, input_tokens, output_tokens, total_tokens, estimated_cost_usd, model
                 FROM runs ORDER BY started_at DESC",
            )?;
            let runs = stmt
                .query_map([], run_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(runs)
        };
        tokio::task::yield_now().await;
        result
    }

    async fn delete_run(&self, run_id: &str) -> anyhow::Result<bool> {
        let run_id = run_id.to_string();
        let deleted = {
            let conn = self.lock();
            let tx = conn
                .unchecked_transaction()
                .context("failed to start transaction for delete_run")?;
            // FK order: events and checkpoints before runs
            if let Err(e) = tx.execute("DELETE FROM events_fts WHERE run_id = ?1", params![run_id])
            {
                tracing::warn!(error = %e, run_id = %run_id, "FTS cleanup failed during delete_run; proceeding");
            }
            tx.execute("DELETE FROM events WHERE run_id = ?1", params![run_id])
                .context("failed to delete events")?;
            tx.execute("DELETE FROM checkpoints WHERE run_id = ?1", params![run_id])
                .context("failed to delete checkpoints")?;
            let n = tx
                .execute("DELETE FROM runs WHERE id = ?1", params![run_id])
                .context("failed to delete run")?;
            tx.commit().context("failed to commit delete_run")?;
            n > 0
        };
        tokio::task::yield_now().await;
        Ok(deleted)
    }

    async fn insert_event(&self, event: &TraceEvent) -> anyhow::Result<()> {
        let event = event.clone();
        // Serialize structured fields upfront so that serde_json errors
        // propagate instead of silently corrupting data via unwrap_or_default().
        let source_json =
            serde_json::to_string(&event.source).context("failed to serialize event.source")?;
        let status_json =
            serde_json::to_string(&event.status).context("failed to serialize event.status")?;
        let side_effect_json = serde_json::to_string(&event.side_effect)
            .context("failed to serialize event.side_effect")?;
        let metadata_json =
            serde_json::to_string(&event.metadata).context("failed to serialize event.metadata")?;
        {
            let conn = self.lock();
            // Wrap event INSERT + FTS upsert in a single transaction for atomicity.
            let tx = conn
                .unchecked_transaction()
                .context("failed to start transaction for insert_event")?;
            tx.execute(
                "INSERT INTO events (id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    event.id,
                    event.run_id,
                    event.parent_event_id,
                    event.sequence as i64,
                    source_json,
                    event.kind,
                    event.started_at.to_rfc3339(),
                    event.ended_at.map(|t| t.to_rfc3339()),
                    event.duration_ms.map(|d| d as i64),
                    status_json,
                    side_effect_json,
                    event.input_blob,
                    event.output_blob,
                    event.error_blob,
                    metadata_json,
                ],
            )
            .context("failed to insert event")?;
            // FTS upsert within the same transaction (best-effort: table may be
            // missing on ancient DBs mid-migrate)
            let _ = fts_upsert_in_tx(&tx, &event);
            // Incremental aggregates (1.5 L1) — best-effort; recompute recovers.
            if let Err(e) = apply_event_to_aggregates_in_tx(&tx, &event) {
                tracing::warn!(error = %e, run_id = %event.run_id, "aggregate update failed");
            }
            tx.commit()
                .context("failed to commit insert_event transaction")?;
        }
        tokio::task::yield_now().await;
        Ok(())
    }

    async fn get_events(&self, run_id: &str) -> anyhow::Result<Vec<TraceEvent>> {
        let run_id = run_id.to_string();
        let result = {
            let conn = self.lock();
            let mut stmt = conn.prepare(
                "SELECT id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata
                 FROM events WHERE run_id = ?1 ORDER BY sequence",
            )?;
            let events = stmt
                .query_map(params![run_id], event_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(events)
        };
        tokio::task::yield_now().await;
        result
    }

    async fn get_events_limited(
        &self,
        run_id: &str,
        limit: usize,
    ) -> anyhow::Result<(Vec<TraceEvent>, bool)> {
        if limit == 0 {
            return Ok((Vec::new(), false));
        }
        let run_id = run_id.to_string();
        let result = {
            let conn = self.lock();
            let total: i64 = conn.query_row(
                "SELECT COUNT(*) FROM events WHERE run_id = ?1",
                params![run_id],
                |row| row.get(0),
            )?;
            let total = total as usize;
            // Fetch last `limit` by sequence DESC then reverse to ascending.
            let mut stmt = conn.prepare(
                "SELECT id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata
                 FROM events WHERE run_id = ?1 ORDER BY sequence DESC LIMIT ?2",
            )?;
            let mut events = stmt
                .query_map(params![run_id, limit as i64], event_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            events.reverse();
            let truncated = total > events.len();
            Ok((events, truncated))
        };
        tokio::task::yield_now().await;
        result
    }

    async fn count_events(&self, run_id: &str) -> anyhow::Result<usize> {
        let run_id = run_id.to_string();
        let result = {
            let conn = self.lock();
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM events WHERE run_id = ?1",
                params![run_id],
                |row| row.get(0),
            )?;
            Ok(n as usize)
        };
        tokio::task::yield_now().await;
        result
    }

    async fn get_events_since(
        &self,
        run_id: &str,
        after_seq: u64,
        limit: usize,
    ) -> anyhow::Result<Vec<TraceEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let run_id = run_id.to_string();
        let result = {
            let conn = self.lock();
            let mut stmt = conn.prepare(
                "SELECT id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata
                 FROM events WHERE run_id = ?1 AND sequence > ?2 ORDER BY sequence ASC LIMIT ?3",
            )?;
            let events = stmt
                .query_map(
                    params![run_id, after_seq as i64, limit as i64],
                    event_from_row,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(events)
        };
        tokio::task::yield_now().await;
        result
    }

    async fn get_event(&self, event_id: &str) -> anyhow::Result<Option<TraceEvent>> {
        let event_id = event_id.to_string();
        let result = {
            let conn = self.lock();
            let mut stmt = conn.prepare(
                "SELECT id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata
                 FROM events WHERE id = ?1",
            )?;
            match stmt.query_row(params![event_id], event_from_row) {
                Ok(ev) => Ok(Some(ev)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e.into()),
            }
        };
        tokio::task::yield_now().await;
        result
    }

    async fn update_event(&self, event: &TraceEvent) -> anyhow::Result<()> {
        let event = event.clone();
        // Serialize structured fields upfront to propagate serde_json errors.
        let source_json =
            serde_json::to_string(&event.source).context("failed to serialize event.source")?;
        let status_json =
            serde_json::to_string(&event.status).context("failed to serialize event.status")?;
        let side_effect_json = serde_json::to_string(&event.side_effect)
            .context("failed to serialize event.side_effect")?;
        let metadata_json =
            serde_json::to_string(&event.metadata).context("failed to serialize event.metadata")?;
        {
            let conn = self.lock();
            // Wrap event UPDATE + FTS upsert in a single transaction for atomicity.
            let tx = conn
                .unchecked_transaction()
                .context("failed to start transaction for update_event")?;
            let n = tx.execute(
                "UPDATE events SET run_id=?2, parent_event_id=?3, sequence=?4, source=?5, kind=?6,
                started_at=?7, ended_at=?8, duration_ms=?9, status=?10, side_effect=?11,
                input_blob=?12, output_blob=?13, error_blob=?14, metadata=?15
                WHERE id=?1",
                params![
                    event.id,
                    event.run_id,
                    event.parent_event_id,
                    event.sequence as i64,
                    source_json,
                    event.kind,
                    event.started_at.to_rfc3339(),
                    event.ended_at.map(|t| t.to_rfc3339()),
                    event.duration_ms.map(|d| d as i64),
                    status_json,
                    side_effect_json,
                    event.input_blob,
                    event.output_blob,
                    event.error_blob,
                    metadata_json,
                ],
            )
            .context("failed to update event")?;
            if n == 0 {
                tx.rollback().ok();
                anyhow::bail!("event not found for update: {}", event.id);
            }
            // FTS upsert within the same transaction
            let _ = fts_upsert_in_tx(&tx, &event);
            tx.commit()
                .context("failed to commit update_event transaction")?;
        }
        tokio::task::yield_now().await;
        Ok(())
    }

    async fn fts_event_ids(
        &self,
        query: &str,
        limit: usize,
    ) -> anyhow::Result<Option<Vec<(String, String, f64)>>> {
        let match_q = build_fts_match(query);
        if match_q.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let limit = limit.max(1) as i64;
        let result = {
            let conn = self.lock();
            let mut stmt = match conn.prepare(
                "SELECT event_id, run_id, rank
                 FROM events_fts
                 WHERE events_fts MATCH ?1
                 ORDER BY rank
                 LIMIT ?2",
            ) {
                Ok(s) => s,
                Err(_) => return Ok(None), // FTS unavailable
            };
            let rows = stmt.query_map(params![match_q, limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, f64>(2).unwrap_or(0.0),
                ))
            });
            match rows {
                Ok(iter) => Ok(Some(iter.filter_map(|r| r.ok()).collect::<Vec<_>>())),
                Err(e) => Err(e.into()),
            }
        };
        tokio::task::yield_now().await;
        result
    }

    async fn insert_checkpoint(&self, cp: &Checkpoint) -> anyhow::Result<()> {
        let cp = cp.clone();
        {
            let conn = self.lock();
            conn.execute(
                "INSERT INTO checkpoints (id, run_id, event_id, git_commit, git_diff_blob, filesystem_manifest_blob, cwd, environment_blob, transcript_blob, harness_session_id, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    cp.id,
                    cp.run_id,
                    cp.event_id,
                    cp.git_commit,
                    cp.git_diff_blob,
                    cp.filesystem_manifest_blob,
                    cp.cwd,
                    cp.environment_blob,
                    cp.transcript_blob,
                    cp.harness_session_id,
                    cp.created_at.to_rfc3339(),
                ],
            )
            .context("failed to insert checkpoint")?;
        }
        tokio::task::yield_now().await;
        Ok(())
    }

    async fn update_checkpoint(&self, cp: &Checkpoint) -> anyhow::Result<()> {
        let cp = cp.clone();
        {
            let conn = self.lock();
            let n = conn
                .execute(
                    "UPDATE checkpoints SET run_id=?2, event_id=?3, git_commit=?4, git_diff_blob=?5,
                     filesystem_manifest_blob=?6, cwd=?7, environment_blob=?8, transcript_blob=?9,
                     harness_session_id=?10, created_at=?11 WHERE id=?1",
                    params![
                        cp.id,
                        cp.run_id,
                        cp.event_id,
                        cp.git_commit,
                        cp.git_diff_blob,
                        cp.filesystem_manifest_blob,
                        cp.cwd,
                        cp.environment_blob,
                        cp.transcript_blob,
                        cp.harness_session_id,
                        cp.created_at.to_rfc3339(),
                    ],
                )
                .context("failed to update checkpoint")?;
            if n == 0 {
                anyhow::bail!("checkpoint not found: {}", cp.id);
            }
        }
        tokio::task::yield_now().await;
        Ok(())
    }

    async fn get_checkpoints(&self, run_id: &str) -> anyhow::Result<Vec<Checkpoint>> {
        let run_id = run_id.to_string();
        let result = {
            let conn = self.lock();
            let mut stmt = conn.prepare(
                "SELECT id, run_id, event_id, git_commit, git_diff_blob, filesystem_manifest_blob, cwd, environment_blob, transcript_blob, harness_session_id, created_at
                 FROM checkpoints WHERE run_id = ?1",
            )?;
            let checkpoints = stmt
                .query_map(params![run_id], checkpoint_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(checkpoints)
        };
        tokio::task::yield_now().await;
        result
    }

    async fn store_blob(&self, data: &[u8]) -> anyhow::Result<BlobReference> {
        // Content key is always over plaintext so addresses stay stable.
        let key = crate::crypto::content_key(data);
        let size = data.len() as u64;

        // Optionally encrypt on disk (BBEN header); key still hashes plaintext.
        let disk_bytes = if let Some(ref crypto) = self.blob_crypto {
            crypto.seal(data)?
        } else {
            data.to_vec()
        };

        let blob_path = self.blob_dir.join(&key);
        if !blob_path.exists() {
            let blob_dir = self.blob_dir.clone();
            let key_for_write = key.clone();
            let data_for_write = disk_bytes;
            task::spawn_blocking(move || -> anyhow::Result<()> {
                std::fs::create_dir_all(&blob_dir).context("failed to create blob directory")?;
                crate::privacy::restrict_dir(&blob_dir);
                let target = blob_dir.join(&key_for_write);
                let temp = target.with_extension("tmp");
                std::fs::write(&temp, &data_for_write).context("failed to write blob temp file")?;
                crate::privacy::restrict_file(&temp);
                std::fs::rename(&temp, &target).context("failed to rename blob temp file")?;
                crate::privacy::restrict_file(&target);
                Ok(())
            })
            .await??;
        }

        {
            let conn = self.lock();
            conn.execute(
                "INSERT OR IGNORE INTO blobs (key, size, compressed, content_type)
                 VALUES (?1, ?2, 0, NULL)",
                params![key, size as i64],
            )
            .context("failed to store blob metadata")?;
        }

        Ok(BlobReference::new(key, size))
    }

    async fn load_blob(&self, reference: &BlobReference) -> anyhow::Result<Vec<u8>> {
        let blob_dir = self.blob_dir.clone();
        let key = reference.key.clone();
        let crypto = self.blob_crypto.clone();
        task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            let path = blob_dir.join(&key);
            let data = std::fs::read(&path)
                .with_context(|| format!("blob not found: {}", path.display()))?;
            // Decrypt if sealed; plaintext legacy blobs pass through.
            let plain = if let Some(ref c) = crypto {
                c.open(&data)?
            } else if crate::crypto::is_encrypted_blob(&data) {
                anyhow::bail!(
                    "blob {} is encrypted but store has no key — set encrypt_blobs / BLACKBOX_STORE_KEY",
                    key
                );
            } else {
                data
            };
            // Integrity: SHA-256 of plaintext must match content key.
            let computed = crate::crypto::content_key(&plain);
            if computed != key {
                anyhow::bail!(
                    "blob integrity mismatch: expected key {} but computed SHA-256 {}",
                    key,
                    computed
                );
            }
            Ok(plain)
        })
        .await?
    }

    async fn move_blob(&self, from_key: &str, to_key: &str) -> anyhow::Result<()> {
        // Move the file on disk
        {
            let blob_dir = self.blob_dir.clone();
            let fk = from_key.to_string();
            let tk = to_key.to_string();
            task::spawn_blocking(move || -> anyhow::Result<()> {
                let from = blob_dir.join(&fk);
                let to = blob_dir.join(&tk);
                if from.exists() && !to.exists() {
                    std::fs::rename(&from, &to).context("failed to rename blob file")?;
                }
                Ok(())
            })
            .await??;
        }
        // Update SQLite metadata: move the row from old key to new key
        // inside a transaction so a crash cannot leave the row deleted
        // without the new row inserted.
        {
            let conn = self.lock();
            let tx = conn
                .unchecked_transaction()
                .context("failed to start transaction for move_blob")?;
            let meta: (i64, bool, Option<String>) = tx
                .query_row(
                    "SELECT size, compressed, content_type FROM blobs WHERE key = ?1",
                    params![from_key],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap_or((0, false, None));
            tx.execute("DELETE FROM blobs WHERE key = ?1", params![from_key])?;
            tx.execute(
                "INSERT OR IGNORE INTO blobs (key, size, compressed, content_type)
                 VALUES (?1, ?2, ?3, ?4)",
                params![to_key, meta.0, meta.1, meta.2],
            )?;
            tx.commit()
                .context("failed to commit move_blob transaction")?;
        }
        Ok(())
    }
    async fn insert_events_batch(&self, events: &[TraceEvent]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        // Pre-serialize structured fields so any serde_json errors are caught
        // before the transaction begins, avoiding data corruption via unwrap_or_default().
        let prepared: Vec<SerializedEvent> = events
            .iter()
            .map(|e| {
                Ok(SerializedEvent {
                    source: serde_json::to_string(&e.source)
                        .context("failed to serialize event.source")?,
                    status: serde_json::to_string(&e.status)
                        .context("failed to serialize event.status")?,
                    side_effect: serde_json::to_string(&e.side_effect)
                        .context("failed to serialize event.side_effect")?,
                    metadata: serde_json::to_string(&e.metadata)
                        .context("failed to serialize event.metadata")?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        {
            let conn = self.lock();
            let tx = conn
                .unchecked_transaction()
                .context("failed to start transaction for insert_events_batch")?;
            // Per-run aggregate state loaded once for the batch (1.5 L1).
            let mut agg_cache: std::collections::HashMap<String, RunAggregates> =
                std::collections::HashMap::new();
            for (i, event) in events.iter().enumerate() {
                let s = &prepared[i];
                tx.execute(
                    "INSERT INTO events (id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        event.id,
                        event.run_id,
                        event.parent_event_id,
                        event.sequence as i64,
                        &s.source,
                        event.kind,
                        event.started_at.to_rfc3339(),
                        event.ended_at.map(|t| t.to_rfc3339()),
                        event.duration_ms.map(|d| d as i64),
                        &s.status,
                        &s.side_effect,
                        event.input_blob,
                        event.output_blob,
                        event.error_blob,
                        &s.metadata,
                    ],
                )
                .context("failed to insert event in batch")?;
                let _ = fts_upsert_in_tx(&tx, event);
                let agg = agg_cache.entry(event.run_id.clone()).or_insert_with(|| {
                    load_aggregates(&tx, &event.run_id)
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| RunAggregates::new(event.run_id.clone()))
                });
                agg.observe(event);
            }
            for agg in agg_cache.values() {
                if let Err(e) = upsert_aggregates(&tx, agg) {
                    tracing::warn!(error = %e, run_id = %agg.run_id, "batch aggregate upsert failed");
                }
            }
            tx.commit()
                .context("failed to commit insert_events_batch transaction")?;
        }
        // Flush WAL after batch write to keep WAL size bounded.
        if let Err(e) = self.wal_checkpoint() {
            tracing::warn!(error = %e, "post-batch WAL checkpoint failed (non-fatal)");
        }
        tokio::task::yield_now().await;
        Ok(())
    }
    async fn all_blob_keys(&self) -> anyhow::Result<Vec<String>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT key FROM blobs")
            .context("failed to prepare all_blob_keys")?;
        let keys = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(keys)
    }

    async fn delete_blob_keys(&self, keys: &[String]) -> anyhow::Result<usize> {
        if keys.is_empty() {
            return Ok(0);
        }
        let conn = self.lock();
        let tx = conn
            .unchecked_transaction()
            .context("failed to start transaction for delete_blob_keys")?;
        let mut deleted = 0usize;
        for key in keys {
            let n = tx
                .execute("DELETE FROM blobs WHERE key = ?1", params![key])
                .with_context(|| format!("failed to delete blob metadata for {key}"))?;
            deleted += n;
        }
        tx.commit().context("failed to commit delete_blob_keys")?;
        Ok(deleted)
    }

    async fn get_run_aggregates(
        &self,
        run_id: &str,
    ) -> anyhow::Result<Option<RunAggregates>> {
        let run_id = run_id.to_string();
        let result = {
            let conn = self.lock();
            load_aggregates(&conn, &run_id)
        };
        tokio::task::yield_now().await;
        result
    }

    async fn put_run_aggregates(&self, agg: &RunAggregates) -> anyhow::Result<()> {
        let agg = agg.clone();
        {
            let conn = self.lock();
            upsert_aggregates(&conn, &agg)?;
        }
        tokio::task::yield_now().await;
        Ok(())
    }

    async fn recompute_run_aggregates(
        &self,
        run_id: &str,
    ) -> anyhow::Result<RunAggregates> {
        let events = self.get_events(run_id).await?;
        let agg = RunAggregates::recompute(run_id, &events);
        self.put_run_aggregates(&agg).await?;
        Ok(agg)
    }

    async fn get_events_head(
        &self,
        run_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TraceEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let run_id = run_id.to_string();
        let result = {
            let conn = self.lock();
            let mut stmt = conn.prepare(
                "SELECT id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata
                 FROM events WHERE run_id = ?1 ORDER BY sequence ASC LIMIT ?2",
            )?;
            let events = stmt
                .query_map(params![run_id, limit as i64], event_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(events)
        };
        tokio::task::yield_now().await;
        result
    }

    async fn get_events_tail(
        &self,
        run_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TraceEvent>> {
        let (events, _) = self.get_events_limited(run_id, limit).await?;
        Ok(events)
    }

    async fn get_events_by_kinds(
        &self,
        run_id: &str,
        kinds: &[&str],
        limit: usize,
    ) -> anyhow::Result<Vec<TraceEvent>> {
        if kinds.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let run_id = run_id.to_string();
        let kinds_owned: Vec<String> = kinds.iter().map(|s| (*s).to_string()).collect();
        let result = {
            let conn = self.lock();
            // Build IN clause placeholders.
            let placeholders: String = (0..kinds_owned.len())
                .map(|i| format!("?{}", i + 2))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "SELECT id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata
                 FROM events WHERE run_id = ?1 AND kind IN ({placeholders})
                 ORDER BY sequence ASC LIMIT ?{lim}",
                lim = kinds_owned.len() + 2
            );
            let mut stmt = conn.prepare(&sql)?;
            let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
            values.push(Box::new(run_id));
            for k in &kinds_owned {
                values.push(Box::new(k.clone()));
            }
            values.push(Box::new(limit as i64));
            let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                values.iter().map(|v| v.as_ref()).collect();
            let events = stmt
                .query_map(params_refs.as_slice(), event_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(events)
        };
        tokio::task::yield_now().await;
        result
    }

    async fn get_error_events(
        &self,
        run_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<TraceEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let run_id = run_id.to_string();
        // EventStatus::Error serializes as `"Error"` (with quotes in JSON form stored).
        let status_json = serde_json::to_string(&crate::core::event::EventStatus::Error)
            .unwrap_or_else(|_| "\"Error\"".into());
        let result = {
            let conn = self.lock();
            let mut stmt = conn.prepare(
                "SELECT id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata
                 FROM events WHERE run_id = ?1 AND status = ?2
                 ORDER BY sequence ASC LIMIT ?3",
            )?;
            let events = stmt
                .query_map(params![run_id, status_json, limit as i64], event_from_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(events)
        };
        tokio::task::yield_now().await;
        result
    }
}

/// Load aggregates payload for a run, if present.
fn load_aggregates(conn: &Connection, run_id: &str) -> anyhow::Result<Option<RunAggregates>> {
    let mut stmt = conn.prepare(
        "SELECT payload FROM run_aggregates WHERE run_id = ?1",
    )?;
    match stmt.query_row(params![run_id], |row| row.get::<_, String>(0)) {
        Ok(payload) => {
            let agg: RunAggregates = serde_json::from_str(&payload)
                .context("failed to deserialize run_aggregates payload")?;
            Ok(Some(agg))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => {
            // Table may be missing mid-migration on ancient DBs.
            if e.to_string().contains("no such table") {
                return Ok(None);
            }
            Err(e.into())
        }
    }
}

fn upsert_aggregates(conn: &Connection, agg: &RunAggregates) -> anyhow::Result<()> {
    let payload =
        serde_json::to_string(agg).context("failed to serialize run_aggregates payload")?;
    conn.execute(
        "INSERT INTO run_aggregates (run_id, payload, events_total, last_sequence, aggregates_complete, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(run_id) DO UPDATE SET
           payload = excluded.payload,
           events_total = excluded.events_total,
           last_sequence = excluded.last_sequence,
           aggregates_complete = excluded.aggregates_complete,
           updated_at = excluded.updated_at",
        params![
            agg.run_id,
            payload,
            agg.events_total as i64,
            agg.last_sequence as i64,
            if agg.aggregates_complete { 1i64 } else { 0i64 },
            agg.updated_at.to_rfc3339(),
        ],
    )
    .context("failed to upsert run_aggregates")?;
    Ok(())
}

fn apply_event_to_aggregates_in_tx(
    tx: &rusqlite::Transaction<'_>,
    event: &TraceEvent,
) -> anyhow::Result<()> {
    // Ensure table exists (fresh DBs always have it after migrate).
    let mut agg = match load_aggregates(tx, &event.run_id)? {
        Some(a) => a,
        None => RunAggregates::new(event.run_id.clone()),
    };
    agg.observe(event);
    upsert_aggregates(tx, &agg)?;
    Ok(())
}

fn event_search_body(event: &TraceEvent) -> String {
    // Only include metadata values in the body column; kind, source, and
    // status are separate FTS columns and indexing them in body too would
    // double-count them during ranking.
    let mut body = String::new();
    for (k, v) in &event.metadata {
        if !body.is_empty() {
            body.push(' ');
        }
        body.push_str(k);
        body.push(' ');
        match v {
            serde_json::Value::String(s) => body.push_str(s),
            other => body.push_str(&other.to_string()),
        }
    }
    // Redact secrets before indexing in FTS to prevent leaking
    // credentials through full-text search results.
    FTS_SCANNER.redact(&body)
}

fn fts_upsert(conn: &Connection, event: &TraceEvent) -> anyhow::Result<()> {
    let source_str = serde_json::to_string(&event.source).unwrap_or_else(|_| "Unknown".to_string());
    let status_str = serde_json::to_string(&event.status).unwrap_or_else(|_| "Unknown".to_string());
    let tx = conn
        .unchecked_transaction()
        .context("failed to start transaction for FTS upsert")?;
    // Replace existing row for this event_id
    tx.execute(
        "DELETE FROM events_fts WHERE event_id = ?1",
        params![event.id],
    )
    .context("failed to delete existing FTS row for upsert")?;
    tx.execute(
        "INSERT INTO events_fts(event_id, run_id, kind, source, status, body)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            event.id,
            event.run_id,
            event.kind,
            source_str,
            status_str,
            event_search_body(event),
        ],
    )
    .context("failed to upsert events_fts")?;
    tx.commit().context("failed to commit FTS upsert")?;
    Ok(())
}

/// FTS upsert that operates within an existing transaction (no inner txn).
fn fts_upsert_in_tx(tx: &rusqlite::Transaction, event: &TraceEvent) -> anyhow::Result<()> {
    let source_str = serde_json::to_string(&event.source).unwrap_or_else(|_| "Unknown".to_string());
    let status_str = serde_json::to_string(&event.status).unwrap_or_else(|_| "Unknown".to_string());
    // Replace existing row for this event_id
    tx.execute(
        "DELETE FROM events_fts WHERE event_id = ?1",
        params![event.id],
    )
    .context("failed to delete existing FTS row for upsert")?;
    tx.execute(
        "INSERT INTO events_fts(event_id, run_id, kind, source, status, body)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            event.id,
            event.run_id,
            event.kind,
            source_str,
            status_str,
            event_search_body(event),
        ],
    )
    .context("failed to upsert events_fts")?;
    Ok(())
}

/// Build an FTS5 MATCH query: all alphanumeric terms AND-ed.
fn build_fts_match(query: &str) -> String {
    // Build a safe FTS5 match expression by quoting each term and filtering
    // out special FTS5 characters that could be used for injection.
    //
    // FTS5 special characters: * ( ) + - ~ ^ : " { } [ ]
    // By wrapping each term in double quotes and removing all special chars
    // from the term body, we prevent query injection while preserving search
    // relevance for typical identifiers and paths.
    let terms: Vec<String> = query
        .split_whitespace()
        .filter_map(|t| {
            // Strip FTS5 special characters that would break out of quoted strings
            // or alter the query syntax. We keep only alphanumeric, underscore,
            // hyphen, dot, and forward-slash — sufficient for code identifiers,
            // file paths, and error message fragments.
            let cleaned: String = t
                .chars()
                .filter(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
                .collect();
            if cleaned.len() < 2 {
                return None;
            }
            // Wrap in double quotes so that any remaining safe characters
            // are treated as literal text by FTS5.
            Some(format!("\"{}\"", cleaned))
        })
        .collect();
    if terms.is_empty() {
        // Return a match-nothing expression rather than an empty query
        // which would match everything.
        return "\"__NO_MATCH__\"".to_string();
    }
    terms.join(" AND ")
}

// ── Row deserialization helpers ───────────────────────────────────

fn run_from_row(row: &rusqlite::Row) -> rusqlite::Result<Run> {
    let command_json: String = row.get(2)?;
    let tags_json: String = row.get(5)?;
    let status_json: String = row.get(7)?;
    let started_at_str: String = row.get(8)?;
    let ended_at_str: Option<String> = row.get(9)?;

    Ok(Run {
        id: row.get(0)?,
        name: row.get(1)?,
        command: serde_json::from_str(&command_json).unwrap_or_default(),
        cwd: row.get(3)?,
        project_dir: row.get(4)?,
        tags: serde_json::from_str(&tags_json).unwrap_or_default(),
        notes: row.get(6)?,
        status: serde_json::from_str(&status_json).unwrap_or(crate::core::run::RunStatus::Unknown),
        started_at: chrono::DateTime::parse_from_rfc3339(&started_at_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|e| {
                tracing::warn!(
                    "corrupt started_at for run {}: {e}",
                    row.get::<_, String>(0).unwrap_or_default()
                );
                rusqlite::Error::InvalidParameterName(format!(
                    "corrupt timestamp: {started_at_str}: {e}"
                ))
            })?,
        ended_at: ended_at_str.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        }),
        exit_code: row.get(10)?,
        parent_run_id: row.get(11)?,
        next_sequence: row.get::<_, i64>(12)? as u64,
        duration_ms: row.get::<_, Option<i64>>(13)?.map(|v| v.max(0) as u64),
        adapter: row.get(14)?,
        session_id: row.get(15)?,
        input_tokens: row.get::<_, Option<i64>>(16)?.map(|v| v.max(0) as u64),
        output_tokens: row.get::<_, Option<i64>>(17)?.map(|v| v.max(0) as u64),
        total_tokens: row.get::<_, Option<i64>>(18)?.map(|v| v.max(0) as u64),
        estimated_cost_usd: row.get(19)?,
        model: row.get(20)?,
    })
}

fn event_from_row(row: &rusqlite::Row) -> rusqlite::Result<TraceEvent> {
    let source_json: String = row.get(4)?;
    let status_json: String = row.get(9)?;
    let side_effect_json: String = row.get(10)?;
    let started_at_str: String = row.get(6)?;
    let ended_at_str: Option<String> = row.get(7)?;
    let metadata_json: String = row.get(14)?;

    Ok(TraceEvent {
        id: row.get(0)?,
        run_id: row.get(1)?,
        parent_event_id: row.get(2)?,
        sequence: row.get::<_, i64>(3)? as u64,
        source: serde_json::from_str(&source_json)
            .unwrap_or(crate::core::event::EventSource::System),
        kind: row.get(5)?,
        started_at: chrono::DateTime::parse_from_rfc3339(&started_at_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|e| {
                tracing::warn!(
                    "corrupt started_at for event {}: {e}",
                    row.get::<_, String>(0).unwrap_or_default()
                );
                rusqlite::Error::InvalidParameterName(format!(
                    "corrupt timestamp: {started_at_str}: {e}"
                ))
            })?,
        ended_at: ended_at_str.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        }),
        duration_ms: row.get::<_, Option<i64>>(8)?.map(|d| {
            if d < 0 {
                // Negative duration indicates clock skew or data corruption;
                // clamp to zero rather than wrapping to u64::MAX.
                tracing::warn!(
                    "negative duration_ms {} for event {}, clamped to 0",
                    d,
                    row.get::<_, String>(0).unwrap_or_default()
                );
                0u64
            } else {
                d as u64
            }
        }),
        status: serde_json::from_str(&status_json)
            .unwrap_or(crate::core::event::EventStatus::Unknown),
        side_effect: serde_json::from_str(&side_effect_json)
            .unwrap_or(crate::core::event::SideEffect::Unknown),
        input_blob: row.get(11)?,
        output_blob: row.get(12)?,
        error_blob: row.get(13)?,
        metadata: serde_json::from_str(&metadata_json).unwrap_or_default(),
    })
}

fn checkpoint_from_row(row: &rusqlite::Row) -> rusqlite::Result<Checkpoint> {
    let created_at_str: String = row.get(10)?;

    Ok(Checkpoint {
        id: row.get(0)?,
        run_id: row.get(1)?,
        event_id: row.get(2)?,
        git_commit: row.get(3)?,
        git_diff_blob: row.get(4)?,
        filesystem_manifest_blob: row.get(5)?,
        cwd: row.get(6)?,
        environment_blob: row.get(7)?,
        transcript_blob: row.get(8)?,
        harness_session_id: row.get(9)?,
        created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|e| {
                tracing::warn!(
                    "corrupt created_at for checkpoint {}: {e}",
                    row.get::<_, String>(0).unwrap_or_default()
                );
                rusqlite::Error::InvalidParameterName(format!(
                    "corrupt timestamp: {created_at_str}: {e}"
                ))
            })?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, EventStatus};
    use crate::core::run::RunStatus;
    use std::sync::Arc;

    #[tokio::test]
    async fn store_and_load_run() {
        let store = SqliteStore::open_memory().unwrap();
        let run = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let loaded = store.get_run(&run.id).await.unwrap().unwrap();
        assert_eq!(loaded.id, run.id);
        assert_eq!(loaded.command, run.command);
    }

    #[tokio::test]
    async fn store_blob_on_disk() {
        let store = SqliteStore::open_memory().unwrap();
        let data = b"hello blob content";
        let reference = store.store_blob(data).await.unwrap();
        assert!(!reference.key.is_empty());
        let loaded = store.load_blob(&reference).await.unwrap();
        assert_eq!(loaded, data);
        // Dedup: second store returns same key
        let reference2 = store.store_blob(data).await.unwrap();
        assert_eq!(reference.key, reference2.key);
    }

    #[tokio::test]
    async fn encrypted_blob_roundtrip_and_disk_format() {
        let crypto = crate::crypto::BlobCrypto::from_key_bytes([9u8; 32]);
        let store = SqliteStore::open_memory()
            .unwrap()
            .with_blob_crypto(Some(crypto));
        assert!(store.blob_encryption_enabled());
        let data = b"sk-abcdefghijklmnopqrstuvwxyz012345 secret";
        let reference = store.store_blob(data).await.unwrap();
        // On-disk file must not be raw plaintext
        let disk = std::fs::read(store.blob_dir().join(&reference.key)).unwrap();
        assert!(crate::crypto::is_encrypted_blob(&disk));
        assert!(!disk.windows(data.len()).any(|w| w == data));
        let loaded = store.load_blob(&reference).await.unwrap();
        assert_eq!(loaded, data);
        // Content key is over plaintext
        assert_eq!(reference.key, crate::crypto::content_key(data));
    }

    #[tokio::test]
    async fn insert_event_and_checkpoint() {
        let store = SqliteStore::open_memory().unwrap();
        let mut run = Run::new(vec!["true".into()], "/tmp".into());
        run.status = RunStatus::Running;
        store.insert_run(&run).await.unwrap();

        let mut ev = TraceEvent::new(&run.id, EventSource::System, "test.event");
        ev.status = EventStatus::Success;
        store.insert_event(&ev).await.unwrap();

        let events = store.get_events(&run.id).await.unwrap();
        assert_eq!(events.len(), 1);

        let cp = Checkpoint::new(&run.id, &ev.id, &run.cwd);
        store.insert_checkpoint(&cp).await.unwrap();
        let cps = store.get_checkpoints(&run.id).await.unwrap();
        assert_eq!(cps.len(), 1);
    }

    #[tokio::test]
    async fn delete_run_cascades() {
        let store = SqliteStore::open_memory().unwrap();
        let run = Run::new(vec!["true".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let mut ev = TraceEvent::new(&run.id, EventSource::System, "test.event");
        ev.status = EventStatus::Success;
        store.insert_event(&ev).await.unwrap();
        store
            .insert_checkpoint(&Checkpoint::new(&run.id, &ev.id, &run.cwd))
            .await
            .unwrap();

        assert!(store.delete_run(&run.id).await.unwrap());
        assert!(store.get_run(&run.id).await.unwrap().is_none());
        assert!(store.get_events(&run.id).await.unwrap().is_empty());
        assert!(store.get_checkpoints(&run.id).await.unwrap().is_empty());
        assert!(!store.delete_run(&run.id).await.unwrap());
    }

    #[tokio::test]
    async fn fts_finds_tool_name() {
        let store = SqliteStore::open_memory().unwrap();
        let run = Run::new(vec!["x".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let mut ev = TraceEvent::new(&run.id, EventSource::Tool, "tool.call");
        ev.status = EventStatus::Running;
        ev.metadata
            .insert("tool_name".into(), serde_json::json!("WebSearch"));
        store.insert_event(&ev).await.unwrap();
        let hits = store.fts_event_ids("WebSearch", 10).await.unwrap().unwrap();
        assert!(!hits.is_empty());
        assert_eq!(hits[0].0, ev.id);
    }

    #[test]
    fn parking_lot_mutex_no_poisoning() {
        // With parking_lot, mutex lock() returns the guard directly —
        // no poisoning, no Result to unwrap.
        let store = SqliteStore::open_memory().unwrap();
        let guard = store.lock();
        // The guard dereferences to a Connection
        let _ = guard.execute_batch("SELECT 1;");
        drop(guard);
        // Lock is usable again after drop
        let guard2 = store.lock();
        let _ = guard2.execute_batch("SELECT 1;");
    }

    #[test]
    fn transactional_migrate_rollback_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let blob_dir = dir.path().join("blobs");
        std::fs::create_dir_all(&blob_dir).unwrap();

        // Open once to run migrations through v3
        {
            let _store = SqliteStore::open_with_blobs(&db_path, &blob_dir).unwrap();
        }

        // Verify schema_version has all 3 versions recorded
        let conn = Connection::open(&db_path).unwrap();
        let count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_version WHERE version IN (1,2,3)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3, "all 3 migration versions should be recorded");

        // Re-opening should be a no-op (already at current version)
        let store = SqliteStore::open_with_blobs(&db_path, &blob_dir).unwrap();
        let run = Run::new(vec!["echo".into()], "/tmp".into());
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(store.insert_run(&run))
            .unwrap();
        drop(store);

        // Still exactly 3 versions — no extra rows from re-open
        let count2: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_version WHERE version IN (1,2,3)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count2, 3);
    }

    #[test]
    fn delete_run_is_transactional() {
        let store = SqliteStore::open_memory().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let run = Run::new(vec!["true".into()], "/tmp".into());
        rt.block_on(store.insert_run(&run)).unwrap();

        let mut ev = TraceEvent::new(&run.id, EventSource::System, "test.event");
        ev.status = EventStatus::Success;
        rt.block_on(store.insert_event(&ev)).unwrap();

        let cp = Checkpoint::new(&run.id, &ev.id, &run.cwd);
        rt.block_on(store.insert_checkpoint(&cp)).unwrap();

        // delete_run should remove everything atomically
        assert!(rt.block_on(store.delete_run(&run.id)).unwrap());
        assert!(rt.block_on(store.get_run(&run.id)).unwrap().is_none());
        assert!(rt.block_on(store.get_events(&run.id)).unwrap().is_empty());
        assert!(rt
            .block_on(store.get_checkpoints(&run.id))
            .unwrap()
            .is_empty());
    }
    #[test]
    fn test_migrate_v2_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("v1test.db");
        let blob_dir = dir.path().join("blobs");
        std::fs::create_dir_all(&blob_dir).unwrap();
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (1);
                 CREATE TABLE runs (id TEXT PRIMARY KEY, name TEXT, command TEXT NOT NULL, cwd TEXT NOT NULL, project_dir TEXT NOT NULL, tags TEXT NOT NULL DEFAULT '[]', notes TEXT, status TEXT NOT NULL DEFAULT 'Pending', started_at TEXT NOT NULL, ended_at TEXT, exit_code INTEGER, parent_run_id TEXT, next_sequence INTEGER NOT NULL DEFAULT 0);
                 CREATE TABLE events (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, parent_event_id TEXT, sequence INTEGER NOT NULL DEFAULT 0, source TEXT NOT NULL, kind TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT, duration_ms INTEGER, status TEXT NOT NULL DEFAULT 'Pending', side_effect TEXT NOT NULL DEFAULT 'Unknown', input_blob TEXT, output_blob TEXT, error_blob TEXT, metadata TEXT NOT NULL DEFAULT '{}');
                 CREATE TABLE checkpoints (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, event_id TEXT NOT NULL, git_commit TEXT, git_diff_blob TEXT, filesystem_manifest_blob TEXT, cwd TEXT NOT NULL, environment_blob TEXT, transcript_blob TEXT, harness_session_id TEXT, created_at TEXT NOT NULL);
                 CREATE TABLE blobs (key TEXT PRIMARY KEY, data BLOB NOT NULL, size INTEGER NOT NULL, compressed INTEGER NOT NULL DEFAULT 0, content_type TEXT);",
            ).unwrap();
            conn.execute(
                "INSERT INTO blobs (key, data, size, compressed) VALUES (?1, ?2, ?3, 0)",
                rusqlite::params![
                    "test-blob-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    b"blob-payload-data",
                    16i64
                ],
            )
            .unwrap();
        }
        let _store = SqliteStore::open_with_blobs(&db_path, &blob_dir).unwrap();
        let extracted = blob_dir.join("test-blob-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(
            extracted.exists(),
            "v2 migration should extract blobs to disk"
        );
        assert_eq!(std::fs::read(&extracted).unwrap(), b"blob-payload-data");
    }

    #[test]
    fn test_recover_stale_runs() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("stale.db");
        let blob_dir = dir.path().join("blobs");
        std::fs::create_dir_all(&blob_dir).unwrap();
        let run_id = "stale-run-001";
        {
            let store = SqliteStore::open_with_blobs(&db_path, &blob_dir).unwrap();
            let mut run = Run::new(vec!["long".into(), "command".into()], "/tmp".into());
            run.id = run_id.to_string();
            run.status = RunStatus::Running;
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(store.insert_run(&run)).unwrap();
        }
        let store = SqliteStore::open_with_blobs(&db_path, &blob_dir).unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let loaded = rt.block_on(store.get_run(run_id)).unwrap().unwrap();
        assert_eq!(
            loaded.status,
            RunStatus::Failed,
            "Running run should be recovered to Failed on re-open"
        );
        assert!(
            loaded.ended_at.is_some(),
            "recovered run should have ended_at set"
        );
        let notes = loaded.notes.unwrap_or_default();
        assert!(
            notes.contains("interrupted") || notes.contains("recovered"),
            "recovery notes missing: {notes}"
        );
    }

    #[tokio::test]
    async fn test_concurrent_insert() {
        let store = Arc::new(SqliteStore::open_memory().unwrap());
        let mut handles = Vec::new();
        for i in 0..50 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                let mut run = Run::new(vec![format!("cmd-{i}"), "arg".into()], "/tmp".into());
                run.status = RunStatus::Succeeded;
                run.exit_code = Some(0);
                store.insert_run(&run).await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let runs = store.list_runs().await.unwrap();
        assert_eq!(
            runs.len(),
            50,
            "all 50 concurrent inserts should be persisted"
        );
    }
}
