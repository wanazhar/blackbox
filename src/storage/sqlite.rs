use std::sync::LazyLock;
use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;

use std::path::{Path, PathBuf};
use parking_lot::Mutex;

use anyhow::Context;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use tokio::task;

use crate::core::blob::BlobReference;
use crate::core::checkpoint::Checkpoint;
use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::storage::TraceStore;

/// Current schema version. Bump when migrations change.
const SCHEMA_VERSION: i32 = 3;

/// Default scanner for redacting secrets in FTS index content.
static FTS_SCANNER: LazyLock<SecretScanner> =
    LazyLock::new(|| SecretScanner::new(RedactionConfig::default()));


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
    pub fn open_with_blobs(db_path: impl AsRef<Path>, blob_dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        let blob_dir = blob_dir.as_ref().to_path_buf();

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).context("failed to create database directory")?;
        }
        std::fs::create_dir_all(&blob_dir).context("failed to create blob directory")?;

        let conn = Connection::open(&db_path).context("failed to open SQLite database")?;

        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             PRAGMA busy_timeout=5000;",
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
        };
        store.migrate()?;
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

    /// Mark abandoned `Running` runs as `Failed`.
    ///
    /// Called on open so a killed supervisor does not leave ghost sessions.
    fn recover_stale_runs(&self) -> anyhow::Result<()> {
        let conn = self.lock();
        let now = chrono::Utc::now().to_rfc3339();
        let n = conn.execute(
            "UPDATE runs
             SET status = ?1,
                 ended_at = COALESCE(ended_at, ?2),
                 notes = CASE
                     WHEN notes IS NULL OR notes = '' THEN 'recovered: process exited while status=Running'
                     WHEN notes LIKE '%recovered:%' THEN notes
                     ELSE notes || '; recovered: process exited while status=Running'
                 END
             WHERE status = ?3",
            params![
                serde_json::to_string(&crate::core::run::RunStatus::Failed).unwrap_or_else(|_| "\"Failed\"".into()),
                now,
                serde_json::to_string(&crate::core::run::RunStatus::Running).unwrap_or_else(|_| "\"Running\"".into()),
            ],
        )?;
        if n > 0 {
            tracing::warn!(count = n, "recovered abandoned Running runs");
        }
        Ok(())
    }

    /// Open an in-memory SQLite database (for testing).
    pub fn open_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory SQLite")?;

        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;")
            .context("failed to set pragmas")?;

        let blob_dir = std::env::temp_dir().join(format!(
            "blackbox-test-blobs-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&blob_dir).context("failed to create test blob directory")?;

        let store = Self {
            conn: Mutex::new(conn),
            blob_dir,
            db_path: PathBuf::from(":memory:"),
        };
        store.migrate()?;
        Ok(store)
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
            let tx = conn.unchecked_transaction()
                .context("failed to start transaction for v1 migration")?;
            Self::migrate_v1(&tx)?;
            tx.execute("INSERT INTO schema_version (version) VALUES (1)", [])
                .context("failed to record v1 version")?;
            tx.commit().context("failed to commit v1 migration")?;
        }

        if current < 2 {
            let tx = conn.unchecked_transaction()
                .context("failed to start transaction for v2 migration")?;
            Self::migrate_v2(&tx, &self.blob_dir)?;
            tx.execute("INSERT INTO schema_version (version) VALUES (2)", [])
                .context("failed to record v2 version")?;
            tx.commit().context("failed to commit v2 migration")?;
        }

        if current < 3 {
            let tx = conn.unchecked_transaction()
                .context("failed to start transaction for v3 migration")?;
            Self::migrate_v3(&tx)?;
            tx.execute("INSERT INTO schema_version (version) VALUES (3)", [])
                .context("failed to record v3 version")?;
            tx.commit().context("failed to commit v3 migration")?;
        }
        if current < 4 {
            let tx = conn.unchecked_transaction()
                .context("failed to start transaction for v4 migration")?;
            Self::migrate_v4(&tx)?;
            tx.execute("INSERT INTO schema_version (version) VALUES (4)", [])
                .context("failed to record v4 version")?;
            tx.commit().context("failed to commit v4 migration")?;
        }

        // Ensure we never claim a higher version than we support
        let _ = SCHEMA_VERSION;

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
            let tags_json =
                serde_json::to_string(&run.tags).context("failed to serialize tags")?;
            let status_json =
                serde_json::to_string(&run.status).context("failed to serialize status")?;
            conn.execute(
                "INSERT INTO runs (id, name, command, cwd, project_dir, tags, notes, status, started_at, ended_at, exit_code, parent_run_id, next_sequence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
            let tags_json =
                serde_json::to_string(&run.tags).context("failed to serialize tags")?;
            let status_json =
                serde_json::to_string(&run.status).context("failed to serialize status")?;
            conn.execute(
                "UPDATE runs SET name=?2, command=?3, cwd=?4, project_dir=?5, tags=?6, notes=?7, status=?8, started_at=?9, ended_at=?10, exit_code=?11, parent_run_id=?12, next_sequence=?13
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
                "SELECT id, name, command, cwd, project_dir, tags, notes, status, started_at, ended_at, exit_code, parent_run_id, next_sequence
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
                "SELECT id, name, command, cwd, project_dir, tags, notes, status, started_at, ended_at, exit_code, parent_run_id, next_sequence
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
            let tx = conn.unchecked_transaction()
                .context("failed to start transaction for delete_run")?;
            // FK order: events and checkpoints before runs
            if let Err(e) = tx.execute("DELETE FROM events_fts WHERE run_id = ?1", params![run_id]) {
                tracing::warn!(error = %e, run_id = %run_id, "FTS cleanup failed during delete_run; proceeding");
            }
            tx.execute("DELETE FROM events WHERE run_id = ?1", params![run_id])
                .context("failed to delete events")?;
            tx.execute(
                "DELETE FROM checkpoints WHERE run_id = ?1",
                params![run_id],
            )
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
        {
            let conn = self.lock();
            // Wrap event INSERT + FTS upsert in a single transaction for atomicity.
            let tx = conn.unchecked_transaction()
                .context("failed to start transaction for insert_event")?;
            tx.execute(
                "INSERT INTO events (id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    event.id,
                    event.run_id,
                    event.parent_event_id,
                    event.sequence as i64,
                    serde_json::to_string(&event.source).unwrap_or_default(),
                    event.kind,
                    event.started_at.to_rfc3339(),
                    event.ended_at.map(|t| t.to_rfc3339()),
                    event.duration_ms.map(|d| d as i64),
                    serde_json::to_string(&event.status).unwrap_or_default(),
                    serde_json::to_string(&event.side_effect).unwrap_or_default(),
                    event.input_blob,
                    event.output_blob,
                    event.error_blob,
                    serde_json::to_string(&event.metadata).unwrap_or_default(),
                ],
            )
            .context("failed to insert event")?;
            // FTS upsert within the same transaction (best-effort: table may be
            // missing on ancient DBs mid-migrate)
            let _ = fts_upsert_in_tx(&tx, &event);
            tx.commit().context("failed to commit insert_event transaction")?;
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
        {
            let conn = self.lock();
            // Wrap event UPDATE + FTS upsert in a single transaction for atomicity.
            let tx = conn.unchecked_transaction()
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
                    serde_json::to_string(&event.source).unwrap_or_default(),
                    event.kind,
                    event.started_at.to_rfc3339(),
                    event.ended_at.map(|t| t.to_rfc3339()),
                    event.duration_ms.map(|d| d as i64),
                    serde_json::to_string(&event.status).unwrap_or_default(),
                    serde_json::to_string(&event.side_effect).unwrap_or_default(),
                    event.input_blob,
                    event.output_blob,
                    event.error_blob,
                    serde_json::to_string(&event.metadata).unwrap_or_default(),
                ],
            )
            .context("failed to update event")?;
            if n == 0 {
                tx.rollback().ok();
                anyhow::bail!("event not found for update: {}", event.id);
            }
            // FTS upsert within the same transaction
            let _ = fts_upsert_in_tx(&tx, &event);
            tx.commit().context("failed to commit update_event transaction")?;
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
                Ok(iter) => Ok(Some(
                    iter.filter_map(|r| r.ok()).collect::<Vec<_>>(),
                )),
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
        let mut hasher = Sha256::new();
        hasher.update(data);
        let key = hex::encode(hasher.finalize());
        let size = data.len() as u64;

        // Write blob to disk (content-addressed: key IS the filename)
        // Write blob to disk using atomic write (write-to-temp + rename)
        // to prevent TOCTOU race conditions with concurrent writers
        let blob_path = self.blob_dir.join(&key);
        if !blob_path.exists() {
            let blob_dir = self.blob_dir.clone();
            let key_for_write = key.clone();
            let data_for_write = data.to_vec();
            task::spawn_blocking(move || -> anyhow::Result<()> {
                std::fs::create_dir_all(&blob_dir).context("failed to create blob directory")?;
                let target = blob_dir.join(&key_for_write);
                // Use atomic write: write to temp file, then rename
                let temp = target.with_extension("tmp");
                std::fs::write(&temp, &data_for_write)
                    .context("failed to write blob temp file")?;
                // rename is atomic on the same filesystem
                std::fs::rename(&temp, &target)
                    .context("failed to rename blob temp file")?;
                Ok(())
            })
            .await??;
        }

        // Insert metadata into SQLite (no data column — data lives on disk)
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
        task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            let path = blob_dir.join(&key);
            let data = std::fs::read(&path)
                .with_context(|| format!("blob not found: {}", path.display()))?;
            // Verify integrity: SHA-256 of the data must match the
            // content-addressed key. A mismatch indicates corruption or
            // tampering on disk.
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let computed = hex::encode(hasher.finalize());
            if computed != key {
                anyhow::bail!(
                    "blob integrity mismatch: expected key {} but computed SHA-256 {}",
                    key,
                    computed
                );
            }
            Ok(data)
        })
        .await?
    }

    async fn move_blob(
        &self,
        from_key: &str,
        to_key: &str,
    ) -> anyhow::Result<()> {
        // Move the file on disk
        {
            let blob_dir = self.blob_dir.clone();
            let fk = from_key.to_string();
            let tk = to_key.to_string();
            task::spawn_blocking(move || -> anyhow::Result<()> {
                let from = blob_dir.join(&fk);
                let to = blob_dir.join(&tk);
                if from.exists() && !to.exists() {
                    std::fs::rename(&from, &to)
                        .context("failed to rename blob file")?;
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
            let tx = conn.unchecked_transaction()
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
            tx.commit().context("failed to commit move_blob transaction")?;
        }
        Ok(())
    }
    async fn insert_events_batch(&self, events: &[TraceEvent]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let events: Vec<TraceEvent> = events.to_vec();
        {
            let conn = self.lock();
            let tx = conn.unchecked_transaction()
                .context("failed to start transaction for insert_events_batch")?;
            for event in &events {
                tx.execute(
                    "INSERT INTO events (id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    params![
                        event.id,
                        event.run_id,
                        event.parent_event_id,
                        event.sequence as i64,
                        serde_json::to_string(&event.source).unwrap_or_default(),
                        event.kind,
                        event.started_at.to_rfc3339(),
                        event.ended_at.map(|t| t.to_rfc3339()),
                        event.duration_ms.map(|d| d as i64),
                        serde_json::to_string(&event.status).unwrap_or_default(),
                        serde_json::to_string(&event.side_effect).unwrap_or_default(),
                        event.input_blob,
                        event.output_blob,
                        event.error_blob,
                        serde_json::to_string(&event.metadata).unwrap_or_default(),
                    ],
                )
                .context("failed to insert event in batch")?;
                let _ = fts_upsert_in_tx(&tx, event);
            }
            tx.commit().context("failed to commit insert_events_batch transaction")?;
        }
        tokio::task::yield_now().await;
        Ok(())
    }
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
    let tx = conn.unchecked_transaction()
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
            serde_json::to_string(&event.source).unwrap_or_default(),
            serde_json::to_string(&event.status).unwrap_or_default(),
            event_search_body(event),
        ],
    )
    .context("failed to upsert events_fts")?;
    tx.commit().context("failed to commit FTS upsert")?;
    Ok(())
}

/// FTS upsert that operates within an existing transaction (no inner txn).
fn fts_upsert_in_tx(tx: &rusqlite::Transaction, event: &TraceEvent) -> anyhow::Result<()> {
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
            serde_json::to_string(&event.source).unwrap_or_default(),
            serde_json::to_string(&event.status).unwrap_or_default(),
            event_search_body(event),
        ],
    )
    .context("failed to upsert events_fts")?;
    Ok(())
}

/// Build an FTS5 MATCH query: all alphanumeric terms AND-ed.
fn build_fts_match(query: &str) -> String {
    let terms: Vec<String> = query
        .split_whitespace()
        .filter_map(|t| {
            let cleaned: String = t
                .chars()
                .filter(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
                .collect();
            if cleaned.len() < 2 {
                None
            } else {
                // Quote tokens so punctuation-safe
                Some(format!("\"{}\"", cleaned.replace('"', "")))
            }
        })
        .collect();
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
                tracing::warn!("corrupt started_at for run {}: {e}", row.get::<_, String>(0).unwrap_or_default());
                rusqlite::Error::InvalidParameterName(format!("corrupt timestamp: {started_at_str}: {e}"))
            })?,
        ended_at: ended_at_str.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        }),
        exit_code: row.get(10)?,
        parent_run_id: row.get(11)?,
        next_sequence: row.get::<_, i64>(12)? as u64,
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
                tracing::warn!("corrupt started_at for event {}: {e}", row.get::<_, String>(0).unwrap_or_default());
                rusqlite::Error::InvalidParameterName(format!("corrupt timestamp: {started_at_str}: {e}"))
            })?,
        ended_at: ended_at_str.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        }),
        duration_ms: row.get::<_, Option<i64>>(8)?.map(|d| d as u64),
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
                tracing::warn!("corrupt created_at for checkpoint {}: {e}", row.get::<_, String>(0).unwrap_or_default());
                rusqlite::Error::InvalidParameterName(format!("corrupt timestamp: {created_at_str}: {e}"))
            })?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::core::event::{EventSource, EventStatus};
    use crate::core::run::RunStatus;

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
            let _store =
                SqliteStore::open_with_blobs(&db_path, &blob_dir).unwrap();
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
        let store =
            SqliteStore::open_with_blobs(&db_path, &blob_dir).unwrap();
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

        let mut ev =
            TraceEvent::new(&run.id, EventSource::System, "test.event");
        ev.status = EventStatus::Success;
        rt.block_on(store.insert_event(&ev)).unwrap();

        let cp = Checkpoint::new(&run.id, &ev.id, &run.cwd);
        rt.block_on(store.insert_checkpoint(&cp)).unwrap();

        // delete_run should remove everything atomically
        assert!(rt.block_on(store.delete_run(&run.id)).unwrap());
        assert!(rt.block_on(store.get_run(&run.id)).unwrap().is_none());
        assert!(rt.block_on(store.get_events(&run.id)).unwrap().is_empty());
        assert!(
            rt.block_on(store.get_checkpoints(&run.id))
                .unwrap()
                .is_empty()
        );
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
                rusqlite::params!["test-blob-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", b"blob-payload-data", 16i64],
            ).unwrap();
        }
        let _store = SqliteStore::open_with_blobs(&db_path, &blob_dir).unwrap();
        let extracted = blob_dir.join("test-blob-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(extracted.exists(), "v2 migration should extract blobs to disk");
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
        assert_eq!(loaded.status, RunStatus::Failed, "Running run should be recovered to Failed on re-open");
        assert!(loaded.ended_at.is_some(), "recovered run should have ended_at set");
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
        for h in handles { h.await.unwrap(); }
        let runs = store.list_runs().await.unwrap();
        assert_eq!(runs.len(), 50, "all 50 concurrent inserts should be persisted");
    }
}
