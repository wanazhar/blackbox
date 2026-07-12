use std::path::Path;

use anyhow::Context;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use tokio::task;

use crate::core::blob::BlobReference;
use crate::core::checkpoint::Checkpoint;
use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::storage::TraceStore;

/// SQLite-backed trace store with content-addressed blob storage.
///
/// All rusqlite operations run on a dedicated blocking thread via
/// `tokio::task::spawn_blocking` to avoid holding the async runtime.
pub struct SqliteStore {
    db_path: String,
}

impl SqliteStore {
    /// Open or create a SQLite database at the given path.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_string_lossy().to_string();
        let conn = Connection::open(&path).context("failed to open SQLite database")?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .context("failed to set pragmas")?;

        let store = Self { db_path: path };
        store.migrate(&conn)?;
        Ok(store)
    }

    /// Open an in-memory SQLite database (for testing).
    pub fn open_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory SQLite")?;

        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .context("failed to set pragmas")?;

        let store = Self {
            db_path: ":memory:".to_string(),
        };
        store.migrate(&conn)?;
        Ok(store)
    }

    fn migrate(&self, conn: &Connection) -> anyhow::Result<()> {
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
                run_id          TEXT NOT NULL REFERENCES runs(id),
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
            CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);

            CREATE TABLE IF NOT EXISTS checkpoints (
                id                          TEXT PRIMARY KEY,
                run_id                      TEXT NOT NULL REFERENCES runs(id),
                event_id                    TEXT NOT NULL,
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

            CREATE TABLE IF NOT EXISTS blobs (
                key             TEXT PRIMARY KEY,
                data            BLOB NOT NULL,
                size            INTEGER NOT NULL,
                compressed      INTEGER NOT NULL DEFAULT 0,
                content_type    TEXT
            );
            ",
        )
        .context("failed to create tables")?;

        Ok(())
    }

    fn get_conn(&self) -> anyhow::Result<Connection> {
        Connection::open(&self.db_path).context("failed to open SQLite connection")
    }
}

#[async_trait::async_trait]
impl TraceStore for SqliteStore {
    async fn insert_run(&self, run: &Run) -> anyhow::Result<()> {
        let conn = self.get_conn()?;
        let run = run.clone();
        task::spawn_blocking(move || -> anyhow::Result<()> {
            conn.execute(
                "INSERT INTO runs (id, name, command, cwd, project_dir, tags, notes, status, started_at, ended_at, exit_code, parent_run_id, next_sequence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    run.id,
                    run.name,
                    serde_json::to_string(&run.command).unwrap_or_default(),
                    run.cwd,
                    run.project_dir,
                    serde_json::to_string(&run.tags).unwrap_or_default(),
                    run.notes,
                    serde_json::to_string(&run.status).unwrap_or_default(),
                    run.started_at.to_rfc3339(),
                    run.ended_at.map(|t| t.to_rfc3339()),
                    run.exit_code,
                    run.parent_run_id,
                    run.next_sequence as i64,
                ],
            )
            .context("failed to insert run")?;
            Ok(())
        })
        .await?
    }

    async fn update_run(&self, run: &Run) -> anyhow::Result<()> {
        let conn = self.get_conn()?;
        let run = run.clone();
        task::spawn_blocking(move || -> anyhow::Result<()> {
            conn.execute(
                "UPDATE runs SET name=?2, command=?3, cwd=?4, project_dir=?5, tags=?6, notes=?7, status=?8, started_at=?9, ended_at=?10, exit_code=?11, parent_run_id=?12, next_sequence=?13
                 WHERE id=?1",
                params![
                    run.id,
                    run.name,
                    serde_json::to_string(&run.command).unwrap_or_default(),
                    run.cwd,
                    run.project_dir,
                    serde_json::to_string(&run.tags).unwrap_or_default(),
                    run.notes,
                    serde_json::to_string(&run.status).unwrap_or_default(),
                    run.started_at.to_rfc3339(),
                    run.ended_at.map(|t| t.to_rfc3339()),
                    run.exit_code,
                    run.parent_run_id,
                    run.next_sequence as i64,
                ],
            )
            .context("failed to update run")?;
            Ok(())
        })
        .await?
    }

    async fn get_run(&self, run_id: &str) -> anyhow::Result<Option<Run>> {
        let conn = self.get_conn()?;
        let run_id = run_id.to_string();
        task::spawn_blocking(move || -> anyhow::Result<Option<Run>> {
            let mut stmt = conn.prepare(
                "SELECT id, name, command, cwd, project_dir, tags, notes, status, started_at, ended_at, exit_code, parent_run_id, next_sequence
                 FROM runs WHERE id = ?1",
            )?;

            let result = stmt.query_row(params![run_id], |row| run_from_row(row));

            match result {
                Ok(run) => Ok(Some(run)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
        .await?
    }

    async fn list_runs(&self) -> anyhow::Result<Vec<Run>> {
        let conn = self.get_conn()?;
        task::spawn_blocking(move || -> anyhow::Result<Vec<Run>> {
            let mut stmt = conn.prepare(
                "SELECT id, name, command, cwd, project_dir, tags, notes, status, started_at, ended_at, exit_code, parent_run_id, next_sequence
                 FROM runs ORDER BY started_at DESC",
            )?;

            let runs = stmt
                .query_map([], |row| run_from_row(row))?
                .collect::<Result<Vec<_>, _>>()?;

            Ok(runs)
        })
        .await?
    }

    async fn insert_event(&self, event: &TraceEvent) -> anyhow::Result<()> {
        let conn = self.get_conn()?;
        let event = event.clone();
        task::spawn_blocking(move || -> anyhow::Result<()> {
            conn.execute(
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
            Ok(())
        })
        .await?
    }

    async fn get_events(&self, run_id: &str) -> anyhow::Result<Vec<TraceEvent>> {
        let conn = self.get_conn()?;
        let run_id = run_id.to_string();
        task::spawn_blocking(move || -> anyhow::Result<Vec<TraceEvent>> {
            let mut stmt = conn.prepare(
                "SELECT id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata
                 FROM events WHERE run_id = ?1 ORDER BY sequence",
            )?;

            let events = stmt
                .query_map(params![run_id], |row| event_from_row(row))?
                .collect::<Result<Vec<_>, _>>()?;

            Ok(events)
        })
        .await?
    }

    async fn get_event(&self, event_id: &str) -> anyhow::Result<Option<TraceEvent>> {
        let conn = self.get_conn()?;
        let event_id = event_id.to_string();
        task::spawn_blocking(move || -> anyhow::Result<Option<TraceEvent>> {
            let mut stmt = conn.prepare(
                "SELECT id, run_id, parent_event_id, sequence, source, kind, started_at, ended_at, duration_ms, status, side_effect, input_blob, output_blob, error_blob, metadata
                 FROM events WHERE id = ?1",
            )?;

            let result = stmt.query_row(params![event_id], |row| event_from_row(row));

            match result {
                Ok(ev) => Ok(Some(ev)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
        .await?
    }

    async fn insert_checkpoint(&self, cp: &Checkpoint) -> anyhow::Result<()> {
        let conn = self.get_conn()?;
        let cp = cp.clone();
        task::spawn_blocking(move || -> anyhow::Result<()> {
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
            Ok(())
        })
        .await?
    }

    async fn get_checkpoints(&self, run_id: &str) -> anyhow::Result<Vec<Checkpoint>> {
        let conn = self.get_conn()?;
        let run_id = run_id.to_string();
        task::spawn_blocking(move || -> anyhow::Result<Vec<Checkpoint>> {
            let mut stmt = conn.prepare(
                "SELECT id, run_id, event_id, git_commit, git_diff_blob, filesystem_manifest_blob, cwd, environment_blob, transcript_blob, harness_session_id, created_at
                 FROM checkpoints WHERE run_id = ?1",
            )?;

            let checkpoints = stmt
                .query_map(params![run_id], |row| checkpoint_from_row(row))?
                .collect::<Result<Vec<_>, _>>()?;

            Ok(checkpoints)
        })
        .await?
    }

    async fn store_blob(&self, data: &[u8]) -> anyhow::Result<BlobReference> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let key = hex::encode(hasher.finalize());
        let size = data.len() as u64;
        let data = data.to_vec();
        let key_clone = key.clone();

        let conn = self.get_conn()?;
        task::spawn_blocking(move || -> anyhow::Result<()> {
            conn.execute(
                "INSERT OR IGNORE INTO blobs (key, data, size, compressed, content_type)
                 VALUES (?1, ?2, ?3, 0, NULL)",
                params![key_clone, data, size as i64],
            )
            .context("failed to store blob")?;
            Ok(())
        })
        .await??;

        Ok(BlobReference::new(key, size))
    }

    async fn load_blob(&self, reference: &BlobReference) -> anyhow::Result<Vec<u8>> {
        let conn = self.get_conn()?;
        let key = reference.key.clone();
        task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            let result: Vec<u8> = conn.query_row(
                "SELECT data FROM blobs WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )?;

            Ok(result)
        })
        .await?
        .map_err(|e| anyhow::anyhow!("blob not found: {}", e))
    }
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
            .unwrap_or_else(|_| chrono::Utc::now()),
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
        source: serde_json::from_str(&source_json).unwrap_or(crate::core::event::EventSource::System),
        kind: row.get(5)?,
        started_at: chrono::DateTime::parse_from_rfc3339(&started_at_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now()),
        ended_at: ended_at_str.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
        }),
        duration_ms: row.get::<_, Option<i64>>(8)?.map(|d| d as u64),
        status: serde_json::from_str(&status_json).unwrap_or(crate::core::event::EventStatus::Unknown),
        side_effect: serde_json::from_str(&side_effect_json).unwrap_or(crate::core::event::SideEffect::Unknown),
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
            .unwrap_or_else(|_| chrono::Utc::now()),
    })
}
