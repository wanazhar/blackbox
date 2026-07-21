//! Append-only durable event spool with CRC and idempotent batch IDs.
//!
//! Layout under `.blackbox/spool/`:
//! - `pending/<batch_id>.spool` — acknowledged by producer, not yet in SQLite
//! - `acked/` — compacted after successful SQLite commit
//!
//! Record format (binary):
//! ```text
//! magic "BBSP" (4)
//! version u32 LE (4)
//! batch_id utf8 len u32 LE + bytes
//! event_count u32 LE
//! for each event: json_len u32 LE + json bytes
//! crc32 of payload after header magic+version (4)
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::event::TraceEvent;

/// `SPOOL_VERSION` constant.
pub const SPOOL_VERSION: u32 = 1;
const MAGIC: &[u8; 4] = b"BBSP";

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `SpoolBatch` value.
pub struct SpoolBatch {
    /// Batch id.
    pub batch_id: String,
    /// Events.
    pub events: Vec<TraceEvent>,
    /// Creation timestamp.
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize)]
/// `SpoolAppendResult` value.
pub struct SpoolAppendResult {
    /// Batch id.
    pub batch_id: String,
    /// Filesystem path.
    pub path: PathBuf,
    /// Event count.
    pub event_count: usize,
    /// Bytes.
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
/// `SpoolHealth` value.
pub struct SpoolHealth {
    /// Pending batches.
    pub pending_batches: u64,
    /// Pending events.
    pub pending_events: u64,
    /// Pending bytes.
    pub pending_bytes: u64,
    /// Last append at.
    pub last_append_at: Option<String>,
    /// Last commit at.
    pub last_commit_at: Option<String>,
    /// Write failures.
    pub write_failures: u64,
    /// Replayed batches.
    pub replayed_batches: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
/// `SpoolInspectInfo` value.
pub struct SpoolInspectInfo {
    /// Pending batches.
    pub pending_batches: u64,
    /// Pending events.
    pub pending_events: u64,
    /// Bytes.
    pub bytes: u64,
    /// Torn records.
    pub torn_records: u64,
    /// Acked batches.
    pub acked_batches: u64,
}

/// File-backed durable spool.
pub struct EventSpool {
    root: PathBuf,
    pending_dir: PathBuf,
    acked_dir: PathBuf,
    health: parking_lot::Mutex<SpoolHealth>,
}

impl EventSpool {
    /// Open.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `open` — see module docs for full workflow.
    /// ```
    pub fn open(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let root = root.as_ref().to_path_buf();
        let pending_dir = root.join("pending");
        let acked_dir = root.join("acked");
        fs::create_dir_all(&pending_dir)?;
        fs::create_dir_all(&acked_dir)?;
        crate::privacy::restrict_dir(&root);
        crate::privacy::restrict_dir(&pending_dir);
        crate::privacy::restrict_dir(&acked_dir);
        Ok(Self {
            root,
            pending_dir,
            acked_dir,
            health: parking_lot::Mutex::new(SpoolHealth::default()),
        })
    }

    /// Root.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `root` — see module docs for full workflow.
    /// ```
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Health snapshot.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `health_snapshot` — see module docs for full workflow.
    /// ```
    pub fn health_snapshot(&self) -> SpoolHealth {
        let mut h = self.health.lock().clone();
        if let Ok(info) = inspect_spool(&self.root) {
            h.pending_batches = info.pending_batches;
            h.pending_events = info.pending_events;
            h.pending_bytes = info.bytes;
        }
        h
    }

    /// Append a batch to the spool. Producer acknowledgement is safe after return.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `append_batch` — see module docs for full workflow.
    /// ```
    pub fn append_batch(&self, events: &[TraceEvent]) -> anyhow::Result<SpoolAppendResult> {
        if events.is_empty() {
            anyhow::bail!("cannot append empty spool batch");
        }
        let batch_id = new_batch_id(events);
        let batch = SpoolBatch {
            batch_id: batch_id.clone(),
            events: events.to_vec(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let path = self.pending_dir.join(format!("{batch_id}.spool"));
        // Write to temp then rename for atomic visibility.
        let tmp = self.pending_dir.join(format!("{batch_id}.spool.tmp"));
        let bytes = encode_batch(&batch)?;
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        // Private file mode before rename (redacted events may still be sensitive).
        crate::privacy::restrict_file(&tmp);
        fs::rename(&tmp, &path)?;
        crate::privacy::restrict_file(&path);
        // fsync directory best-effort
        if let Ok(dir) = File::open(&self.pending_dir) {
            let _ = dir.sync_all();
        }
        let mut h = self.health.lock();
        h.last_append_at = Some(batch.created_at.clone());
        Ok(SpoolAppendResult {
            batch_id,
            path,
            event_count: events.len(),
            bytes: bytes.len() as u64,
        })
    }

    /// List pending batches (decoded, valid only).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `list_pending` — see module docs for full workflow.
    /// ```
    pub fn list_pending(&self) -> anyhow::Result<Vec<SpoolBatch>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.pending_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".spool") {
                continue;
            }
            match decode_batch_file(&entry.path()) {
                Ok(b) => out.push(b),
                Err(e) => {
                    tracing::warn!(path = %entry.path().display(), error = %e, "torn spool record");
                }
            }
        }
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(out)
    }

    /// Mark a batch as committed to SQLite (move to acked / delete).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `acknowledge` — see module docs for full workflow.
    /// ```
    pub fn acknowledge(&self, batch_id: &str) -> anyhow::Result<()> {
        let pending = self.pending_dir.join(format!("{batch_id}.spool"));
        if !pending.exists() {
            return Ok(()); // already acked or never written — idempotent
        }
        let acked = self.acked_dir.join(format!("{batch_id}.spool"));
        fs::rename(&pending, &acked)?;
        // Compact: remove acked file (payload is in SQLite). Keep only marker via delete.
        let _ = fs::remove_file(&acked);
        let mut h = self.health.lock();
        h.last_commit_at = Some(chrono::Utc::now().to_rfc3339());
        Ok(())
    }

    /// Pending count.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `pending_count` — see module docs for full workflow.
    /// ```
    pub fn pending_count(&self) -> usize {
        fs::read_dir(&self.pending_dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .ends_with(".spool")
                    })
                    .count()
            })
            .unwrap_or(0)
    }
}

fn new_batch_id(events: &[TraceEvent]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
    for e in events {
        hasher.update(e.id.as_bytes());
        hasher.update(e.sequence.to_le_bytes());
    }
    format!("b{}", hex::encode(&hasher.finalize()[..16]))
}

fn encode_batch(batch: &SpoolBatch) -> anyhow::Result<Vec<u8>> {
    let mut payload = Vec::new();
    let id_bytes = batch.batch_id.as_bytes();
    payload.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(id_bytes);
    let created = batch.created_at.as_bytes();
    payload.extend_from_slice(&(created.len() as u32).to_le_bytes());
    payload.extend_from_slice(created);
    payload.extend_from_slice(&(batch.events.len() as u32).to_le_bytes());
    for ev in &batch.events {
        let json = serde_json::to_vec(ev)?;
        payload.extend_from_slice(&(json.len() as u32).to_le_bytes());
        payload.extend_from_slice(&json);
    }
    let crc = crc32_ieee(&payload);

    let mut out = Vec::with_capacity(8 + payload.len() + 4);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&SPOOL_VERSION.to_le_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(out)
}

fn decode_batch_file(path: &Path) -> anyhow::Result<SpoolBatch> {
    let mut data = fs::read(path)?;
    decode_batch_bytes(&mut data)
}

fn decode_batch_bytes(data: &mut [u8]) -> anyhow::Result<SpoolBatch> {
    if data.len() < 12 {
        anyhow::bail!("spool record too short");
    }
    if &data[0..4] != MAGIC {
        anyhow::bail!("bad spool magic");
    }
    let version = u32::from_le_bytes(data[4..8].try_into()?);
    if version != SPOOL_VERSION {
        anyhow::bail!("unsupported spool version {version}");
    }
    let crc_stored = u32::from_le_bytes(data[data.len() - 4..].try_into()?);
    let payload = &data[8..data.len() - 4];
    let crc = crc32_ieee(payload);
    if crc != crc_stored {
        anyhow::bail!("spool CRC mismatch (torn or corrupt record)");
    }
    let mut off = 0usize;
    let id_len = read_u32(payload, &mut off)? as usize;
    let batch_id = read_str(payload, &mut off, id_len)?;
    let created_len = read_u32(payload, &mut off)? as usize;
    let created_at = read_str(payload, &mut off, created_len)?;
    let n = read_u32(payload, &mut off)? as usize;
    let mut events = Vec::with_capacity(n);
    for _ in 0..n {
        let jlen = read_u32(payload, &mut off)? as usize;
        if off + jlen > payload.len() {
            anyhow::bail!("spool event truncated");
        }
        let ev: TraceEvent = serde_json::from_slice(&payload[off..off + jlen])?;
        off += jlen;
        events.push(ev);
    }
    Ok(SpoolBatch {
        batch_id,
        events,
        created_at,
    })
}

fn read_u32(buf: &[u8], off: &mut usize) -> anyhow::Result<u32> {
    if *off + 4 > buf.len() {
        anyhow::bail!("truncated");
    }
    let v = u32::from_le_bytes(buf[*off..*off + 4].try_into()?);
    *off += 4;
    Ok(v)
}

fn read_str(buf: &[u8], off: &mut usize, len: usize) -> anyhow::Result<String> {
    if *off + len > buf.len() {
        anyhow::bail!("truncated");
    }
    let s = std::str::from_utf8(&buf[*off..*off + len])?.to_string();
    *off += len;
    Ok(s)
}

/// IEEE CRC32 (polynomial 0xEDB88320), no extra crate dependency.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Inspect spool directory without full recovery.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `inspect_spool` — see module docs for full workflow.
/// ```
pub fn inspect_spool(root: &Path) -> anyhow::Result<SpoolInspectInfo> {
    let pending = root.join("pending");
    let acked = root.join("acked");
    let mut info = SpoolInspectInfo::default();
    if pending.is_dir() {
        for entry in fs::read_dir(&pending)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".spool") {
                continue;
            }
            let meta = entry.metadata()?;
            info.bytes += meta.len();
            match decode_batch_file(&entry.path()) {
                Ok(b) => {
                    info.pending_batches += 1;
                    info.pending_events += b.events.len() as u64;
                }
                Err(_) => info.torn_records += 1,
            }
        }
    }
    if acked.is_dir() {
        info.acked_batches = fs::read_dir(&acked)?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".spool"))
            .count() as u64;
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::EventSource;

    #[test]
    fn round_trip_and_crc() {
        let dir = tempfile::tempdir().unwrap();
        let spool = EventSpool::open(dir.path()).unwrap();
        let mut ev = TraceEvent::new("run1", EventSource::System, "tick");
        ev.sequence = 1;
        let res = spool.append_batch(&[ev.clone()]).unwrap();
        assert!(res.path.exists());
        let pending = spool.list_pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].events[0].id, ev.id);
        spool.acknowledge(&res.batch_id).unwrap();
        assert!(spool.list_pending().unwrap().is_empty());
    }

    #[test]
    fn detects_torn_crc() {
        let batch = SpoolBatch {
            batch_id: "b1".into(),
            events: vec![TraceEvent::new("r", EventSource::System, "t")],
            created_at: "t".into(),
        };
        let mut bytes = encode_batch(&batch).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        let err = decode_batch_bytes(&mut bytes).unwrap_err();
        assert!(err.to_string().contains("CRC"));
    }
}
