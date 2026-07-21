//! Metadata-only discovery across project-local stores.
//!
//! Project `.blackbox/` stores remain authoritative. The global index never
//! centralizes transcripts or blobs.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectIndexEntry {
    pub project_root: PathBuf,
    pub store_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_status: Option<String>,
    #[serde(default)]
    pub run_count_estimate: u64,
    pub indexed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct ProjectIndexQuery {
    pub name_substr: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectRegistry {
    pub schema: String,
    pub entries: Vec<ProjectIndexEntry>,
}

impl ProjectRegistry {
    pub fn empty() -> Self {
        Self {
            schema: "blackbox.projects.index/v1".into(),
            entries: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::empty());
        }
        let s = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&s)?)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        crate::privacy::restrict_file(path);
        Ok(())
    }

    pub fn upsert(&mut self, entry: ProjectIndexEntry) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.project_root == entry.project_root)
        {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    pub fn query(&self, q: &ProjectIndexQuery) -> Vec<&ProjectIndexEntry> {
        let mut out: Vec<_> = self.entries.iter().collect();
        if let Some(ref sub) = q.name_substr {
            let s = sub.to_lowercase();
            out.retain(|e| {
                e.project_root
                    .to_string_lossy()
                    .to_lowercase()
                    .contains(&s)
            });
        }
        out.sort_by_key(|e| std::cmp::Reverse(e.indexed_at));
        if let Some(lim) = q.limit {
            out.truncate(lim);
        }
        out
    }

    /// Drop entries whose store file is missing. Returns count removed.
    pub fn prune_missing(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.store_path.is_file());
        before.saturating_sub(self.entries.len())
    }

    /// Remove a project root entry (exact path match). Returns true if removed.
    pub fn remove_root(&mut self, project_root: &Path) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.project_root != project_root);
        before != self.entries.len()
    }
}

/// Walk `roots` one level deep looking for `.blackbox/blackbox.db` (or legacy).
pub fn discover_project_stores(roots: &[PathBuf]) -> Vec<ProjectIndexEntry> {
    let mut out = Vec::new();
    let now = Utc::now();
    for root in roots {
        let candidates = [
            root.join(".blackbox/blackbox.db"),
            root.join("blackbox.db"),
        ];
        for store_path in candidates {
            if store_path.is_file() {
                out.push(ProjectIndexEntry {
                    project_root: root.clone(),
                    store_path,
                    last_run_at: None,
                    last_run_id: None,
                    last_status: None,
                    run_count_estimate: 0,
                    indexed_at: now,
                });
                break;
            }
        }
        // Also scan immediate children
        if let Ok(rd) = std::fs::read_dir(root) {
            for entry in rd.flatten() {
                let p = entry.path();
                if !p.is_dir() {
                    continue;
                }
                let db = p.join(".blackbox/blackbox.db");
                if db.is_file() {
                    out.push(ProjectIndexEntry {
                        project_root: p,
                        store_path: db,
                        last_run_at: None,
                        last_run_id: None,
                        last_status: None,
                        run_count_estimate: 0,
                        indexed_at: now,
                    });
                }
            }
        }
    }
    out
}

/// Default global index path: `~/.blackbox/projects-index.json` (metadata only).
pub fn default_index_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".blackbox/projects-index.json");
    }
    PathBuf::from(".blackbox/projects-index.json")
}
