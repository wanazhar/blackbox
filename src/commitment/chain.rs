//! Append-only per-run hash chain and run root commitment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::core::event::TraceEvent;
use crate::protocol::canonical_hash;

use super::event_hash::event_content_hash;
use super::sign::SignedRunRoot;

/// Schema for run commitments.
pub const COMMITMENT_RUN_SCHEMA: &str = "blackbox.commitment.run/v1";

/// Genesis previous-hash (32 zero bytes hex).
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// One link in the event hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLink {
    /// Recorder sequence.
    pub sequence: u64,
    /// Event id.
    pub event_id: String,
    /// Content hash of the event.
    pub event_hash: String,
    /// Hash of this link: sha256(prev_hash || event_hash || sequence || event_id).
    pub link_hash: String,
    /// Previous link hash (or genesis).
    pub prev_hash: String,
}

impl ChainLink {
    /// Compute link hash from parts.
    pub fn compute_link_hash(
        prev_hash: &str,
        event_hash: &str,
        sequence: u64,
        event_id: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(b"|");
        hasher.update(event_hash.as_bytes());
        hasher.update(b"|");
        hasher.update(sequence.to_string().as_bytes());
        hasher.update(b"|");
        hasher.update(event_id.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Build a link given previous hash and event.
    pub fn from_event(prev_hash: &str, event: &TraceEvent) -> Self {
        let event_hash = event_content_hash(event);
        let link_hash = Self::compute_link_hash(prev_hash, &event_hash, event.sequence, &event.id);
        Self {
            sequence: event.sequence,
            event_id: event.id.clone(),
            event_hash,
            link_hash,
            prev_hash: prev_hash.to_string(),
        }
    }
}

/// Final run commitment object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunCommitment {
    /// Schema.
    pub schema: String,
    /// Run id.
    pub run_id: String,
    /// Number of events in the chain.
    pub event_count: u64,
    /// Tip of the event chain (last link_hash), or genesis if empty.
    pub chain_tip: String,
    /// Root covering chain tip + receipt/manifest/evidence roots.
    pub root_hash: String,
    /// Optional receipt content hashes included in the root.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipt_roots: Vec<String>,
    /// Workspace manifest root when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_root: Option<String>,
    /// External evidence set root when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_root: Option<String>,
    /// Ordered chain links (may be omitted in compact export).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<ChainLink>,
    /// Optional signature over root_hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignedRunRoot>,
    /// Creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    /// Honest limitations of what this commitment proves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

impl RunCommitment {
    /// Default honesty limitations.
    pub fn default_limitations() -> Vec<String> {
        vec![
            "proves_record_consistency_after_commitment".into(),
            "does_not_prove_observation_completeness".into(),
            "does_not_prove_external_truth".into(),
            "does_not_upgrade_unverified_observations".into(),
        ]
    }
}

/// Builder for a run commitment from events and optional roots.
#[derive(Debug, Default)]
pub struct RunCommitmentBuilder {
    run_id: String,
    events: Vec<TraceEvent>,
    receipt_roots: Vec<String>,
    manifest_root: Option<String>,
    evidence_root: Option<String>,
    include_links: bool,
}

impl RunCommitmentBuilder {
    /// Start a builder for `run_id`.
    pub fn new(run_id: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            events: vec![],
            receipt_roots: vec![],
            manifest_root: None,
            evidence_root: None,
            include_links: true,
        }
    }

    /// Events in sequence order.
    pub fn events(mut self, events: Vec<TraceEvent>) -> Self {
        self.events = events;
        self
    }

    /// Receipt content hashes.
    pub fn receipt_roots(mut self, roots: Vec<String>) -> Self {
        self.receipt_roots = roots;
        self
    }

    /// Workspace manifest root.
    pub fn manifest_root(mut self, root: impl Into<String>) -> Self {
        self.manifest_root = Some(root.into());
        self
    }

    /// External evidence root.
    pub fn evidence_root(mut self, root: impl Into<String>) -> Self {
        self.evidence_root = Some(root.into());
        self
    }

    /// Whether to embed full links (default true).
    pub fn include_links(mut self, yes: bool) -> Self {
        self.include_links = yes;
        self
    }

    /// Build the commitment.
    pub fn build(self) -> RunCommitment {
        build_run_commitment(
            &self.run_id,
            &self.events,
            &self.receipt_roots,
            self.manifest_root.as_deref(),
            self.evidence_root.as_deref(),
            self.include_links,
        )
    }
}

/// Build chain links from ordered events.
pub fn build_chain(events: &[TraceEvent]) -> Vec<ChainLink> {
    let mut links = Vec::with_capacity(events.len());
    let mut prev = GENESIS_PREV_HASH.to_string();
    // Ensure sequence order.
    let mut ordered: Vec<&TraceEvent> = events.iter().collect();
    ordered.sort_by_key(|e| e.sequence);
    for event in ordered {
        let link = ChainLink::from_event(&prev, event);
        prev = link.link_hash.clone();
        links.push(link);
    }
    links
}

/// Compute the run root hash from chain tip and optional sub-roots.
pub fn compute_root_hash(
    run_id: &str,
    chain_tip: &str,
    event_count: u64,
    receipt_roots: &[String],
    manifest_root: Option<&str>,
    evidence_root: Option<&str>,
) -> String {
    let mut receipts = receipt_roots.to_vec();
    receipts.sort();
    let body = json!({
        "run_id": run_id,
        "event_count": event_count,
        "chain_tip": chain_tip,
        "receipt_roots": receipts,
        "manifest_root": manifest_root,
        "evidence_root": evidence_root,
    });
    canonical_hash(&body).unwrap_or_else(|_| {
        let mut hasher = Sha256::new();
        hasher.update(chain_tip.as_bytes());
        hex::encode(hasher.finalize())
    })
}

/// Build a full run commitment.
pub fn build_run_commitment(
    run_id: &str,
    events: &[TraceEvent],
    receipt_roots: &[String],
    manifest_root: Option<&str>,
    evidence_root: Option<&str>,
    include_links: bool,
) -> RunCommitment {
    let links = build_chain(events);
    let chain_tip = links
        .last()
        .map(|l| l.link_hash.clone())
        .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
    let event_count = links.len() as u64;
    let root_hash = compute_root_hash(
        run_id,
        &chain_tip,
        event_count,
        receipt_roots,
        manifest_root,
        evidence_root,
    );
    RunCommitment {
        schema: COMMITMENT_RUN_SCHEMA.into(),
        run_id: run_id.to_string(),
        event_count,
        chain_tip,
        root_hash,
        receipt_roots: {
            let mut r = receipt_roots.to_vec();
            r.sort();
            r
        },
        manifest_root: manifest_root.map(|s| s.to_string()),
        evidence_root: evidence_root.map(|s| s.to_string()),
        links: if include_links { links } else { vec![] },
        signature: None,
        created_at: Some(Utc::now()),
        limitations: RunCommitment::default_limitations(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, TraceEvent};

    fn ev(run: &str, seq: u64, kind: &str) -> TraceEvent {
        let mut e = TraceEvent::new(run, EventSource::System, kind);
        e.sequence = seq;
        e
    }

    #[test]
    fn chain_detects_order() {
        let events = vec![ev("r", 1, "a"), ev("r", 2, "b"), ev("r", 3, "c")];
        let c = build_run_commitment("r", &events, &[], None, None, true);
        assert_eq!(c.event_count, 3);
        assert_eq!(c.links[0].prev_hash, GENESIS_PREV_HASH);
        assert_eq!(c.links[1].prev_hash, c.links[0].link_hash);
    }
}
