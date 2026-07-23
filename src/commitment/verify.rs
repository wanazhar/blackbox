//! Offline verification of event chains and run commitments.

use serde::{Deserialize, Serialize};

use crate::core::event::TraceEvent;

use super::chain::{build_chain, compute_root_hash, ChainLink, RunCommitment, GENESIS_PREV_HASH};
use super::event_hash::event_content_hash;
use super::sign::{verify_run_root_signature, SignatureStatus};

/// Detected chain fault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainFault {
    /// Event inserted or sequence gap.
    Insertion {
        /// Sequence where fault detected.
        sequence: u64,
        /// Detail.
        detail: String,
    },
    /// Event missing from chain vs provided events.
    Deletion {
        /// Sequence.
        sequence: u64,
        /// Detail.
        detail: String,
    },
    /// Events reordered relative to link prev hashes.
    Reordering {
        /// Sequence.
        sequence: u64,
        /// Detail.
        detail: String,
    },
    /// Event content replaced (hash mismatch).
    Replacement {
        /// Sequence.
        sequence: u64,
        /// Event id.
        event_id: String,
    },
    /// Chain truncated vs declared count.
    Truncation {
        /// Expected count.
        expected: u64,
        /// Actual count.
        actual: u64,
    },
    /// Link hash does not recompute.
    LinkCorrupt {
        /// Sequence.
        sequence: u64,
    },
    /// Genesis / prev pointer broken.
    PrevMismatch {
        /// Sequence.
        sequence: u64,
    },
}

/// Report from chain verification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainVerifyReport {
    /// Whether the chain is fully consistent.
    pub ok: bool,
    /// Faults found.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub faults: Vec<ChainFault>,
    /// Links checked.
    pub links_checked: u64,
}

/// Full commitment verification report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentVerifyReport {
    /// Overall ok (chain + root; signature separate).
    pub ok: bool,
    /// Chain report.
    pub chain: ChainVerifyReport,
    /// Whether root_hash matches recomputation.
    pub root_ok: bool,
    /// Signature status (Missing if none).
    pub signature: SignatureStatus,
    /// Limitations still apply even when ok.
    pub limitations: Vec<String>,
}

/// Verify an ordered list of events produces a consistent chain.
pub fn verify_chain(events: &[TraceEvent]) -> ChainVerifyReport {
    let mut report = ChainVerifyReport {
        ok: true,
        faults: vec![],
        links_checked: 0,
    };
    let mut ordered: Vec<&TraceEvent> = events.iter().collect();
    ordered.sort_by_key(|e| e.sequence);

    // Detect duplicate sequences (replacement / insert ambiguity).
    for w in ordered.windows(2) {
        if w[0].sequence == w[1].sequence {
            report.ok = false;
            report.faults.push(ChainFault::Insertion {
                sequence: w[0].sequence,
                detail: "duplicate sequence".into(),
            });
        }
    }

    let links = build_chain(events);
    report.links_checked = links.len() as u64;
    let mut prev = GENESIS_PREV_HASH.to_string();
    for link in &links {
        if link.prev_hash != prev {
            report.ok = false;
            report.faults.push(ChainFault::PrevMismatch {
                sequence: link.sequence,
            });
        }
        let recomputed = ChainLink::compute_link_hash(
            &link.prev_hash,
            &link.event_hash,
            link.sequence,
            &link.event_id,
        );
        if recomputed != link.link_hash {
            report.ok = false;
            report.faults.push(ChainFault::LinkCorrupt {
                sequence: link.sequence,
            });
        }
        // Content hash must match event.
        if let Some(ev) = ordered.iter().find(|e| e.id == link.event_id) {
            let h = event_content_hash(ev);
            if h != link.event_hash {
                report.ok = false;
                report.faults.push(ChainFault::Replacement {
                    sequence: link.sequence,
                    event_id: link.event_id.clone(),
                });
            }
        } else {
            report.ok = false;
            report.faults.push(ChainFault::Deletion {
                sequence: link.sequence,
                detail: format!("event_id {} missing from events", link.event_id),
            });
        }
        prev = link.link_hash.clone();
    }
    report
}

/// Verify a commitment against provided events.
///
/// When `commitment.links` is empty, the chain is rebuilt from `events`.
pub fn verify_commitment(
    commitment: &RunCommitment,
    events: &[TraceEvent],
    trusted_keys: Option<&[String]>,
    revoked_keys: &[String],
) -> CommitmentVerifyReport {
    let mut chain = if commitment.links.is_empty() {
        verify_chain(events)
    } else {
        // Verify embedded links against events and recompute.
        let mut report = ChainVerifyReport {
            ok: true,
            faults: vec![],
            links_checked: commitment.links.len() as u64,
        };
        if commitment.event_count != commitment.links.len() as u64 {
            report.ok = false;
            report.faults.push(ChainFault::Truncation {
                expected: commitment.event_count,
                actual: commitment.links.len() as u64,
            });
        }
        // Rebuild expected links from events and compare.
        let expected = build_chain(events);
        if expected.len() != commitment.links.len() {
            report.ok = false;
            if expected.len() < commitment.links.len() {
                report.faults.push(ChainFault::Deletion {
                    sequence: 0,
                    detail: format!(
                        "events {} vs links {}",
                        expected.len(),
                        commitment.links.len()
                    ),
                });
            } else {
                report.faults.push(ChainFault::Insertion {
                    sequence: 0,
                    detail: format!(
                        "events {} vs links {}",
                        expected.len(),
                        commitment.links.len()
                    ),
                });
            }
        }
        for (i, (exp, got)) in expected.iter().zip(commitment.links.iter()).enumerate() {
            if exp.event_id != got.event_id || exp.sequence != got.sequence {
                report.ok = false;
                report.faults.push(ChainFault::Reordering {
                    sequence: got.sequence,
                    detail: format!("position {i} event/sequence mismatch"),
                });
            }
            if exp.event_hash != got.event_hash {
                report.ok = false;
                report.faults.push(ChainFault::Replacement {
                    sequence: got.sequence,
                    event_id: got.event_id.clone(),
                });
            }
            if exp.link_hash != got.link_hash || exp.prev_hash != got.prev_hash {
                report.ok = false;
                report.faults.push(ChainFault::LinkCorrupt {
                    sequence: got.sequence,
                });
            }
        }
        // Tip check.
        let tip = commitment
            .links
            .last()
            .map(|l| l.link_hash.as_str())
            .unwrap_or(GENESIS_PREV_HASH);
        if tip != commitment.chain_tip {
            report.ok = false;
            report.faults.push(ChainFault::LinkCorrupt { sequence: 0 });
        }
        report
    };

    // Truncation vs event_count.
    if commitment.event_count != events.len() as u64 && commitment.links.is_empty() {
        // Compact form: event_count should match provided events for full verify.
        if commitment.event_count != events.len() as u64 {
            chain.ok = false;
            chain.faults.push(ChainFault::Truncation {
                expected: commitment.event_count,
                actual: events.len() as u64,
            });
        }
    }

    let rebuilt_tip = build_chain(events)
        .last()
        .map(|l| l.link_hash.clone())
        .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
    let expected_root = compute_root_hash(
        &commitment.run_id,
        &rebuilt_tip,
        events.len() as u64,
        &commitment.receipt_roots,
        commitment.manifest_root.as_deref(),
        commitment.evidence_root.as_deref(),
    );
    // For partial exports with declared proof limitations, event_count may differ.
    let root_ok = if commitment.event_count == events.len() as u64 {
        expected_root == commitment.root_hash && rebuilt_tip == commitment.chain_tip
    } else {
        // Partial range: recompute root with declared count only if tip matches declared.
        false
    };

    let signature = match &commitment.signature {
        None => SignatureStatus::Missing,
        Some(sig) => {
            verify_run_root_signature(sig, &commitment.root_hash, trusted_keys, revoked_keys)
        }
    };

    let ok = chain.ok && root_ok;
    CommitmentVerifyReport {
        ok,
        chain,
        root_ok,
        signature,
        limitations: commitment.limitations.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::chain::build_run_commitment;
    use crate::commitment::sign::{generate_signing_key, sign_run_root};
    use crate::core::event::{EventSource, TraceEvent};

    fn ev(run: &str, seq: u64, kind: &str) -> TraceEvent {
        let mut e = TraceEvent::new(run, EventSource::System, kind);
        e.sequence = seq;
        e.id = format!("e-{seq}");
        e
    }

    #[test]
    fn detects_insertion() {
        let events = vec![ev("r", 1, "a"), ev("r", 2, "b")];
        let c = build_run_commitment("r", &events, &[], None, None, true);
        // Attacker inserts a forged link claim by mutating events.
        let mut tampered = events.clone();
        tampered.insert(1, ev("r", 1, "INJECT")); // duplicate seq + new event
        tampered[1].id = "injected".into();
        tampered[1].sequence = 99;
        // Rebuild would differ — verify commitment links against tampered events.
        let report = verify_commitment(&c, &tampered, None, &[]);
        assert!(!report.ok);
        assert!(!report.chain.ok || !report.root_ok);
        let _ = c;
    }

    #[test]
    fn detects_deletion() {
        let events = vec![ev("r", 1, "a"), ev("r", 2, "b"), ev("r", 3, "c")];
        let c = build_run_commitment("r", &events, &[], None, None, true);
        let partial: Vec<_> = events.iter().take(2).cloned().collect();
        let report = verify_commitment(&c, &partial, None, &[]);
        assert!(!report.ok);
    }

    #[test]
    fn detects_reordering() {
        let events = vec![ev("r", 1, "a"), ev("r", 2, "b"), ev("r", 3, "c")];
        let mut c = build_run_commitment("r", &events, &[], None, None, true);
        c.links.swap(0, 1);
        let report = verify_commitment(&c, &events, None, &[]);
        assert!(!report.ok);
        assert!(report
            .chain
            .faults
            .iter()
            .any(|f| matches!(f, ChainFault::Reordering { .. } | ChainFault::LinkCorrupt { .. } | ChainFault::PrevMismatch { .. })));
    }

    #[test]
    fn detects_replacement() {
        let events = vec![ev("r", 1, "a"), ev("r", 2, "b")];
        let c = build_run_commitment("r", &events, &[], None, None, true);
        let mut replaced = events.clone();
        replaced[1].kind = "TAMPERED".into();
        let report = verify_commitment(&c, &replaced, None, &[]);
        assert!(!report.ok);
        assert!(report.chain.faults.iter().any(|f| matches!(
            f,
            ChainFault::Replacement { .. } | ChainFault::LinkCorrupt { .. }
        )) || !report.root_ok);
    }

    #[test]
    fn clean_chain_and_signature() {
        let events = vec![ev("r", 1, "a"), ev("r", 2, "b")];
        let mut c = build_run_commitment(
            "r",
            &events,
            &["receipt-aaa".into()],
            Some("manifest-bbb"),
            Some("evidence-ccc"),
            true,
        );
        let key = generate_signing_key();
        c.signature = Some(sign_run_root(&key, &c.root_hash));
        let report = verify_commitment(&c, &events, None, &[]);
        assert!(report.ok, "{report:?}");
        assert_eq!(report.signature, SignatureStatus::Valid);
        assert!(!report.limitations.is_empty());
    }

    #[test]
    fn signature_does_not_upgrade_when_chain_broken() {
        let events = vec![ev("r", 1, "a")];
        let mut c = build_run_commitment("r", &events, &[], None, None, true);
        let key = generate_signing_key();
        c.signature = Some(sign_run_root(&key, &c.root_hash));
        let mut bad = events.clone();
        bad[0].kind = "changed".into();
        let report = verify_commitment(&c, &bad, None, &[]);
        assert!(!report.ok);
        // Signature may still verify over the *committed* root_hash bytes,
        // but overall ok is false and limitations still apply.
        assert!(!report.limitations.is_empty());
    }
}
