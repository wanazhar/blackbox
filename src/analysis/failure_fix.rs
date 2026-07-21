//! Failure-to-fix correlation pass (1.4 G1).
//!
//! Connects errors with subsequent file changes and **matching** verification
//! retries. `confirmed` requires command fingerprints / tool IDs — not mere
//! chronological proximity to an unrelated success.

use std::collections::HashMap;

use crate::analysis::causal::{
    build_tool_pairing_edges, confidence_for_verification, fingerprint_from_event,
    matching_tool_result, preceding_tool_call, tool_correlation_id, CausalEdge, CausalEvidence,
    CausalRelation, CommandFingerprint, FailureSignature, VerificationCoverage,
};
use crate::analysis::AnalysisPass;
use crate::core::event::{Confidence, EventSource, EventStatus, TraceEvent};

/// A single failure-to-fix correlation chain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FailureFixChain {
    /// The error event that triggered the chain.
    pub error_event_id: String,
    /// The error message or kind.
    pub error_message: String,
    /// File changes that occurred after the error (as fix attempts).
    pub files_changed: Vec<String>,
    /// Whether a verification retry was observed.
    pub retry_occurred: bool,
    /// Whether the verification retry succeeded.
    pub retry_successful: Option<bool>,
    /// Confidence in the correlation (never stronger than evidence).
    pub confidence: Confidence,
    /// Failure command fingerprint key when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_fingerprint: Option<String>,
    /// Verification command fingerprint key when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_fingerprint: Option<String>,
    /// Failure signature key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_signature: Option<String>,
    /// Verification coverage classification.
    #[serde(default)]
    pub verification_coverage: VerificationCoverage,
    /// Why this confidence was assigned.
    #[serde(default)]
    pub reasons: Vec<String>,
    /// Evidence event links.
    #[serde(default)]
    pub evidence: Vec<CausalEvidence>,
    /// Derived causal edges for this chain.
    #[serde(default)]
    pub edges: Vec<CausalEdge>,
}

/// Correlates errors with subsequent file modifications and matching retries.
pub struct FailureFixCorrelator;

impl Default for FailureFixCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl FailureFixCorrelator {
    /// Create a new instance.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `new` — see module docs for full workflow.
    /// ```
    pub fn new() -> Self {
        Self
    }

    /// Find failure-to-fix chains with evidence-based confidence.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `find_chains` — see module docs for full workflow.
    /// ```
    pub fn find_chains(&self, events: &[TraceEvent]) -> Vec<FailureFixChain> {
        let mut chains = Vec::new();
        let error_window_ms: i64 = 30_000;
        let pairing = build_tool_pairing_edges(events);

        let error_indices: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.status == EventStatus::Error
                    || e.metadata
                        .get("exit_code")
                        .and_then(|v| v.as_i64())
                        .map(|c| c != 0)
                        .unwrap_or(false)
            })
            .map(|(i, _)| i)
            .collect();

        for &err_idx in &error_indices {
            let error_event = &events[err_idx];
            let error_time = error_event.started_at;
            let fail_sig = FailureSignature::from_error_event(error_event);

            // Fingerprint of the failed command (prefer preceding tool.call).
            let failure_fp: Option<CommandFingerprint> =
                if let Some((_, call)) = preceding_tool_call(events, err_idx) {
                    fingerprint_from_event(call).or_else(|| fingerprint_from_event(error_event))
                } else {
                    fingerprint_from_event(error_event)
                };

            let mut files_changed: Vec<String> = Vec::new();
            let mut file_evidence: Vec<CausalEvidence> = Vec::new();
            let mut edges: Vec<CausalEdge> = Vec::new();
            let mut latest_fs_time = error_time;

            // Collect edits after the error within the window.
            for ev in events.iter().skip(err_idx + 1) {
                let gap = ev
                    .started_at
                    .signed_duration_since(error_time)
                    .num_milliseconds();
                if gap > error_window_ms {
                    break;
                }

                if ev.source == EventSource::Filesystem
                    && !ev.kind.contains("observer")
                    && !ev.kind.contains("snapshot")
                {
                    if let Some(path) = ev.metadata.get("path").and_then(|v| v.as_str()) {
                        if !files_changed.iter().any(|f| f == path) {
                            files_changed.push(path.to_string());
                            file_evidence.push(CausalEvidence {
                                event_id: ev.id.clone(),
                                sequence: ev.sequence,
                                role: "edited_file".into(),
                            });
                            edges.push(CausalEdge {
                                from_event_id: error_event.id.clone(),
                                to_event_id: ev.id.clone(),
                                relation: CausalRelation::EditedAfter,
                                confidence: Confidence::WeaklyCorrelated,
                                reasons: vec!["filesystem_after_error".into()],
                            });
                        }
                    }
                    if ev.started_at > latest_fs_time {
                        latest_fs_time = ev.started_at;
                    }
                }
            }

            // Search for verification tool.call after error (and preferably after edits).
            let mut retry_occurred = false;
            let mut retry_successful: Option<bool> = None;
            let mut verification_fp: Option<CommandFingerprint> = None;
            let mut verify_call_id: Option<String> = None;
            let mut verify_result_id: Option<String> = None;
            let mut result_linked_by_id = false;
            let mut best_conf = Confidence::Unknown;
            let mut best_cov = VerificationCoverage::None;
            let mut best_reasons: Vec<String> = Vec::new();
            let mut verify_evidence: Vec<CausalEvidence> = Vec::new();

            for j in (err_idx + 1)..events.len() {
                let ev = &events[j];
                let gap = ev
                    .started_at
                    .signed_duration_since(error_time)
                    .num_milliseconds();
                if gap > error_window_ms {
                    break;
                }
                if ev.kind != "tool.call" {
                    continue;
                }

                let call_fp = fingerprint_from_event(ev);
                let (res_idx, res) = match matching_tool_result(events, j) {
                    Some(pair) => pair,
                    None => continue,
                };

                let success = res.status == EventStatus::Success;
                let linked = tool_correlation_id(ev).is_some()
                    && tool_correlation_id(ev) == tool_correlation_id(res);

                let had_edits = !files_changed.is_empty();
                // Prefer verifications that happen after at least one edit when edits exist.
                if had_edits && ev.started_at < latest_fs_time {
                    // Still consider, but lower priority via reasons.
                }

                let (conf, cov, reasons) = confidence_for_verification(
                    failure_fp.as_ref(),
                    call_fp.as_ref(),
                    linked,
                    success,
                    had_edits,
                );

                // Keep the strongest confidence candidate.
                if conf < best_conf
                    || best_conf == Confidence::Unknown
                    || (conf == best_conf && success && retry_successful != Some(true))
                {
                    // Confidence enum: Confirmed < StronglyCorrelated < … so lower is stronger.
                    let better = match (best_conf, conf) {
                        (Confidence::Unknown, _) => true,
                        (_, Confidence::Unknown) => false,
                        (a, b) => b < a,
                    };
                    if better || best_reasons.is_empty() {
                        best_conf = conf;
                        best_cov = cov;
                        best_reasons = reasons;
                        retry_occurred = true;
                        retry_successful = Some(success);
                        verification_fp = call_fp;
                        verify_call_id = Some(ev.id.clone());
                        verify_result_id = Some(res.id.clone());
                        result_linked_by_id = linked;
                        verify_evidence = vec![
                            CausalEvidence {
                                event_id: ev.id.clone(),
                                sequence: ev.sequence,
                                role: "verification_call".into(),
                            },
                            CausalEvidence {
                                event_id: res.id.clone(),
                                sequence: res.sequence,
                                role: if success {
                                    "verification_result".into()
                                } else {
                                    "verification_result_failed".into()
                                },
                            },
                        ];
                        let _ = res_idx;
                    }
                }
            }

            // If we only have edits, no verification:
            if !retry_occurred && !files_changed.is_empty() {
                best_conf = Confidence::WeaklyCorrelated;
                best_cov = VerificationCoverage::None;
                best_reasons = vec!["edits_after_error_no_verification".into()];
            }

            if files_changed.is_empty() && !retry_occurred {
                continue;
            }

            // Attach verified_by edge when we have a verification.
            if let (Some(call_id), Some(res_id)) = (&verify_call_id, &verify_result_id) {
                let mut reasons = best_reasons.clone();
                if result_linked_by_id {
                    reasons.push("matching_tool_result_id".into());
                }
                edges.push(CausalEdge {
                    from_event_id: error_event.id.clone(),
                    to_event_id: res_id.clone(),
                    relation: CausalRelation::VerifiedBy,
                    confidence: best_conf,
                    reasons: reasons.clone(),
                });
                edges.push(CausalEdge {
                    from_event_id: call_id.clone(),
                    to_event_id: res_id.clone(),
                    relation: CausalRelation::ToolResultOf,
                    confidence: if result_linked_by_id {
                        Confidence::Confirmed
                    } else {
                        Confidence::StronglyCorrelated
                    },
                    reasons: if result_linked_by_id {
                        vec!["matching_tool_result_id".into()]
                    } else {
                        vec!["nearest_tool_result".into()]
                    },
                });
                if let (Some(ff), Some(vf)) = (&failure_fp, &verification_fp) {
                    if ff.key == vf.key || ff.same_family(vf) {
                        edges.push(CausalEdge {
                            from_event_id: error_event.id.clone(),
                            to_event_id: call_id.clone(),
                            relation: CausalRelation::SameCommandFamily,
                            confidence: if ff.key == vf.key {
                                Confidence::Confirmed
                            } else {
                                Confidence::StronglyCorrelated
                            },
                            reasons: vec![if ff.key == vf.key {
                                "matching_command_fingerprint".into()
                            } else {
                                "same_command_family".into()
                            }],
                        });
                    }
                }
            }

            // Include pairing edges that touch this chain's events.
            for pe in &pairing {
                let touches = pe.from_event_id == error_event.id
                    || pe.to_event_id == error_event.id
                    || verify_call_id.as_ref() == Some(&pe.from_event_id)
                    || verify_result_id.as_ref() == Some(&pe.to_event_id);
                if touches
                    && !edges.iter().any(|e| {
                        e.from_event_id == pe.from_event_id
                            && e.to_event_id == pe.to_event_id
                            && e.relation == pe.relation
                    })
                {
                    edges.push(pe.clone());
                }
            }

            let mut evidence = vec![CausalEvidence {
                event_id: error_event.id.clone(),
                sequence: error_event.sequence,
                role: "failure".into(),
            }];
            evidence.extend(file_evidence);
            evidence.extend(verify_evidence);

            chains.push(FailureFixChain {
                error_event_id: error_event.id.clone(),
                error_message: fail_sig.message_preview.clone(),
                files_changed,
                retry_occurred,
                retry_successful,
                confidence: best_conf,
                failure_fingerprint: failure_fp.as_ref().map(|f| f.key.clone()),
                verification_fingerprint: verification_fp.as_ref().map(|f| f.key.clone()),
                failure_signature: Some(fail_sig.key),
                verification_coverage: best_cov,
                reasons: best_reasons,
                evidence,
                edges,
            });
        }

        chains
    }
}

#[async_trait::async_trait]
impl AnalysisPass for FailureFixCorrelator {
    fn name(&self) -> &'static str {
        "failure_fix"
    }

    async fn analyze(&self, events: &[TraceEvent]) -> anyhow::Result<Vec<TraceEvent>> {
        let chains = self.find_chains(events);
        let mut derived = Vec::with_capacity(chains.len());

        for chain in &chains {
            let mut meta = HashMap::new();
            meta.insert(
                "error_event_id".to_string(),
                serde_json::Value::String(chain.error_event_id.clone()),
            );
            meta.insert(
                "error_message".to_string(),
                serde_json::Value::String(chain.error_message.clone()),
            );
            meta.insert(
                "files_changed".to_string(),
                serde_json::to_value(&chain.files_changed).unwrap_or_default(),
            );
            meta.insert(
                "retry_occurred".to_string(),
                serde_json::Value::Bool(chain.retry_occurred),
            );
            if let Some(success) = chain.retry_successful {
                meta.insert(
                    "retry_successful".to_string(),
                    serde_json::Value::Bool(success),
                );
            }
            meta.insert(
                "confidence".to_string(),
                serde_json::Value::String(chain.confidence.as_str().to_string()),
            );
            meta.insert(
                "verification_coverage".to_string(),
                serde_json::Value::String(chain.verification_coverage.as_str().to_string()),
            );
            meta.insert(
                "reasons".to_string(),
                serde_json::to_value(&chain.reasons).unwrap_or_default(),
            );
            if let Some(ref fp) = chain.failure_fingerprint {
                meta.insert(
                    "failure_fingerprint".into(),
                    serde_json::Value::String(fp.clone()),
                );
            }
            if let Some(ref fp) = chain.verification_fingerprint {
                meta.insert(
                    "verification_fingerprint".into(),
                    serde_json::Value::String(fp.clone()),
                );
            }
            meta.insert(
                "evidence".to_string(),
                serde_json::to_value(&chain.evidence).unwrap_or_default(),
            );
            meta.insert(
                "edges".to_string(),
                serde_json::to_value(&chain.edges).unwrap_or_default(),
            );

            let mut ev = TraceEvent::new(
                events.first().map(|e| e.run_id.as_str()).unwrap_or(""),
                EventSource::System,
                "analysis.failure_to_fix",
            );
            ev.metadata = meta;
            ev.status = EventStatus::Success;
            derived.push(ev);
        }

        Ok(derived)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn make_event(
        kind: &str,
        source: EventSource,
        status: EventStatus,
        meta: Vec<(&str, serde_json::Value)>,
        started_at: chrono::DateTime<Utc>,
    ) -> TraceEvent {
        let mut ev = TraceEvent::new("run-1", source, kind);
        ev.status = status;
        for (k, v) in meta {
            ev.metadata.insert(k.to_string(), v);
        }
        ev.started_at = started_at;
        ev
    }

    #[test]
    fn empty_events_no_chains() {
        let corr = FailureFixCorrelator::new();
        let chains = corr.find_chains(&[]);
        assert!(chains.is_empty());
    }

    #[test]
    fn no_errors_no_chains() {
        let t0 = Utc::now();
        let ev = make_event(
            "tool.call",
            EventSource::Tool,
            EventStatus::Success,
            vec![("tool_name", serde_json::json!("Bash"))],
            t0,
        );
        let chains = FailureFixCorrelator::new().find_chains(&[ev]);
        assert!(chains.is_empty());
    }

    #[test]
    fn error_with_file_change_creates_weak_chain() {
        let t0 = Utc::now();
        let err = make_event(
            "tool.result",
            EventSource::Tool,
            EventStatus::Error,
            vec![("message", serde_json::json!("compilation error"))],
            t0,
        );
        let file_change = make_event(
            "filesystem.modified",
            EventSource::Filesystem,
            EventStatus::Success,
            vec![("path", serde_json::json!("src/main.rs"))],
            t0 + Duration::milliseconds(500),
        );
        let chains = FailureFixCorrelator::new().find_chains(&[err, file_change]);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].files_changed, vec!["src/main.rs"]);
        assert_eq!(chains[0].confidence, Confidence::WeaklyCorrelated);
        assert_eq!(chains[0].verification_coverage, VerificationCoverage::None);
    }

    #[test]
    fn matching_command_retry_is_confirmed() {
        let t0 = Utc::now();
        let call1 = make_event(
            "tool.call",
            EventSource::Tool,
            EventStatus::Running,
            vec![
                ("tool_name", serde_json::json!("Bash")),
                ("input", serde_json::json!({ "command": "bun test auth" })),
                ("tool_use_id", serde_json::json!("tu-1")),
            ],
            t0,
        );
        let err = make_event(
            "tool.result",
            EventSource::Tool,
            EventStatus::Error,
            vec![
                (
                    "message",
                    serde_json::json!("TypeError: session is undefined"),
                ),
                ("tool_use_id", serde_json::json!("tu-1")),
            ],
            t0 + Duration::milliseconds(100),
        );
        let file_change = make_event(
            "filesystem.modified",
            EventSource::Filesystem,
            EventStatus::Success,
            vec![("path", serde_json::json!("src/session.ts"))],
            t0 + Duration::milliseconds(500),
        );
        let retry = make_event(
            "tool.call",
            EventSource::Tool,
            EventStatus::Running,
            vec![
                ("tool_name", serde_json::json!("Bash")),
                ("input", serde_json::json!({ "command": "bun test auth" })),
                ("tool_use_id", serde_json::json!("tu-2")),
            ],
            t0 + Duration::milliseconds(1000),
        );
        let success = make_event(
            "tool.result",
            EventSource::Tool,
            EventStatus::Success,
            vec![
                ("message", serde_json::json!("43 passed")),
                ("tool_use_id", serde_json::json!("tu-2")),
            ],
            t0 + Duration::milliseconds(1500),
        );
        let chains =
            FailureFixCorrelator::new().find_chains(&[call1, err, file_change, retry, success]);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].confidence, Confidence::Confirmed);
        assert_eq!(chains[0].retry_successful, Some(true));
        assert_eq!(
            chains[0].verification_coverage,
            VerificationCoverage::Passed
        );
        assert!(chains[0]
            .reasons
            .iter()
            .any(|r| r.contains("fingerprint") || r.contains("verification")));
        assert!(!chains[0].evidence.is_empty());
        assert!(chains[0]
            .edges
            .iter()
            .any(|e| e.relation == CausalRelation::VerifiedBy));
    }

    #[test]
    fn unrelated_success_is_not_confirmed() {
        let t0 = Utc::now();
        let call1 = make_event(
            "tool.call",
            EventSource::Tool,
            EventStatus::Running,
            vec![
                ("tool_name", serde_json::json!("Bash")),
                ("input", serde_json::json!({ "command": "bun test auth" })),
                ("tool_use_id", serde_json::json!("tu-1")),
            ],
            t0,
        );
        let err = make_event(
            "tool.result",
            EventSource::Tool,
            EventStatus::Error,
            vec![
                ("message", serde_json::json!("auth failed")),
                ("tool_use_id", serde_json::json!("tu-1")),
            ],
            t0 + Duration::milliseconds(100),
        );
        let file_change = make_event(
            "filesystem.modified",
            EventSource::Filesystem,
            EventStatus::Success,
            vec![("path", serde_json::json!("README.md"))],
            t0 + Duration::milliseconds(500),
        );
        // Unrelated command succeeds — must not prove the auth fix.
        let retry = make_event(
            "tool.call",
            EventSource::Tool,
            EventStatus::Running,
            vec![
                ("tool_name", serde_json::json!("Bash")),
                ("input", serde_json::json!({ "command": "echo hi" })),
                ("tool_use_id", serde_json::json!("tu-2")),
            ],
            t0 + Duration::milliseconds(1000),
        );
        let success = make_event(
            "tool.result",
            EventSource::Tool,
            EventStatus::Success,
            vec![
                ("message", serde_json::json!("hi")),
                ("tool_use_id", serde_json::json!("tu-2")),
            ],
            t0 + Duration::milliseconds(1500),
        );
        let chains =
            FailureFixCorrelator::new().find_chains(&[call1, err, file_change, retry, success]);
        assert_eq!(chains.len(), 1);
        assert_ne!(
            chains[0].confidence,
            Confidence::Confirmed,
            "unrelated success must not be confirmed: reasons={:?}",
            chains[0].reasons
        );
        assert_eq!(
            chains[0].verification_coverage,
            VerificationCoverage::PassedUnrelatedDomain
        );
    }

    #[test]
    fn error_outside_window_ignored() {
        let t0 = Utc::now();
        let err = make_event(
            "tool.result",
            EventSource::Tool,
            EventStatus::Error,
            vec![],
            t0,
        );
        let late_change = make_event(
            "filesystem.modified",
            EventSource::Filesystem,
            EventStatus::Success,
            vec![("path", serde_json::json!("x.rs"))],
            t0 + Duration::milliseconds(35_000),
        );
        let chains = FailureFixCorrelator::new().find_chains(&[err, late_change]);
        assert_eq!(chains.len(), 0);
    }
}
