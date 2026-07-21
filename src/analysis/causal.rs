//! Evidence-based causal graph helpers (1.4 G1 / Phase C).
//!
//! Builds command fingerprints, failure signatures, and causal edges so
//! postmortem `confirmed` claims require exact verification evidence rather
//! than chronological proximity alone.

use sha2::{Digest, Sha256};

use crate::core::command::CommandMetadata;
use crate::core::event::{Confidence, TraceEvent};

/// Relation between two events in the derived causal graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalRelation {
    /// Tool result belongs to a prior tool call (same tool_use_id).
    ToolResultOf,
    /// File edit observed after a failure.
    EditedAfter,
    /// Later command/result verifies an earlier failure domain.
    VerifiedBy,
    /// Same command fingerprint family without full verification proof.
    SameCommandFamily,
}

impl CausalRelation {
    /// View as str.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `as_str` — see module docs for full workflow.
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolResultOf => "tool_result_of",
            Self::EditedAfter => "edited_after",
            Self::VerifiedBy => "verified_by",
            Self::SameCommandFamily => "same_command_family",
        }
    }
}

/// Derived causal edge (not a raw capture event).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CausalEdge {
    /// From event id.
    pub from_event_id: String,
    /// To event id.
    pub to_event_id: String,
    /// Relation.
    pub relation: CausalRelation,
    /// Confidence.
    pub confidence: Confidence,
    /// Reasons.
    pub reasons: Vec<String>,
}

/// Canonical command fingerprint for matching verification retries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommandFingerprint {
    /// Short hex digest of the canonical form (first 16 hex chars of sha256).
    pub key: String,
    /// Human-readable summary (not used for equality).
    pub display: String,
    /// Tool name when the command came from a harness tool call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Whether argv/shell was exact enough for confirmed matching.
    pub exact: bool,
}

impl CommandFingerprint {
    /// Build from executable + argv + optional cwd (material env omitted).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_parts` — see module docs for full workflow.
    /// ```
    pub fn from_parts(
        executable: Option<&str>,
        argv: &[String],
        cwd: Option<&str>,
        tool_name: Option<&str>,
        exact: bool,
    ) -> Self {
        let mut canon = String::new();
        if let Some(exe) = executable {
            canon.push_str(exe);
        }
        canon.push('\0');
        for (i, a) in argv.iter().enumerate() {
            if i > 0 {
                canon.push('\0');
            }
            // Normalize path-like argv[0] to basename for family matching.
            if i == 0 {
                canon.push_str(basename(a));
            } else {
                canon.push_str(a);
            }
        }
        if let Some(c) = cwd {
            canon.push_str("\0cwd:");
            canon.push_str(c);
        }
        if let Some(t) = tool_name {
            canon.push_str("\0tool:");
            canon.push_str(t);
        }
        let key = short_digest(&canon);
        let display = if !argv.is_empty() {
            argv.join(" ")
        } else if let Some(exe) = executable {
            exe.to_string()
        } else if let Some(t) = tool_name {
            format!("tool:{t}")
        } else {
            "(unknown)".into()
        };
        Self {
            key,
            display,
            tool_name: tool_name.map(String::from),
            exact,
        }
    }

    /// Build from command meta.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_command_meta` — see module docs for full workflow.
    /// ```
    pub fn from_command_meta(meta: &CommandMetadata, tool_name: Option<&str>) -> Self {
        let exact = meta.lossless
            || matches!(
                meta.fidelity,
                crate::core::command::CommandFidelity::Exact
                    | crate::core::command::CommandFidelity::Inferred
            );
        if !meta.argv.is_empty() {
            return Self::from_parts(
                meta.executable.as_deref(),
                &meta.argv,
                meta.cwd.as_deref(),
                tool_name,
                exact,
            );
        }
        if let Some(ref src) = meta.shell_source {
            // Fingerprint shell source body (not display-split).
            let key = short_digest(&format!("shell\0{src}"));
            return Self {
                key,
                display: src.clone(),
                tool_name: tool_name.map(String::from),
                exact: false,
            };
        }
        Self::from_parts(
            meta.executable.as_deref(),
            &[],
            meta.cwd.as_deref(),
            tool_name,
            false,
        )
    }

    /// Loose family match: same tool_name or same argv\[0\] basename when keys differ.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `same_family` — see module docs for full workflow.
    /// ```
    pub fn same_family(&self, other: &Self) -> bool {
        if self.key == other.key {
            return true;
        }
        match (&self.tool_name, &other.tool_name) {
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => {
                // Same tool — compare first token of display when present.
                first_token(&self.display) == first_token(&other.display)
            }
            _ => {
                first_token(&self.display) == first_token(&other.display)
                    && !first_token(&self.display).is_empty()
            }
        }
    }
}

/// Normalized failure signature for matching retry domains.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FailureSignature {
    /// Key.
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Process exit code, if known.
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Tool name.
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Error type.
    pub error_type: Option<String>,
    /// First meaningful error line (truncated).
    pub message_preview: String,
}

impl FailureSignature {
    /// Build from error event.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_error_event` — see module docs for full workflow.
    /// ```
    pub fn from_error_event(ev: &TraceEvent) -> Self {
        let exit_code = ev
            .metadata
            .get("exit_code")
            .and_then(|v| v.as_i64())
            .map(|c| c as i32);
        let tool_name = ev
            .metadata
            .get("tool_name")
            .and_then(|v| v.as_str())
            .map(String::from);
        let error_type = ev
            .metadata
            .get("error_type")
            .or_else(|| ev.metadata.get("error_kind"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let message = first_error_line(ev);
        let mut canon = String::new();
        if let Some(c) = exit_code {
            canon.push_str(&format!("exit={c};"));
        }
        if let Some(ref t) = tool_name {
            canon.push_str(&format!("tool={t};"));
        }
        if let Some(ref e) = error_type {
            canon.push_str(&format!("type={e};"));
        }
        // Normalize whitespace for message digest
        let norm: String = message.split_whitespace().collect::<Vec<_>>().join(" ");
        let msg_key = short_digest(&norm);
        canon.push_str(&msg_key);
        Self {
            key: short_digest(&canon),
            exit_code,
            tool_name,
            error_type,
            message_preview: message,
        }
    }
}

/// How verification relates to the failure domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VerificationCoverage {
    /// No verification attempt observed.
    #[default]
    None,
    /// Verification ran and failed.
    AttemptedFailed,
    /// Verification passed and matched the failure domain.
    Passed,
    /// A success was observed but fingerprints/domains do not match.
    PassedUnrelatedDomain,
    /// Insufficient signal to classify.
    Unknown,
}

impl VerificationCoverage {
    /// View as str.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `as_str` — see module docs for full workflow.
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::AttemptedFailed => "attempted_failed",
            Self::Passed => "passed",
            Self::PassedUnrelatedDomain => "passed_unrelated_domain",
            Self::Unknown => "unknown",
        }
    }
}

/// Evidence pointer attached to a claim or chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CausalEvidence {
    /// Event id.
    pub event_id: String,
    /// Monotonic sequence number within the run.
    pub sequence: u64,
    /// Role.
    pub role: String,
}

/// Extract tool_use_id / tool_call_id from event metadata.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `tool_correlation_id` — see module docs for full workflow.
/// ```
pub fn tool_correlation_id(ev: &TraceEvent) -> Option<String> {
    for key in ["tool_use_id", "tool_call_id", "call_id", "id"] {
        if let Some(v) = ev.metadata.get(key).and_then(|x| x.as_str()) {
            if !v.is_empty() && key != "id" {
                return Some(v.to_string());
            }
            // Only use bare `id` on tool.call / tool.result kinds.
            if key == "id" && (ev.kind == "tool.call" || ev.kind == "tool.result") {
                // Prefer tool-specific ids; skip UUID-looking event ids by requiring prefix patterns.
                if v.starts_with("tool") || v.starts_with("tu") || v.starts_with("call") {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Extract a command fingerprint from a tool/process event when possible.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `fingerprint_from_event` — see module docs for full workflow.
/// ```
pub fn fingerprint_from_event(ev: &TraceEvent) -> Option<CommandFingerprint> {
    let tool_name = ev.metadata.get("tool_name").and_then(|v| v.as_str());

    if let Some(meta) = CommandMetadata::from_event(ev) {
        return Some(CommandFingerprint::from_command_meta(&meta, tool_name));
    }

    // tool.call input.command (shell string)
    if let Some(cmd) = ev
        .metadata
        .get("input")
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
    {
        let key = short_digest(&format!("shell\0{cmd}"));
        return Some(CommandFingerprint {
            key,
            display: cmd.to_string(),
            tool_name: tool_name.map(String::from),
            exact: false,
        });
    }

    // Bare command string
    if let Some(cmd) = ev.metadata.get("command").and_then(|v| v.as_str()) {
        let key = short_digest(&format!("shell\0{cmd}"));
        return Some(CommandFingerprint {
            key,
            display: cmd.to_string(),
            tool_name: tool_name.map(String::from),
            exact: false,
        });
    }

    // Tool-only fingerprint (e.g. Read without command body)
    if let Some(t) = tool_name {
        let key = short_digest(&format!("tool_only\0{t}"));
        return Some(CommandFingerprint {
            key,
            display: format!("tool:{t}"),
            tool_name: Some(t.to_string()),
            exact: false,
        });
    }

    None
}

/// Find the tool.call that produced a tool.result via tool_use_id or nearest prior call.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `preceding_tool_call` — see module docs for full workflow.
/// ```
pub fn preceding_tool_call(
    events: &[TraceEvent],
    result_idx: usize,
) -> Option<(usize, &TraceEvent)> {
    let result = events.get(result_idx)?;
    if let Some(id) = tool_correlation_id(result) {
        for i in (0..result_idx).rev() {
            let ev = &events[i];
            if ev.kind == "tool.call" && tool_correlation_id(ev).as_deref() == Some(id.as_str()) {
                return Some((i, ev));
            }
        }
    }
    // Nearest prior tool.call (best-effort)
    for i in (0..result_idx).rev() {
        if events[i].kind == "tool.call" {
            return Some((i, &events[i]));
        }
        // Stop if we hit another tool.result (would pair with different call)
        if events[i].kind == "tool.result" {
            break;
        }
    }
    None
}

/// Pair a tool.call with its tool.result.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `matching_tool_result` — see module docs for full workflow.
/// ```
pub fn matching_tool_result(
    events: &[TraceEvent],
    call_idx: usize,
) -> Option<(usize, &TraceEvent)> {
    let call = events.get(call_idx)?;
    if let Some(id) = tool_correlation_id(call) {
        for (i, ev) in events.iter().enumerate().skip(call_idx + 1).take(40) {
            if ev.kind == "tool.result" && tool_correlation_id(ev).as_deref() == Some(id.as_str()) {
                return Some((i, ev));
            }
        }
    }
    for (i, ev) in events.iter().enumerate().skip(call_idx + 1).take(10) {
        if ev.kind == "tool.result" {
            return Some((i, ev));
        }
        if ev.kind == "tool.call" {
            break;
        }
    }
    None
}

/// Build tool_result_of edges for a run (derived analysis).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `build_tool_pairing_edges` — see module docs for full workflow.
/// ```
pub fn build_tool_pairing_edges(events: &[TraceEvent]) -> Vec<CausalEdge> {
    let mut edges = Vec::new();
    for (i, ev) in events.iter().enumerate() {
        if ev.kind != "tool.call" {
            continue;
        }
        if let Some((_, res)) = matching_tool_result(events, i) {
            let mut reasons = vec![];
            if tool_correlation_id(ev).is_some()
                && tool_correlation_id(ev) == tool_correlation_id(res)
            {
                reasons.push("matching_tool_result_id".into());
            } else {
                reasons.push("nearest_tool_result".into());
            }
            let conf = if reasons.iter().any(|r| r == "matching_tool_result_id") {
                Confidence::Confirmed
            } else {
                Confidence::StronglyCorrelated
            };
            edges.push(CausalEdge {
                from_event_id: ev.id.clone(),
                to_event_id: res.id.clone(),
                relation: CausalRelation::ToolResultOf,
                confidence: conf,
                reasons,
            });
        }
    }
    edges
}

/// Decide confidence for a candidate verification.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `confidence_for_verification` — see module docs for full workflow.
/// ```
pub fn confidence_for_verification(
    failure_fp: Option<&CommandFingerprint>,
    verification_fp: Option<&CommandFingerprint>,
    result_linked_by_id: bool,
    result_success: bool,
    had_relevant_edits: bool,
) -> (Confidence, VerificationCoverage, Vec<String>) {
    let mut reasons = Vec::new();
    if !result_success {
        if let Some(vfp) = verification_fp {
            reasons.push("verification_attempted".into());
            let conf = if failure_fp.is_some_and(|f| f.key == vfp.key) {
                Confidence::StronglyCorrelated
            } else {
                Confidence::WeaklyCorrelated
            };
            return (conf, VerificationCoverage::AttemptedFailed, reasons);
        }
        return (Confidence::Unknown, VerificationCoverage::None, reasons);
    }

    let fps_match = match (failure_fp, verification_fp) {
        (Some(a), Some(b)) if a.key == b.key => {
            reasons.push("matching_command_fingerprint".into());
            true
        }
        (Some(a), Some(b)) if a.same_family(b) => {
            reasons.push("same_command_family".into());
            false
        }
        _ => false,
    };

    if result_linked_by_id {
        reasons.push("matching_tool_result_id".into());
    }
    if had_relevant_edits {
        reasons.push("relevant_file_edits".into());
    }

    if fps_match
        && (result_linked_by_id
            || had_relevant_edits
            || verification_fp.map(|f| f.exact) == Some(true)
            || fps_match)
    {
        // Exact fingerprint match + successful result is enough for confirmed
        // when the verification command is the same domain as the failure.
        if fps_match {
            reasons.push("successful_verification".into());
            return (Confidence::Confirmed, VerificationCoverage::Passed, reasons);
        }
    }

    if fps_match {
        reasons.push("successful_verification".into());
        return (Confidence::Confirmed, VerificationCoverage::Passed, reasons);
    }

    if reasons.iter().any(|r| r == "same_command_family") && result_success {
        return (
            Confidence::StronglyCorrelated,
            VerificationCoverage::Passed,
            reasons,
        );
    }

    if result_success && verification_fp.is_some() {
        reasons.push("unrelated_success_nearby".into());
        return (
            Confidence::WeaklyCorrelated,
            VerificationCoverage::PassedUnrelatedDomain,
            reasons,
        );
    }

    if had_relevant_edits {
        return (
            Confidence::WeaklyCorrelated,
            VerificationCoverage::None,
            reasons,
        );
    }

    (Confidence::Unknown, VerificationCoverage::Unknown, reasons)
}

fn short_digest(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let full = hex::encode(hasher.finalize());
    full.chars().take(16).collect()
}

fn basename(p: &str) -> &str {
    p.rsplit(['/', '\\']).next().unwrap_or(p)
}

fn first_token(s: &str) -> String {
    s.split_whitespace()
        .next()
        .map(|t| basename(t).to_string())
        .unwrap_or_default()
}

fn first_error_line(ev: &TraceEvent) -> String {
    let raw = ev
        .metadata
        .get("message")
        .or_else(|| ev.metadata.get("error_message"))
        .or_else(|| ev.metadata.get("stderr"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let line = raw.lines().next().unwrap_or(raw).trim();
    if line.len() > 160 {
        let end = line.floor_char_boundary(160);
        format!("{}…", &line[..end])
    } else if line.is_empty() {
        format!("{:?}", ev.status)
    } else {
        line.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_stable_for_same_argv() {
        let a = CommandFingerprint::from_parts(
            Some("bun"),
            &["bun".into(), "test".into(), "auth".into()],
            None,
            Some("Bash"),
            true,
        );
        let b = CommandFingerprint::from_parts(
            Some("bun"),
            &["bun".into(), "test".into(), "auth".into()],
            None,
            Some("Bash"),
            true,
        );
        assert_eq!(a.key, b.key);
    }

    #[test]
    fn fingerprint_differs_for_different_commands() {
        let a = CommandFingerprint::from_parts(
            None,
            &["bun".into(), "test".into(), "auth".into()],
            None,
            None,
            true,
        );
        let b =
            CommandFingerprint::from_parts(None, &["echo".into(), "hi".into()], None, None, true);
        assert_ne!(a.key, b.key);
        assert!(!a.same_family(&b));
    }

    #[test]
    fn confirmed_requires_matching_fingerprint() {
        let fail = CommandFingerprint::from_parts(
            None,
            &["bun".into(), "test".into(), "auth".into()],
            None,
            Some("Bash"),
            true,
        );
        let verify = fail.clone();
        let (c, cov, reasons) =
            confidence_for_verification(Some(&fail), Some(&verify), true, true, true);
        assert_eq!(c, Confidence::Confirmed);
        assert_eq!(cov, VerificationCoverage::Passed);
        assert!(reasons.iter().any(|r| r.contains("fingerprint")));
    }

    #[test]
    fn unrelated_success_is_not_confirmed() {
        let fail = CommandFingerprint::from_parts(
            None,
            &["bun".into(), "test".into(), "auth".into()],
            None,
            Some("Bash"),
            true,
        );
        let other = CommandFingerprint::from_parts(
            None,
            &["echo".into(), "hi".into()],
            None,
            Some("Bash"),
            true,
        );
        let (c, cov, _) = confidence_for_verification(Some(&fail), Some(&other), true, true, true);
        assert_ne!(c, Confidence::Confirmed);
        assert_eq!(cov, VerificationCoverage::PassedUnrelatedDomain);
    }

    #[test]
    fn confidence_as_str_snake_case() {
        assert_eq!(Confidence::Confirmed.as_str(), "confirmed");
        assert_eq!(
            Confidence::StronglyCorrelated.as_str(),
            "strongly_correlated"
        );
    }
}
