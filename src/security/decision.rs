//! `blackbox.security.decision/v1` security decision receipts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::action::ActionFingerprint;
use crate::protocol::canonical_hash;

/// Schema identifier.
pub const SECURITY_DECISION_SCHEMA: &str = "blackbox.security.decision/v1";

/// Allow / deny / warn / require_approval.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// Action permitted.
    Allow,
    /// Action denied.
    Deny,
    /// Action allowed with warning.
    Warn,
    /// Must wait for human/agent approval.
    RequireApproval,
    /// Decision could not be determined.
    #[default]
    Unknown,
}

impl DecisionKind {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Warn => "warn",
            Self::RequireApproval => "require_approval",
            Self::Unknown => "unknown",
        }
    }
}

/// Integrity class for a decision receipt.
///
/// Self-asserted `signed_verified` is demoted to `unverified` unless a
/// verifier is configured on the consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionIntegrity {
    /// No integrity proof.
    Unverified,
    /// Payload hash matches.
    HashOk,
    /// Signature verified by a configured verifier.
    SignedVerified,
    /// Signature present but invalid.
    SignedInvalid,
}

impl Default for DecisionIntegrity {
    fn default() -> Self {
        Self::Unverified
    }
}

impl DecisionIntegrity {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::HashOk => "hash_ok",
            Self::SignedVerified => "signed_verified",
            Self::SignedInvalid => "signed_invalid",
        }
    }

    /// Demote self-asserted verified claims without a configured verifier.
    pub fn demote_untrusted(self, verifier_configured: bool) -> Self {
        match self {
            Self::SignedVerified if !verifier_configured => Self::Unverified,
            other => other,
        }
    }
}

/// Who acknowledged a warn / require_approval decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgementActor {
    /// Human operator.
    User,
    /// Agent / harness self-ack.
    Agent,
    /// Automated policy system.
    Policy,
    /// Other.
    Other,
}

/// Acknowledgement of a warn or require_approval decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Acknowledgement {
    /// Who acknowledged.
    pub actor: AcknowledgementActor,
    /// When.
    pub at: DateTime<Utc>,
    /// Optional note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Policy override distinct from acknowledgement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverrideInfo {
    /// Who overrode.
    pub actor: String,
    /// Reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When.
    pub at: DateTime<Utc>,
}

/// External security decision receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityDecision {
    /// Schema id.
    pub schema: String,
    /// Unique decision id.
    pub id: String,
    /// Owning run when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Provider (tirith, opa, cedar, falco, harness, admission, dlp, human, mcp_gateway, …).
    pub provider: String,
    /// Decision outcome.
    pub decision: DecisionKind,
    /// SHA-256 of canonical action fingerprint.
    pub action_hash: String,
    /// Optional embedded fingerprint for offline matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionFingerprint>,
    /// Policy document hash when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    /// Rule identifiers that fired.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_ids: Vec<String>,
    /// Principal / workload identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    /// Policy override (distinct from ack).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_info: Option<OverrideInfo>,
    /// Acknowledgement of warn / require_approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledgement: Option<Acknowledgement>,
    /// Decision timestamp.
    pub decided_at: DateTime<Utc>,
    /// Integrity class (post-demotion when ingested).
    #[serde(default)]
    pub integrity: DecisionIntegrity,
    /// Evidence references (event ids, external evidence ids).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    /// Free-form attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Value>,
}

impl SecurityDecision {
    /// Builder from required fields.
    pub fn builder(
        provider: impl Into<String>,
        decision: DecisionKind,
        action_hash: impl Into<String>,
    ) -> SecurityDecisionBuilder {
        SecurityDecisionBuilder {
            provider: provider.into(),
            decision,
            action_hash: action_hash.into(),
            ..Default::default()
        }
    }

    /// Normalize integrity on ingest (demote untrusted signed_verified).
    pub fn normalize_integrity(&mut self, verifier_configured: bool) {
        self.integrity = self.integrity.demote_untrusted(verifier_configured);
    }

    /// Validate the receipt and normalize claims that require local trust.
    ///
    /// A producer cannot upgrade its own integrity merely by serializing
    /// `signed_verified`; callers pass `verifier_configured = true` only after
    /// verification through a configured trust path.
    pub fn validate_and_normalize(&mut self, verifier_configured: bool) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.schema != SECURITY_DECISION_SCHEMA {
            errors.push(format!("unsupported schema: {}", self.schema));
        }
        if self.id.is_empty() {
            errors.push("id is required".into());
        }
        if self.provider.trim().is_empty() {
            errors.push("provider is required".into());
        }
        if !is_lower_sha256(&self.action_hash) {
            errors.push("action_hash must be 64 lowercase hex characters".into());
        }
        if let Some(action) = &self.action {
            let computed = action.hash();
            if computed != self.action_hash {
                errors.push(format!(
                    "action_hash does not match normalized action: expected {computed}"
                ));
            }
        }
        if self
            .policy_hash
            .as_deref()
            .is_some_and(|hash| !is_lower_sha256(hash))
        {
            errors.push("policy_hash must be 64 lowercase hex characters".into());
        }
        self.normalize_integrity(verifier_configured);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Canonical hash of the decision body (excluding transport).
    pub fn content_hash(&self) -> anyhow::Result<String> {
        let v = serde_json::to_value(self)?;
        Ok(canonical_hash(&v)?)
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Fluent builder for [`SecurityDecision`].
#[derive(Debug, Default)]
pub struct SecurityDecisionBuilder {
    provider: String,
    decision: DecisionKind,
    action_hash: String,
    run_id: Option<String>,
    action: Option<ActionFingerprint>,
    policy_hash: Option<String>,
    rule_ids: Vec<String>,
    identity: Option<Value>,
    override_info: Option<OverrideInfo>,
    acknowledgement: Option<Acknowledgement>,
    decided_at: Option<DateTime<Utc>>,
    integrity: Option<DecisionIntegrity>,
    evidence_refs: Vec<String>,
    attributes: Option<Value>,
    id: Option<String>,
}

impl SecurityDecisionBuilder {
    /// Set run id.
    pub fn run_id(mut self, id: impl Into<String>) -> Self {
        self.run_id = Some(id.into());
        self
    }
    /// Embed action fingerprint.
    pub fn action(mut self, action: ActionFingerprint) -> Self {
        self.action_hash = action.hash();
        self.action = Some(action);
        self
    }
    /// Policy hash.
    pub fn policy_hash(mut self, h: impl Into<String>) -> Self {
        self.policy_hash = Some(h.into());
        self
    }
    /// Rule ids.
    pub fn rule_ids(mut self, ids: Vec<String>) -> Self {
        self.rule_ids = ids;
        self
    }
    /// Integrity claim (will still be demoted on ingest if unverified).
    pub fn integrity(mut self, i: DecisionIntegrity) -> Self {
        self.integrity = Some(i);
        self
    }
    /// Acknowledgement.
    pub fn acknowledgement(mut self, a: Acknowledgement) -> Self {
        self.acknowledgement = Some(a);
        self
    }
    /// Override.
    pub fn override_info(mut self, o: OverrideInfo) -> Self {
        self.override_info = Some(o);
        self
    }
    /// Evidence refs.
    pub fn evidence_refs(mut self, refs: Vec<String>) -> Self {
        self.evidence_refs = refs;
        self
    }
    /// Fixed id.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }
    /// Build the decision.
    pub fn build(self) -> SecurityDecision {
        SecurityDecision {
            schema: SECURITY_DECISION_SCHEMA.into(),
            id: self.id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            run_id: self.run_id,
            provider: self.provider,
            decision: self.decision,
            action_hash: self.action_hash,
            action: self.action,
            policy_hash: self.policy_hash,
            rule_ids: self.rule_ids,
            identity: self.identity,
            override_info: self.override_info,
            acknowledgement: self.acknowledgement,
            decided_at: self.decided_at.unwrap_or_else(Utc::now),
            integrity: self.integrity.unwrap_or(DecisionIntegrity::Unverified),
            evidence_refs: self.evidence_refs,
            attributes: self.attributes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::action::ActionFingerprint;

    #[test]
    fn demote_signed_without_verifier() {
        let mut d = SecurityDecision::builder("opa", DecisionKind::Deny, "aa".repeat(32))
            .integrity(DecisionIntegrity::SignedVerified)
            .build();
        d.normalize_integrity(false);
        assert_eq!(d.integrity, DecisionIntegrity::Unverified);

        let mut d2 = d.clone();
        d2.integrity = DecisionIntegrity::SignedVerified;
        d2.normalize_integrity(true);
        assert_eq!(d2.integrity, DecisionIntegrity::SignedVerified);
    }

    #[test]
    fn action_hash_from_fingerprint() {
        let fp = ActionFingerprint::process_exec(&["curl".into(), "x".into()], None);
        let d = SecurityDecision::builder("harness", DecisionKind::Allow, "")
            .action(fp.clone())
            .build();
        assert_eq!(d.action_hash, fp.hash());
        assert_eq!(d.schema, SECURITY_DECISION_SCHEMA);
    }
}
