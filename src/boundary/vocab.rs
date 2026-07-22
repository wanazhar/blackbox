//! Stable vocabularies for boundary contracts (`blackbox.boundary/v1`).
//!
//! Tokens are lowercase snake_case strings. Well-known constants are provided
//! for common cases; unknown tokens are preserved as free-form strings so
//! future tools and harnesses do not require a binary upgrade.

use serde::{Deserialize, Serialize};

/// How a capability/effect is treated when evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Hard denial; fail-closed when evidence confirms the effect.
    HardProhibition,
    /// Allowed only with explicit prior approval evidence.
    ApprovalRequired,
    /// Explicitly allowed under the resolved contract.
    Allowed,
    /// May appear in telemetry; not authorized as intentional action.
    ObservedOnly,
    /// No disposition declared; treated as unknown at evaluation time.
    Unknown,
}

impl Disposition {
    /// Stable snake_case string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HardProhibition => "hard_prohibition",
            Self::ApprovalRequired => "approval_required",
            Self::Allowed => "allowed",
            Self::ObservedOnly => "observed_only",
            Self::Unknown => "unknown",
        }
    }

    /// Parse a disposition token; unknown → [`Disposition::Unknown`].
    pub fn parse(s: &str) -> Self {
        match s {
            "hard_prohibition" | "prohibited" | "deny" => Self::HardProhibition,
            "approval_required" | "requires_approval" => Self::ApprovalRequired,
            "allowed" | "allow" | "permit" => Self::Allowed,
            "observed_only" | "observe" => Self::ObservedOnly,
            _ => Self::Unknown,
        }
    }
}

/// Canonical disposition vocabulary (for docs and validate).
pub const BOUNDARY_DISPOSITIONS: &[&str] = &[
    "hard_prohibition",
    "approval_required",
    "allowed",
    "observed_only",
    "unknown",
];

// ── Token newtypes (string-backed for forward compatibility) ─────────

macro_rules! token_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            /// Create from any string-like value.
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            /// Borrow the underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

token_type!(
    /// Network destination, host pattern, or network class token.
    ///
    /// Well-known: `public_network`, `package_proxy`, `local_only`, `dns`, …
    CapabilityToken
);

token_type!(
    /// Side-effect class token.
    ///
    /// Well-known: `workspace_write`, `credential_read`, `process_spawn`,
    /// `network_connect`, `persistence`, `privilege_escalation`, …
    EffectToken
);

token_type!(
    /// Principal / identity class.
    ///
    /// Well-known: `eval_workload`, `ci_runner`, `developer_workstation`,
    /// `production_credentials`, …
    IdentityToken
);

token_type!(
    /// Target system or range.
    ///
    /// Well-known: `local_range`, `localhost`, `kubernetes_cluster`,
    /// `external_organizations`, `production`, …
    TargetToken
);

token_type!(
    /// Data classification token.
    ///
    /// Well-known: `synthetic`, `public`, `internal`, `secret`, `pii`, …
    DataClassToken
);

token_type!(
    /// Provenance / answer-source class.
    ///
    /// Well-known: `declared_dataset`, `undeclared_answer_sources`,
    /// `model_weights`, `retrieved_content`, `human_provided`, …
    ProvenanceToken
);

/// Well-known capability / prohibition tokens used in docs and fixtures.
pub mod well_known {
    /// Public Internet egress.
    pub const PUBLIC_NETWORK: &str = "public_network";
    /// Production credential material.
    pub const PRODUCTION_CREDENTIALS: &str = "production_credentials";
    /// Contact with orgs outside the declared evaluation set.
    pub const EXTERNAL_ORGANIZATIONS: &str = "external_organizations";
    /// Benchmark answers obtained outside declared paths.
    pub const UNDECLARED_ANSWER_SOURCES: &str = "undeclared_answer_sources";
    /// Package manager / build-system install.
    pub const PACKAGE_INSTALL: &str = "package_install";
    /// Local evaluation network range.
    pub const LOCAL_RANGE: &str = "local_range";
    /// Synthetic / non-sensitive data class.
    pub const SYNTHETIC: &str = "synthetic";
    /// Eval workload identity.
    pub const EVAL_WORKLOAD: &str = "eval_workload";

    /// All well-known tokens (for docs / validate hints).
    pub const ALL: &[&str] = &[
        PUBLIC_NETWORK,
        PRODUCTION_CREDENTIALS,
        EXTERNAL_ORGANIZATIONS,
        UNDECLARED_ANSWER_SOURCES,
        PACKAGE_INSTALL,
        LOCAL_RANGE,
        SYNTHETIC,
        EVAL_WORKLOAD,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_roundtrip() {
        for d in [
            Disposition::HardProhibition,
            Disposition::ApprovalRequired,
            Disposition::Allowed,
            Disposition::ObservedOnly,
            Disposition::Unknown,
        ] {
            assert_eq!(Disposition::parse(d.as_str()), d);
        }
    }

    #[test]
    fn disposition_aliases() {
        assert_eq!(Disposition::parse("deny"), Disposition::HardProhibition);
        assert_eq!(Disposition::parse("allow"), Disposition::Allowed);
        assert_eq!(Disposition::parse("nonsense"), Disposition::Unknown);
    }

    #[test]
    fn well_known_tokens_nonempty() {
        assert!(well_known::ALL.contains(&well_known::PUBLIC_NETWORK));
        assert!(!well_known::ALL.is_empty());
    }
}
