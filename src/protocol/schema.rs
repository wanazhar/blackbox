//! Protocol schema identifiers and object catalog.

use serde::{Deserialize, Serialize};

/// Protocol major version string for documentation and conformance banners.
pub const PROTOCOL_VERSION: &str = "1.9.0";

/// Stable schema identifier (`blackbox.<domain>[.<sub>]/vN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaId {
    /// Full schema id string.
    pub id: &'static str,
    /// Human-readable object kind.
    pub kind: ProtocolObjectKind,
    /// Stability of this schema surface.
    pub stability: crate::protocol::stability::SurfaceClass,
}

/// High-level object families in the evidence protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolObjectKind {
    /// Recorded run lifecycle.
    Run,
    /// Trace event within a run.
    Event,
    /// External evidence event.
    EvidenceEvent,
    /// Boundary contract / resolution.
    Boundary,
    /// Verification or security receipt.
    Receipt,
    /// Calibrated finding.
    Finding,
    /// Multi-run incident.
    Incident,
    /// Forensic pack.
    ForensicPack,
    /// Security decision.
    SecurityDecision,
    /// Evidence commitment / run root.
    Commitment,
    /// Portable archive envelope.
    Portable,
    /// Conformance report.
    Conformance,
    /// Other protocol object.
    Other,
}

/// Catalog of published protocol schema ids for 1.9.
pub static SCHEMA_CATALOG: &[SchemaId] = &[
    SchemaId {
        id: "blackbox.run/v1",
        kind: ProtocolObjectKind::Run,
        stability: crate::protocol::stability::SurfaceClass::Stable,
    },
    SchemaId {
        id: "blackbox.event/v1",
        kind: ProtocolObjectKind::Event,
        stability: crate::protocol::stability::SurfaceClass::Stable,
    },
    SchemaId {
        id: "blackbox.evidence.event/v1",
        kind: ProtocolObjectKind::EvidenceEvent,
        stability: crate::protocol::stability::SurfaceClass::Stable,
    },
    SchemaId {
        id: "blackbox.boundary/v1",
        kind: ProtocolObjectKind::Boundary,
        stability: crate::protocol::stability::SurfaceClass::Stable,
    },
    SchemaId {
        id: "blackbox.boundary.finding/v1",
        kind: ProtocolObjectKind::Finding,
        stability: crate::protocol::stability::SurfaceClass::Stable,
    },
    SchemaId {
        id: "blackbox.boundary.finding.decision/v1",
        kind: ProtocolObjectKind::Finding,
        stability: crate::protocol::stability::SurfaceClass::Stable,
    },
    SchemaId {
        id: "blackbox.containment.receipt/v1",
        kind: ProtocolObjectKind::Receipt,
        stability: crate::protocol::stability::SurfaceClass::Stable,
    },
    SchemaId {
        id: "blackbox.verification.receipt/v1",
        kind: ProtocolObjectKind::Receipt,
        stability: crate::protocol::stability::SurfaceClass::Stable,
    },
    SchemaId {
        id: "blackbox.incident/v1",
        kind: ProtocolObjectKind::Incident,
        stability: crate::protocol::stability::SurfaceClass::Stable,
    },
    SchemaId {
        id: "blackbox.forensic.pack/v1",
        kind: ProtocolObjectKind::ForensicPack,
        stability: crate::protocol::stability::SurfaceClass::Stable,
    },
    SchemaId {
        id: "blackbox.security.decision/v1",
        kind: ProtocolObjectKind::SecurityDecision,
        stability: crate::protocol::stability::SurfaceClass::Provisional,
    },
    SchemaId {
        id: "blackbox.commitment.run/v1",
        kind: ProtocolObjectKind::Commitment,
        stability: crate::protocol::stability::SurfaceClass::Provisional,
    },
    SchemaId {
        id: "blackbox.reconcile.outcome/v1",
        kind: ProtocolObjectKind::Other,
        stability: crate::protocol::stability::SurfaceClass::Provisional,
    },
    SchemaId {
        id: "blackbox.portable/v2",
        kind: ProtocolObjectKind::Portable,
        stability: crate::protocol::stability::SurfaceClass::Stable,
    },
    SchemaId {
        id: "blackbox.conformance.report/v1",
        kind: ProtocolObjectKind::Conformance,
        stability: crate::protocol::stability::SurfaceClass::Provisional,
    },
    SchemaId {
        id: "blackbox.native.ingest/v1",
        kind: ProtocolObjectKind::Other,
        stability: crate::protocol::stability::SurfaceClass::Provisional,
    },
    SchemaId {
        id: "blackbox.otlp.loss/v1",
        kind: ProtocolObjectKind::Other,
        stability: crate::protocol::stability::SurfaceClass::Experimental,
    },
];

/// Look up a schema id in the catalog.
pub fn find_schema(id: &str) -> Option<&'static SchemaId> {
    SCHEMA_CATALOG.iter().find(|s| s.id == id)
}

/// Whether `id` is a known published schema.
pub fn is_known_schema(id: &str) -> bool {
    find_schema(id).is_some()
}
