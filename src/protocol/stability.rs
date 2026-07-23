//! Public surface stability inventory (1.9).
//!
//! Classifications:
//! - **stable** — semantic changes require a major version bump or a new `/vN` schema id
//! - **provisional** — may change in a minor release; documented migration path required
//! - **experimental** — may change or be removed without notice; not for production contracts
//! - **internal** — not a public protocol surface; may change freely

use serde::{Deserialize, Serialize};

/// Stability class for a public or internal surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceClass {
    /// Backward-compatible within major; new schema id for breaks.
    Stable,
    /// May change in minor; migration documented.
    Provisional,
    /// Unstable; no compatibility promise.
    Experimental,
    /// Not public API / not protocol.
    Internal,
}

impl SurfaceClass {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Provisional => "provisional",
            Self::Experimental => "experimental",
            Self::Internal => "internal",
        }
    }
}

/// One inventoried surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SurfaceEntry {
    /// Dot-path or schema id.
    pub name: &'static str,
    /// Stability class.
    pub class: SurfaceClass,
    /// Short description.
    pub notes: &'static str,
}

/// Inventory of externally serialized or library-visible surfaces for 1.9.
pub static SURFACE_INVENTORY: &[SurfaceEntry] = &[
    // ── Protocol schemas ──────────────────────────────────────────────
    SurfaceEntry {
        name: "blackbox.run/v1",
        class: SurfaceClass::Stable,
        notes: "Run record fields used in portable export and native ingest",
    },
    SurfaceEntry {
        name: "blackbox.event/v1",
        class: SurfaceClass::Stable,
        notes: "TraceEvent wire form for portable and native ingest",
    },
    SurfaceEntry {
        name: "blackbox.evidence.event/v1",
        class: SurfaceClass::Stable,
        notes: "External evidence NDJSON event",
    },
    SurfaceEntry {
        name: "blackbox.boundary/v1",
        class: SurfaceClass::Stable,
        notes: "Boundary contract",
    },
    SurfaceEntry {
        name: "blackbox.boundary.finding/v1",
        class: SurfaceClass::Stable,
        notes: "Boundary finding with calibrated decision (1.8)",
    },
    SurfaceEntry {
        name: "blackbox.verification.receipt/v1",
        class: SurfaceClass::Stable,
        notes: "Immutable verification receipt",
    },
    SurfaceEntry {
        name: "blackbox.containment.receipt/v1",
        class: SurfaceClass::Stable,
        notes: "Containment honesty receipt",
    },
    SurfaceEntry {
        name: "blackbox.incident/v1",
        class: SurfaceClass::Stable,
        notes: "Multi-run incident object",
    },
    SurfaceEntry {
        name: "blackbox.forensic.pack/v1",
        class: SurfaceClass::Stable,
        notes: "Forensic pack with citation-complete selection",
    },
    SurfaceEntry {
        name: "blackbox.portable/v2",
        class: SurfaceClass::Stable,
        notes: "Portable archive envelope",
    },
    SurfaceEntry {
        name: "blackbox.cli/v1",
        class: SurfaceClass::Stable,
        notes: "CLI JSON envelope",
    },
    SurfaceEntry {
        name: "blackbox.score/v1",
        class: SurfaceClass::Stable,
        notes: "Eval score.json",
    },
    SurfaceEntry {
        name: "blackbox.security.decision/v1",
        class: SurfaceClass::Provisional,
        notes: "External security decision receipt (1.9)",
    },
    SurfaceEntry {
        name: "blackbox.commitment.run/v1",
        class: SurfaceClass::Provisional,
        notes: "Run evidence commitment chain (1.9)",
    },
    SurfaceEntry {
        name: "blackbox.reconcile.outcome/v1",
        class: SurfaceClass::Provisional,
        notes: "Action-to-effect reconciliation outcome (1.9)",
    },
    SurfaceEntry {
        name: "blackbox.native.ingest/v1",
        class: SurfaceClass::Provisional,
        notes: "Native ingestion envelope (1.9)",
    },
    SurfaceEntry {
        name: "blackbox.conformance.report/v1",
        class: SurfaceClass::Provisional,
        notes: "Conformance runner report (1.9)",
    },
    SurfaceEntry {
        name: "blackbox.otlp.loss/v1",
        class: SurfaceClass::Experimental,
        notes: "OTLP semantic loss ledger (1.9)",
    },
    // ── Library APIs ──────────────────────────────────────────────────
    SurfaceEntry {
        name: "blackbox::protocol",
        class: SurfaceClass::Provisional,
        notes: "Canonical form, schema catalog, validation",
    },
    SurfaceEntry {
        name: "blackbox::native",
        class: SurfaceClass::Provisional,
        notes: "In-process native recorder API",
    },
    SurfaceEntry {
        name: "blackbox::security",
        class: SurfaceClass::Provisional,
        notes: "Security decisions and reconciliation",
    },
    SurfaceEntry {
        name: "blackbox::commitment",
        class: SurfaceClass::Provisional,
        notes: "Hash chain and optional signatures",
    },
    SurfaceEntry {
        name: "blackbox::otlp",
        class: SurfaceClass::Experimental,
        notes: "OTLP export/import foundation",
    },
    SurfaceEntry {
        name: "blackbox::conformance",
        class: SurfaceClass::Provisional,
        notes: "Conformance profiles and runner",
    },
    SurfaceEntry {
        name: "blackbox::storage::TraceStore",
        class: SurfaceClass::Provisional,
        notes: "Internal storage trait; not part of wire protocol",
    },
    SurfaceEntry {
        name: "blackbox::cli",
        class: SurfaceClass::Internal,
        notes: "clap CLI types — not protocol",
    },
    SurfaceEntry {
        name: "blackbox::storage::sqlite",
        class: SurfaceClass::Internal,
        notes: "SQLite backend — not protocol",
    },
];

/// Entries with a given stability class.
pub fn surfaces_with_class(class: SurfaceClass) -> impl Iterator<Item = &'static SurfaceEntry> {
    SURFACE_INVENTORY.iter().filter(move |e| e.class == class)
}
