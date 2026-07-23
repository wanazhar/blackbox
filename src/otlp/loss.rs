//! Explicit semantic loss ledger for OTLP round-trips.

use serde::{Deserialize, Serialize};

/// Schema for loss ledgers.
pub const OTLP_LOSS_SCHEMA: &str = "blackbox.otlp.loss/v1";

/// One concept that could not be represented faithfully in OTLP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossEntry {
    /// Blackbox concept id (e.g. `security.decision.integrity`).
    pub concept: String,
    /// Why it was lost or degraded.
    pub reason: String,
    /// Optional related event/object id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
}

/// Deterministic ledger of semantic losses during export/import.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossLedger {
    /// Schema.
    pub schema: String,
    /// Direction: export | import.
    pub direction: String,
    /// Losses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub losses: Vec<LossEntry>,
}

impl LossLedger {
    /// New empty ledger.
    pub fn new(direction: impl Into<String>) -> Self {
        Self {
            schema: OTLP_LOSS_SCHEMA.into(),
            direction: direction.into(),
            losses: vec![],
        }
    }

    /// Record a loss.
    pub fn push(
        &mut self,
        concept: impl Into<String>,
        reason: impl Into<String>,
        object_id: Option<String>,
    ) {
        self.losses.push(LossEntry {
            concept: concept.into(),
            reason: reason.into(),
            object_id,
        });
    }

    /// True when any loss was recorded.
    pub fn has_losses(&self) -> bool {
        !self.losses.is_empty()
    }
}
