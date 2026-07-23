//! Security decision receipts and action↔effect reconciliation (1.9).
//!
//! Decision evidence is distinct from runtime observation. Self-asserted
//! `signed_verified` integrity is demoted without a configured verifier.

pub mod action;
pub mod decision;
pub mod reconcile;

pub use action::{action_fingerprint, ActionFingerprint, ActionKind};
pub use decision::{
    Acknowledgement, AcknowledgementActor, DecisionIntegrity, DecisionKind, OverrideInfo,
    SecurityDecision, SecurityDecisionBuilder, SECURITY_DECISION_SCHEMA,
};
pub use reconcile::{
    reconcile_run, ObservedEffect, ObservedExecution, ReconcileCitation, ReconcileInput,
    ReconcileOutcome, ReconcileOutcomeKind, RECONCILE_OUTCOME_SCHEMA,
};
