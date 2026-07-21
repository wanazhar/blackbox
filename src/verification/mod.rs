//! Verification receipts: separate execution, verification, and capture (1.6 Phase C).

pub mod command;
pub mod junit;
pub mod outcome;
pub mod receipt;
pub mod tap;

pub use command::verify_command;
pub use junit::{parse_junit_xml, receipt_from_junit};
pub use outcome::{
    build_outcome_view, CaptureStatus, ExecutionStatus, RunOutcomeView,
};
pub use receipt::{
    VerificationConfidence, VerificationReceipt, VerificationStatus, VerifierType,
};
pub use tap::{parse_tap, receipt_from_tap};
