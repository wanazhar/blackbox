//! Reproducibility capsules with explicit completeness classes (1.6 Phase E).

pub mod create;
pub mod inspect;

pub use create::{create_capsule, CapsuleCreateOpts};
pub use create::{CapsuleCompleteness, CapsuleManifest, TransformationEntry};
pub use inspect::{inspect_capsule, verify_capsule_integrity, CapsuleInspectReport};
