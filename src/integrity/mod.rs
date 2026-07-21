//! Store integrity: fsck, repair planning, and structured reports (1.6 Phase B).

pub mod fsck;
pub mod repair;
pub mod report;

pub use fsck::{fsck_store, FsckMode, FsckOptions};
pub use repair::{apply_repair_plan, plan_repairs};
pub use report::{FsckFinding, FsckReport, FsckSeverity, RepairAction, RepairPlan};
