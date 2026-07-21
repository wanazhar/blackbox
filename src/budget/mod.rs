//! Controlled execution budgets with capability classification (1.6 Phase F).

pub mod cgroup;
pub mod linux;
pub mod policy;
pub mod report;

pub use cgroup::{cgroup_v2_memory_writable, CgroupApplyReport, CgroupScope};
pub use linux::{
    apply_child_rlimits, count_descendant_processes, kill_budget_pid, linux_enforcement_status,
    linux_enforcement_status_with_cgroup, spawn_process_count_watchdog, spawn_wall_watchdog,
    BudgetBreachKill,
};
pub use policy::{BudgetCapability, BudgetPolicy, BudgetStatus};
pub use report::{evaluate_budgets, BudgetBreach, BudgetReport, ObservedBudgets};
