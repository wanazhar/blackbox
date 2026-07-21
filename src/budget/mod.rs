//! Controlled execution budgets with capability classification (1.6 Phase F).

pub mod linux;
pub mod policy;
pub mod report;

pub use linux::{
    apply_process_rlimits, linux_enforcement_status, spawn_process_count_watchdog,
    spawn_wall_watchdog, BudgetBreachKill,
};
pub use policy::{BudgetCapability, BudgetPolicy, BudgetStatus};
pub use report::{evaluate_budgets, BudgetBreach, BudgetReport, ObservedBudgets};
