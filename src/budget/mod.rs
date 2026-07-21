//! Controlled execution budgets with capability classification (1.6 Phase F).

pub mod policy;
pub mod report;

pub use policy::{BudgetCapability, BudgetPolicy, BudgetStatus};
pub use report::{evaluate_budgets, BudgetBreach, BudgetReport, ObservedBudgets};
