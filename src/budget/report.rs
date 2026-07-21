//! Budget evaluation against observed run metrics.

use serde::{Deserialize, Serialize};

use crate::budget::policy::{BudgetCapability, BudgetPolicy, BudgetStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `BudgetBreach` value.
pub struct BudgetBreach {
    /// Display name.
    pub name: String,
    /// Configured limit, if any.
    pub limit: u64,
    /// Observed value, if any.
    pub observed: u64,
    /// Capability.
    pub capability: BudgetCapability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `BudgetReport` value.
pub struct BudgetReport {
    /// Schema identifier string.
    pub schema: String,
    /// Capabilities.
    pub capabilities: Vec<BudgetStatus>,
    /// Breaches.
    pub breaches: Vec<BudgetBreach>,
    /// True when an enforced budget was exceeded.
    pub terminated_by_budget: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Breach reason.
    pub breach_reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
/// `ObservedBudgets` value.
pub struct ObservedBudgets {
    /// Wall secs.
    pub wall_secs: Option<u64>,
    /// Processes.
    pub processes: Option<u64>,
    /// Output bytes.
    pub output_bytes: Option<u64>,
    /// Store growth bytes.
    pub store_growth_bytes: Option<u64>,
    /// Tool calls.
    pub tool_calls: Option<u64>,
    /// Tokens.
    pub tokens: Option<u64>,
}

/// Compare configured limits against observed values.
///
/// Enforced limits that are exceeded set [`BudgetReport::terminated_by_budget`].
///
/// # Examples
///
/// ```
/// use blackbox::budget::{evaluate_budgets, BudgetCapability, BudgetPolicy, ObservedBudgets};
///
/// let policy = BudgetPolicy {
///     max_wall_secs: Some(30),
///     ..Default::default()
/// };
/// let report = evaluate_budgets(
///     &policy,
///     &ObservedBudgets {
///         wall_secs: Some(45),
///         ..Default::default()
///     },
/// );
/// assert!(report.terminated_by_budget);
/// assert!(report.breaches.iter().any(|b| b.name == "wall_time"));
/// assert!(matches!(
///     report.capabilities.iter().find(|c| c.name == "wall_time").unwrap().capability,
///     BudgetCapability::Enforced
/// ));
/// ```
pub fn evaluate_budgets(policy: &BudgetPolicy, observed: &ObservedBudgets) -> BudgetReport {
    let mut capabilities = policy.capability_report();
    // Fill observed values
    for c in &mut capabilities {
        c.observed = match c.name.as_str() {
            "wall_time" => observed.wall_secs,
            "process_count" => observed.processes,
            "output_bytes" => observed.output_bytes,
            "store_growth" => observed.store_growth_bytes,
            "tool_calls" => observed.tool_calls,
            "tokens" => observed.tokens,
            _ => None,
        };
    }

    let mut breaches = Vec::new();
    for c in &capabilities {
        if let (Some(limit), Some(obs)) = (c.limit, c.observed) {
            if obs > limit {
                breaches.push(BudgetBreach {
                    name: c.name.clone(),
                    limit,
                    observed: obs,
                    capability: c.capability,
                });
            }
        }
    }

    let enforced_breach = breaches
        .iter()
        .find(|b| matches!(b.capability, BudgetCapability::Enforced));

    BudgetReport {
        schema: "blackbox.budget.report/v1".into(),
        capabilities,
        terminated_by_budget: enforced_breach.is_some(),
        breach_reason: enforced_breach.map(|b| {
            format!(
                "enforced budget {} exceeded: {} > {}",
                b.name, b.observed, b.limit
            )
        }),
        breaches,
    }
}
