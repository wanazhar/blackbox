//! Budget evaluation against observed run metrics.

use serde::{Deserialize, Serialize};

use crate::budget::policy::{BudgetCapability, BudgetPolicy, BudgetStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetBreach {
    pub name: String,
    pub limit: u64,
    pub observed: u64,
    pub capability: BudgetCapability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetReport {
    pub schema: String,
    pub capabilities: Vec<BudgetStatus>,
    pub breaches: Vec<BudgetBreach>,
    /// True when an enforced budget was exceeded.
    pub terminated_by_budget: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breach_reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ObservedBudgets {
    pub wall_secs: Option<u64>,
    pub processes: Option<u64>,
    pub output_bytes: Option<u64>,
    pub store_growth_bytes: Option<u64>,
    pub tool_calls: Option<u64>,
    pub tokens: Option<u64>,
}

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
