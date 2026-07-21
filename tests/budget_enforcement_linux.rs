//! 1.6 F: budget capabilities never over-claim enforcement.

use blackbox::budget::{evaluate_budgets, BudgetCapability, BudgetPolicy, ObservedBudgets};

#[test]
fn unsupported_token_budget_is_observed_only() {
    let policy = BudgetPolicy {
        max_tokens: Some(1000),
        max_wall_secs: Some(30),
        ..Default::default()
    };
    let report = evaluate_budgets(
        &policy,
        &ObservedBudgets {
            wall_secs: Some(10),
            tokens: Some(50),
            ..Default::default()
        },
    );
    let tokens = report
        .capabilities
        .iter()
        .find(|c| c.name == "tokens")
        .unwrap();
    assert!(matches!(tokens.capability, BudgetCapability::ObservedOnly));
    let wall = report
        .capabilities
        .iter()
        .find(|c| c.name == "wall_time")
        .unwrap();
    assert!(matches!(wall.capability, BudgetCapability::Enforced));
    assert!(!report.terminated_by_budget);
}

#[test]
fn enforced_wall_breach_terminates() {
    let policy = BudgetPolicy {
        max_wall_secs: Some(5),
        ..Default::default()
    };
    let report = evaluate_budgets(
        &policy,
        &ObservedBudgets {
            wall_secs: Some(30),
            ..Default::default()
        },
    );
    assert!(report.terminated_by_budget);
    assert!(report.breach_reason.is_some());
}
