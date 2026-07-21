//! Budget policy and per-limit capability classification.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetCapability {
    Enforced,
    ObservedOnly,
    Unavailable,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetStatus {
    pub name: String,
    pub capability: BudgetCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BudgetPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wall_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_processes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_store_growth_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tool_calls: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    /// RSS/address-space budget (cgroup v2 `memory.max` when available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_bytes: Option<u64>,
    /// CPU bandwidth as percent of one CPU (cgroup v2 `cpu.max`); e.g. 50 = half a core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpu_percent: Option<u32>,
    #[serde(default)]
    pub contained: bool,
}

impl BudgetPolicy {
    /// Classify each budget for the current OS. Never report unavailable as enforced.
    pub fn capability_report(&self) -> Vec<BudgetStatus> {
        let linux = cfg!(target_os = "linux");
        let mut out = Vec::new();

        out.push(BudgetStatus {
            name: "wall_time".into(),
            capability: if self.max_wall_secs.is_some() {
                BudgetCapability::Enforced
            } else {
                BudgetCapability::NotApplicable
            },
            limit: self.max_wall_secs,
            observed: None,
            unit: Some("seconds".into()),
            note: None,
        });

        out.push(BudgetStatus {
            name: "process_count".into(),
            capability: if self.max_processes.is_some() {
                if linux {
                    BudgetCapability::Enforced
                } else {
                    BudgetCapability::ObservedOnly
                }
            } else {
                BudgetCapability::NotApplicable
            },
            limit: self.max_processes,
            observed: None,
            unit: Some("processes".into()),
            note: if !linux && self.max_processes.is_some() {
                Some("macOS/other: process budget is observed-only".into())
            } else {
                None
            },
        });

        out.push(BudgetStatus {
            name: "output_bytes".into(),
            capability: if self.max_output_bytes.is_some() {
                // Hard-terminated mid-run via capture path counter + SIGKILL.
                BudgetCapability::Enforced
            } else {
                BudgetCapability::NotApplicable
            },
            limit: self.max_output_bytes,
            observed: None,
            unit: Some("bytes".into()),
            note: if self.max_output_bytes.is_some() {
                Some("output byte ceiling kills the supervised child when exceeded".into())
            } else {
                None
            },
        });

        out.push(BudgetStatus {
            name: "store_growth".into(),
            capability: if self.max_store_growth_bytes.is_some() {
                BudgetCapability::ObservedOnly
            } else {
                BudgetCapability::NotApplicable
            },
            limit: self.max_store_growth_bytes,
            observed: None,
            unit: Some("bytes".into()),
            note: Some("store growth is measured, not hard-cgroup limited".into()),
        });

        out.push(BudgetStatus {
            name: "tool_calls".into(),
            capability: if self.max_tool_calls.is_some() {
                BudgetCapability::Enforced
            } else {
                BudgetCapability::NotApplicable
            },
            limit: self.max_tool_calls,
            observed: None,
            unit: Some("calls".into()),
            note: if self.max_tool_calls.is_some() {
                Some("tool-call ceiling kills the supervised child when exceeded".into())
            } else {
                None
            },
        });

        out.push(BudgetStatus {
            name: "tokens".into(),
            capability: if self.max_tokens.is_some() {
                BudgetCapability::ObservedOnly
            } else {
                BudgetCapability::NotApplicable
            },
            limit: self.max_tokens,
            observed: None,
            unit: Some("tokens".into()),
            note: Some("token budgets are observed-only unless harness enforces".into()),
        });

        out.push(BudgetStatus {
            name: "memory".into(),
            capability: if self.max_memory_bytes.is_some() {
                if linux {
                    // Refined later by cgroup probe / apply report.
                    BudgetCapability::ObservedOnly
                } else {
                    BudgetCapability::Unavailable
                }
            } else {
                BudgetCapability::NotApplicable
            },
            limit: self.max_memory_bytes,
            observed: None,
            unit: Some("bytes".into()),
            note: if self.max_memory_bytes.is_some() && linux {
                Some("prefers cgroup v2 memory.max; else RLIMIT_AS".into())
            } else if self.max_memory_bytes.is_some() {
                Some("cgroup memory not available on this OS".into())
            } else {
                None
            },
        });

        out.push(BudgetStatus {
            name: "cpu".into(),
            capability: if self.max_cpu_percent.is_some() {
                if linux {
                    BudgetCapability::ObservedOnly
                } else {
                    BudgetCapability::Unavailable
                }
            } else {
                BudgetCapability::NotApplicable
            },
            limit: self.max_cpu_percent.map(|p| p as u64),
            observed: None,
            unit: Some("percent_of_cpu".into()),
            note: if self.max_cpu_percent.is_some() && linux {
                Some("prefers cgroup v2 cpu.max; RLIMIT_CPU is time backstop only".into())
            } else {
                None
            },
        });

        out.push(BudgetStatus {
            name: "containment".into(),
            capability: if self.contained {
                if linux {
                    BudgetCapability::Enforced
                } else {
                    BudgetCapability::Unavailable
                }
            } else {
                BudgetCapability::NotApplicable
            },
            limit: None,
            observed: None,
            unit: None,
            note: if self.contained && !linux {
                Some("containment unavailable on this OS".into())
            } else {
                None
            },
        });

        out
    }
}
