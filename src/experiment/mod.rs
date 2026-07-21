//! Structured experiments, multi-run reports, and regression gates (1.6 Phase D).

pub mod gate;
pub mod model;
pub mod report;
pub mod stats;

pub use gate::{evaluate_gate, GateConfig, GateResult, GateRuleFailure};
pub use model::{
    next_attempt_number, ExperimentManifest, ExperimentRole, RunExperimentMeta, EXPERIMENT_SCHEMA,
};
pub use report::{build_experiment_report, ExperimentReport, RunReportInput, VariantMetrics};
pub use stats::{median_f64, percentile, StatisticalNote};
