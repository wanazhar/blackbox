pub mod claude;
pub mod codex;
pub mod generic;
pub mod harness;
pub mod launch;
pub mod native_logs;
pub mod parse;

use std::collections::HashMap;

/// Context provided when launching a harness.
#[derive(Debug, Clone)]
pub struct LaunchContext {
    pub project_dir: String,
    pub environment: HashMap<String, String>,
    pub run_id: String,
}

/// Prepared launch configuration returned by an adapter.
#[derive(Debug, Clone)]
pub struct PreparedLaunch {
    pub command: Vec<String>,
    pub environment: HashMap<String, String>,
    pub cwd: String,
}

/// Context for locating harness-native log files.
#[derive(Debug, Clone)]
pub struct RunContext {
    pub run_id: String,
    pub project_dir: String,
    pub command: Vec<String>,
}
