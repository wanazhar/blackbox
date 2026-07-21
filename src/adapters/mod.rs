pub mod agents;
/// Claude module.
pub mod claude;
/// Codex module.
pub mod codex;
pub mod detect;
/// Generic module.
pub mod generic;
/// Harness module.
pub mod harness;
pub mod launch;
pub mod native_logs;
pub mod parse;

use std::collections::HashMap;

/// Context provided when launching a harness.
#[derive(Debug, Clone)]
pub struct LaunchContext {
    /// Project dir.
    pub project_dir: String,
    /// Environment.
    pub environment: HashMap<String, String>,
    /// Owning run id.
    pub run_id: String,
}

/// Prepared launch configuration returned by an adapter.
#[derive(Debug, Clone)]
pub struct PreparedLaunch {
    /// Command argv.
    pub command: Vec<String>,
    /// Environment.
    pub environment: HashMap<String, String>,
    /// Working directory.
    pub cwd: String,
}

/// Context for locating harness-native log files.
#[derive(Debug, Clone)]
pub struct RunContext {
    /// Owning run id.
    pub run_id: String,
    /// Project dir.
    pub project_dir: String,
    /// Command argv.
    pub command: Vec<String>,
}
