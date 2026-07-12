use crate::adapters::harness::HarnessAdapter;
use crate::adapters::{LaunchContext, PreparedLaunch, RunContext};
use crate::core::event::TraceEvent;

/// Adapter for Claude Code CLI agent harness.
///
/// Detects: `claude`, `claude ...`
///
/// Capabilities:
/// - Session identification from output
/// - Transcript log location
/// - Resume command construction
pub struct ClaudeAdapter;

impl ClaudeAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for ClaudeAdapter {
    fn id(&self) -> &'static str {
        "claude"
    }

    fn detect(&self, command: &[String]) -> bool {
        command.first().map_or(false, |c| {
            c.ends_with("claude") || c == "claude"
        })
    }

    fn prepare_launch(
        &self,
        command: &[String],
        context: &LaunchContext,
    ) -> Option<PreparedLaunch> {
        Some(PreparedLaunch {
            command: command.to_vec(),
            environment: context.environment.clone(),
            cwd: context.project_dir.clone(),
        })
    }

    fn discover_session_id(&self, _events: &[TraceEvent]) -> Option<String> {
        None
    }

    fn locate_native_logs(&self, context: &RunContext) -> Vec<String> {
        let path = std::path::Path::new(&context.project_dir)
            .join(".claude")
            .join("logs");
        if path.exists() {
            vec![path.to_string_lossy().to_string()]
        } else {
            Vec::new()
        }
    }
}
