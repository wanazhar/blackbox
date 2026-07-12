use crate::adapters::{LaunchContext, PreparedLaunch, RunContext};
use crate::core::event::TraceEvent;

/// Harness adapter trait.
///
/// Adapters are intentionally small. They know:
/// - How to detect a specific harness from the command
/// - How to prepare the launch (environment, args)
/// - How to parse output for structured events
/// - How to discover session IDs for resumption
/// - How to build resume commands
/// - Where the harness stores native logs
///
/// An adapter should NOT need an integration for every tool
/// the harness may invoke.
#[async_trait::async_trait]
pub trait HarnessAdapter: Send + Sync {
    /// Unique adapter identifier.
    fn id(&self) -> &'static str;

    /// Whether this adapter recognizes the given command.
    fn detect(&self, command: &[String]) -> bool;

    /// Prepare the launch configuration.
    fn prepare_launch(
        &self,
        command: &[String],
        context: &LaunchContext,
    ) -> Option<PreparedLaunch>;

    /// Parse a terminal output chunk into semantic events.
    fn parse_output(&self, _chunk: &[u8]) -> Vec<TraceEvent> {
        Vec::new()
    }

    /// Try to discover a harness session ID from recorded events.
    fn discover_session_id(&self, _events: &[TraceEvent]) -> Option<String> {
        None
    }

    /// Build a command to resume an existing session.
    fn build_resume_command(&self, _session_id: &str) -> Option<Vec<String>> {
        None
    }

    /// Locate native harness log files for ingestion.
    fn locate_native_logs(&self, _context: &RunContext) -> Vec<String> {
        Vec::new()
    }
}
