use crate::adapters::harness::HarnessAdapter;
use crate::adapters::{LaunchContext, PreparedLaunch};

/// Generic adapter for unrecognized commands and shell scripts.
///
/// The default fallback: no special detection, no structured
/// parsing, no session management. The debugger's universal
/// capture layers (PTY, process, filesystem) handle everything.
pub struct GenericAdapter;

impl GenericAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl HarnessAdapter for GenericAdapter {
    fn id(&self) -> &'static str {
        "generic"
    }

    fn detect(&self, _command: &[String]) -> bool {
        true
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
}
