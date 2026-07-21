//! Central harness adapter detection.

use std::sync::Arc;

use crate::adapters::agents::{
    AiderAdapter, CursorAdapter, GeminiAdapter, GrokAdapter, OpenCodeAdapter,
};
use crate::adapters::claude::ClaudeAdapter;
use crate::adapters::codex::CodexAdapter;
use crate::adapters::generic::GenericAdapter;
use crate::adapters::harness::HarnessAdapter;

/// Detect the best harness adapter for a command (first match wins).
///
/// Order: specific named harnesses first, generic last.
pub fn detect_adapter(command: &[String]) -> Arc<dyn HarnessAdapter> {
    let candidates: Vec<Arc<dyn HarnessAdapter>> = vec![
        Arc::new(ClaudeAdapter::new()),
        Arc::new(CodexAdapter::new()),
        Arc::new(AiderAdapter::new()),
        Arc::new(GeminiAdapter::new()),
        Arc::new(CursorAdapter::new()),
        Arc::new(OpenCodeAdapter::new()),
        Arc::new(GrokAdapter::new()),
        Arc::new(GenericAdapter::new()),
    ];
    for a in candidates {
        if a.detect(command) {
            return a;
        }
    }
    Arc::new(GenericAdapter::new())
}

/// Basename of argv\[0\] for detection helpers.
pub fn command_basename(command: &[String]) -> Option<&str> {
    command
        .first()
        .and_then(|c| std::path::Path::new(c).file_name())
        .and_then(|n| n.to_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_claude_codex() {
        assert_eq!(detect_adapter(&["claude".into()]).id(), "claude");
        assert_eq!(
            detect_adapter(&["codex".into(), "exec".into()]).id(),
            "codex"
        );
    }

    #[test]
    fn detects_extra_harnesses() {
        assert_eq!(detect_adapter(&["aider".into()]).id(), "aider");
        assert_eq!(detect_adapter(&["gemini".into()]).id(), "gemini");
        assert_eq!(detect_adapter(&["cursor".into()]).id(), "cursor");
        assert_eq!(detect_adapter(&["cursor-agent".into()]).id(), "cursor");
        assert_eq!(detect_adapter(&["opencode".into()]).id(), "opencode");
        assert_eq!(detect_adapter(&["grok".into()]).id(), "grok");
    }

    #[test]
    fn falls_back_to_generic() {
        assert_eq!(
            detect_adapter(&["echo".into(), "hi".into()]).id(),
            "generic"
        );
    }
}
