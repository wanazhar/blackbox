//! Native harness integrations and reference adapters (1.9).

pub mod claude_hooks;

pub use claude_hooks::{ClaudeHooksAdapter, ClaudeHooksCoverage, CLAUDE_HOOKS_CONFORMANCE_LEVEL};
