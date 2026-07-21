//! MCP tool cassette record/replay (experimental, 1.6 Phase E).

pub mod format;
pub mod matching;

pub use format::{CassetteEntry, CassetteFile, SideEffectClass};
pub use matching::{match_request, MatchMode, MatchResult};
