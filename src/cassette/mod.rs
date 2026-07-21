//! MCP tool cassette record/replay (experimental, 1.6 Phase E).

pub mod format;
pub mod matching;
pub mod mcp_proxy;

pub use format::{CassetteEntry, CassetteFile, SideEffectClass};
pub use matching::{match_request, MatchMode, MatchResult};
pub use mcp_proxy::{
    init_cassette, run_mcp_proxy, ProxyConfig, ProxyMode, ProxyReport, UnknownPolicy,
};
