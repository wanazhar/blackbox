pub mod jsonl;

use crate::core::event::TraceEvent;
use crate::core::run::Run;

/// Export a run and its events in the requested format.
pub async fn export_run(
    run: &Run,
    events: &[TraceEvent],
    format: &str,
    redact: bool,
) -> anyhow::Result<String> {
    match format {
        "jsonl" => jsonl::export_jsonl(run, events, redact),
        _ => anyhow::bail!("unsupported export format: {}", format),
    }
}
