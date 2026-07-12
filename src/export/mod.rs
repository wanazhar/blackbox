pub mod html;
pub mod jsonl;
pub mod portable;

use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::redaction::export::ExportRedactor;
use crate::redaction::RedactionConfig;

/// Export a run and its events in the requested format.
///
/// When `redact` is true, format-specific redaction runs first, then
/// `ExportRedactor` scans every string field for known secret patterns.
pub async fn export_run(
    run: &Run,
    events: &[TraceEvent],
    format: &str,
    redact: bool,
) -> anyhow::Result<String> {
    let output = match format {
        "jsonl" => jsonl::export_jsonl(run, events, redact)?,
        "html" => html::export_html(run, events, redact)?,
        "portable" => portable::export_portable(run, events, redact)?,
        _ => anyhow::bail!("unsupported export format: {}", format),
    };

    if !redact {
        return Ok(output);
    }

    // Second pass: ExportRedactor scans for secret patterns
    let redactor = ExportRedactor::new(RedactionConfig::default());
    match format {
        "jsonl" => {
            let mut lines = Vec::new();
            for line in output.lines() {
                if line.is_empty() {
                    continue;
                }
                let mut v: serde_json::Value = serde_json::from_str(line)?;
                redactor.redact_json(&mut v);
                lines.push(serde_json::to_string(&v)?);
            }
            Ok(lines.join("\n") + "\n")
        }
        "portable" => {
            let mut v: serde_json::Value = serde_json::from_str(&output)?;
            redactor.redact_json(&mut v);
            Ok(serde_json::to_string_pretty(&v)?)
        }
        "html" => {
            // HTML is not JSON — apply a plain-text secret scrub via the scanner
            // by wrapping in a JSON string value, redacting, then unwrapping.
            let mut wrapped = serde_json::Value::String(output);
            redactor.redact_json(&mut wrapped);
            Ok(wrapped.as_str().unwrap_or("").to_string())
        }
        _ => Ok(output),
    }
}
