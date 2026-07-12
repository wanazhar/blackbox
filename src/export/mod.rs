pub mod html;
pub mod jsonl;
pub mod portable;

use crate::core::event::TraceEvent;
use crate::core::run::Run;
use crate::redaction::export::ExportRedactor;
use crate::redaction::RedactionConfig;
use crate::storage::TraceStore;

/// Export a run and its events in the requested format.
///
/// When `redact` is true, format-specific redaction runs first, then
/// `ExportRedactor` scans every string field for known secret patterns.
/// Portable format embeds blobs and requires a store handle.
pub async fn export_run(
    store: &dyn TraceStore,
    run: &Run,
    events: &[TraceEvent],
    format: &str,
    redact: bool,
) -> anyhow::Result<String> {
    let output = match format {
        "jsonl" => jsonl::export_jsonl(run, events, redact)?,
        "html" => html::export_html(run, events, redact)?,
        "portable" => portable::export_portable(store, run, events, redact).await?,
        _ => anyhow::bail!("unsupported export format: {}", format),
    };

    if !redact {
        return Ok(output);
    }

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
            // Do not wipe blob binary payloads during secret scan of keys only —
            // redactor walks all strings including base64; skip blob data fields.
            if let Some(blobs) = v.get_mut("blobs").and_then(|b| b.as_object_mut()) {
                // Temporarily extract blobs, redact rest, restore
                let saved = blobs.clone();
                redactor.redact_json(&mut v);
                if let Some(b) = v.get_mut("blobs").and_then(|b| b.as_object_mut()) {
                    *b = saved;
                }
            } else {
                redactor.redact_json(&mut v);
            }
            Ok(serde_json::to_string_pretty(&v)?)
        }
        "html" => {
            let mut wrapped = serde_json::Value::String(output);
            redactor.redact_json(&mut wrapped);
            Ok(wrapped.as_str().unwrap_or("").to_string())
        }
        _ => Ok(output),
    }
}
