pub mod html;
pub mod jsonl;
pub mod portable;

use base64::Engine;

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
            if let Some(blobs) = v.get_mut("blobs").and_then(|b| b.as_object_mut()) {
                // Temporarily extract blobs, redact rest, restore
                let saved = blobs.clone();
                redactor.redact_json(&mut v);
                if let Some(b) = v.get_mut("blobs").and_then(|b| b.as_object_mut()) {
                    *b = saved;
                }
                // H-08: Scan restored blob data for secrets that survived
                // export. Decode each base64 payload and redact if the
                // decoded text matches known secret patterns.
                if let Some(blobs_obj) = v.get_mut("blobs").and_then(|b| b.as_object_mut()) {
                    for (_key, entry) in blobs_obj.iter_mut() {
                        let data_str = if let Some(obj) = entry.as_object_mut() {
                            obj.get("data")
                                .and_then(|d| d.as_str())
                                .map(|s| s.to_string())
                        } else {
                            entry.as_str().map(|s| s.to_string())
                        };
                        if let Some(data_b64) = data_str {
                            if let Ok(decoded) =
                                base64::engine::general_purpose::STANDARD.decode(&data_b64)
                            {
                                if let Ok(text) = String::from_utf8(decoded) {
                                    let redacted_text = redactor.scanner.redact(&text);
                                    if redacted_text != text {
                                        let new_b64 = base64::engine::general_purpose::STANDARD
                                            .encode(redacted_text.as_bytes());
                                        if let Some(obj) = entry.as_object_mut() {
                                            obj.insert(
                                                "data".to_string(),
                                                serde_json::Value::String(new_b64),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                redactor.redact_json(&mut v);
            }
            Ok(serde_json::to_string_pretty(&v)?)
        }
        "html" => {
            // M-26: The HTML redactor operates on a single JSON string value.
            // It does not parse or walk the HTML DOM — so redaction patterns
            // that span element boundaries (e.g. split across tags) will not
            // be caught.  This is acceptable for the current export pipeline
            // where the HTML is machine-generated and patterns stay within
            // text nodes.
            let mut wrapped = serde_json::Value::String(output);
            redactor.redact_json(&mut wrapped);
            Ok(wrapped.as_str().unwrap_or("").to_string())
        }
        _ => Ok(output),
    }
}
