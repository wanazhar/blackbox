/// Html module.
pub mod html;
/// Jsonl module.
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
/// `ExportRedactor` path-aware-scans string fields (structural ids/refs skipped;
/// free-form content still secret-scanned). Portable format embeds blobs and
/// requires a store handle; the top-level `blobs` map keys are restored around
/// the JSON walk so content-addressed refs stay importable.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `export_run` — see module docs for full workflow.
/// ```
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

    match format {
        "jsonl" => apply_jsonl_redaction(&output),
        "portable" => apply_portable_blob_redaction(&output),
        "html" => apply_html_redaction(&output),
        _ => Ok(output),
    }
}

/// Portable export with the same H-08 blob re-scan used by CLI `export`.
///
/// Prefer this over bare [`portable::export_portable`] for sync / serve so
/// secrets that only live inside embedded blobs are still redacted.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `export_portable_secure` — see module docs for full workflow.
/// ```
pub async fn export_portable_secure(
    store: &dyn TraceStore,
    run: &Run,
    events: &[TraceEvent],
    redact: bool,
) -> anyhow::Result<String> {
    let output = portable::export_portable(store, run, events, redact).await?;
    if !redact {
        return Ok(output);
    }
    apply_portable_blob_redaction(&output)
}

/// HTML export + ExportRedactor second pass (matches CLI `export --format html`).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `export_html_secure` — see module docs for full workflow.
/// ```
pub fn export_html_secure(
    run: &Run,
    events: &[TraceEvent],
    redact: bool,
) -> anyhow::Result<String> {
    let output = html::export_html(run, events, redact)?;
    if !redact {
        return Ok(output);
    }
    apply_html_redaction(&output)
}

fn apply_jsonl_redaction(output: &str) -> anyhow::Result<String> {
    let redactor = ExportRedactor::new(RedactionConfig::default());
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

fn apply_html_redaction(output: &str) -> anyhow::Result<String> {
    // M-26: single JSON string walk — patterns spanning HTML tags may miss.
    let redactor = ExportRedactor::new(RedactionConfig::default());
    let mut wrapped = serde_json::Value::String(output.to_string());
    redactor.redact_json(&mut wrapped);
    Ok(wrapped.as_str().unwrap_or("").to_string())
}

/// H-08: path-aware JSON redaction + base64 blob body re-scan + **rekey**.
///
/// After redacting blob plaintext, recompute content keys so `key ==
/// sha256(data)` still holds for import (A1). Event `*_blob` refs are rewritten.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `apply_portable_blob_redaction` — see module docs for full workflow.
/// ```
pub fn apply_portable_blob_redaction(output: &str) -> anyhow::Result<String> {
    let redactor = ExportRedactor::new(RedactionConfig::default());
    let mut v: serde_json::Value = serde_json::from_str(output)?;
    if let Some(blobs) = v.get_mut("blobs").and_then(|b| b.as_object_mut()) {
        // Temporarily extract blobs, redact rest, restore
        let saved = blobs.clone();
        redactor.redact_json(&mut v);
        if let Some(b) = v.get_mut("blobs").and_then(|b| b.as_object_mut()) {
            *b = saved;
        }
        // Scan restored blob data for secrets; rekey map + event refs.
        let mut key_remap: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        if let Some(blobs_obj) = v.get("blobs").and_then(|b| b.as_object()) {
            let mut rebuilt = serde_json::Map::new();
            for (old_key, entry) in blobs_obj {
                let data_str = if let Some(obj) = entry.as_object() {
                    obj.get("data")
                        .and_then(|d| d.as_str())
                        .map(|s| s.to_string())
                } else {
                    entry.as_str().map(|s| s.to_string())
                };
                let mut new_entry = entry.clone();
                let mut new_key = old_key.clone();
                if let Some(data_b64) = data_str {
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&data_b64)
                    {
                        if let Ok(text) = String::from_utf8(decoded.clone()) {
                            let redacted_text = redactor.scanner.redact(&text);
                            let plain = if redacted_text != text {
                                redacted_text.into_bytes()
                            } else {
                                decoded
                            };
                            new_key = crate::crypto::content_key(&plain);
                            let new_b64 = base64::engine::general_purpose::STANDARD.encode(&plain);
                            if let Some(obj) = new_entry.as_object_mut() {
                                obj.insert("data".into(), serde_json::Value::String(new_b64));
                                obj.insert("size".into(), serde_json::json!(plain.len()));
                            } else {
                                new_entry = serde_json::Value::String(new_b64);
                            }
                        }
                    }
                }
                if new_key != *old_key {
                    key_remap.insert(old_key.clone(), new_key.clone());
                }
                rebuilt.insert(new_key, new_entry);
            }
            if let Some(b) = v.get_mut("blobs").and_then(|b| b.as_object_mut()) {
                *b = rebuilt;
            }
        }
        if !key_remap.is_empty() {
            rewrite_blob_refs_in_value(&mut v, &key_remap);
        }
    } else {
        redactor.redact_json(&mut v);
    }
    Ok(serde_json::to_string_pretty(&v)?)
}

fn rewrite_blob_refs_in_value(
    v: &mut serde_json::Value,
    remap: &std::collections::HashMap<String, String>,
) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map.iter_mut() {
                if matches!(
                    k.as_str(),
                    "input_blob" | "output_blob" | "error_blob" | "key"
                ) {
                    if let Some(s) = child.as_str() {
                        if let Some(new_k) = remap.get(s) {
                            *child = serde_json::Value::String(new_k.clone());
                            continue;
                        }
                    }
                }
                rewrite_blob_refs_in_value(child, remap);
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr {
                rewrite_blob_refs_in_value(child, remap);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, TraceEvent};
    use crate::core::run::RunStatus;
    use crate::storage::sqlite::SqliteStore;
    use std::sync::Arc;

    #[tokio::test]
    async fn portable_secure_redacts_secret_inside_blob() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open_with_blobs(dir.path().join("t.db"), dir.path().join("blobs"))
            .unwrap();
        let store: Arc<dyn TraceStore> = Arc::new(store);
        let mut run = Run::new(vec!["echo".into()], "/tmp".into());
        store.insert_run(&run).await.unwrap();
        let secret = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let bref = store.store_blob(secret.as_bytes()).await.unwrap();
        let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
        ev.output_blob = Some(bref.key.clone());
        store.insert_event(&ev).await.unwrap();
        run.status = RunStatus::Succeeded;
        store.update_run(&run).await.unwrap();

        let events = store.get_events(&run.id).await.unwrap();
        let secure = export_portable_secure(store.as_ref(), &run, &events, true)
            .await
            .unwrap();
        assert!(
            !secure.contains(secret),
            "secure portable must re-scan blob bodies"
        );
        assert!(!secure.contains("sk-abcdef"));
    }
}
