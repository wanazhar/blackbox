//! Typed blob-reference collection and remapping (1.6 integrity).
//!
//! Transformations that change blob plaintext must rewrite every reference
//! (top-level event fields, checkpoint fields, and nested content hashes
//! inside workspace manifests) rather than guessing field names ad hoc.

use std::collections::{HashMap, HashSet};

use crate::core::blob::is_valid_blob_key;
use crate::core::checkpoint::Checkpoint;
use crate::core::event::TraceEvent;
use crate::workspace_manifest::{ManifestEntryType, WorkspaceManifest};

/// Collect every content-addressed blob key referenced by an event.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `collect_event_blob_keys` — see module docs for full workflow.
/// ```
pub fn collect_event_blob_keys(event: &TraceEvent) -> HashSet<String> {
    let mut keys = HashSet::new();
    for k in [
        event.input_blob.as_deref(),
        event.output_blob.as_deref(),
        event.error_blob.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if is_valid_blob_key(k) {
            keys.insert(k.to_string());
        }
    }
    collect_json_blob_keys_in_map(&event.metadata, &mut keys);
    keys
}

/// Collect blob keys from a checkpoint's typed fields.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `collect_checkpoint_blob_keys` — see module docs for full workflow.
/// ```
pub fn collect_checkpoint_blob_keys(cp: &Checkpoint) -> HashSet<String> {
    let mut keys = HashSet::new();
    for k in [
        cp.git_diff_blob.as_deref(),
        cp.filesystem_manifest_blob.as_deref(),
        cp.environment_blob.as_deref(),
        cp.transcript_blob.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if is_valid_blob_key(k) {
            keys.insert(k.to_string());
        }
    }
    keys
}

/// Collect `content_hash` keys from a workspace manifest.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `collect_manifest_blob_keys` — see module docs for full workflow.
/// ```
pub fn collect_manifest_blob_keys(manifest: &WorkspaceManifest) -> HashSet<String> {
    let mut keys = HashSet::new();
    for entry in &manifest.entries {
        if let Some(ref h) = entry.content_hash {
            if is_valid_blob_key(h) {
                keys.insert(h.clone());
            }
        }
    }
    keys
}

/// Remap top-level event blob fields and string metadata values that look like
/// blob keys. Returns true if anything changed.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `remap_event_blob_refs` — see module docs for full workflow.
/// ```
pub fn remap_event_blob_refs(event: &mut TraceEvent, remap: &HashMap<String, String>) -> bool {
    if remap.is_empty() {
        return false;
    }
    let mut dirty = false;
    for slot in [
        &mut event.input_blob,
        &mut event.output_blob,
        &mut event.error_blob,
    ] {
        if let Some(ref key) = slot {
            if let Some(new_key) = remap.get(key) {
                *slot = Some(new_key.clone());
                dirty = true;
            }
        }
    }
    if remap_json_map_strings(&mut event.metadata, remap) {
        dirty = true;
    }
    dirty
}

/// Remap typed checkpoint blob fields. Returns true if anything changed.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `remap_checkpoint_blob_refs` — see module docs for full workflow.
/// ```
pub fn remap_checkpoint_blob_refs(cp: &mut Checkpoint, remap: &HashMap<String, String>) -> bool {
    if remap.is_empty() {
        return false;
    }
    let mut dirty = false;
    for slot in [
        &mut cp.git_diff_blob,
        &mut cp.filesystem_manifest_blob,
        &mut cp.environment_blob,
        &mut cp.transcript_blob,
    ] {
        if let Some(ref key) = slot {
            if let Some(new_key) = remap.get(key) {
                *slot = Some(new_key.clone());
                dirty = true;
            }
        }
    }
    dirty
}

/// Remap `content_hash` fields inside a workspace manifest.
/// Returns true if any hash was rewritten.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `remap_manifest_blob_refs` — see module docs for full workflow.
/// ```
pub fn remap_manifest_blob_refs(
    manifest: &mut WorkspaceManifest,
    remap: &HashMap<String, String>,
) -> bool {
    if remap.is_empty() {
        return false;
    }
    let mut dirty = false;
    for entry in &mut manifest.entries {
        if entry.entry_type != ManifestEntryType::File {
            continue;
        }
        if let Some(ref hash) = entry.content_hash {
            if let Some(new_hash) = remap.get(hash) {
                entry.content_hash = Some(new_hash.clone());
                // Content was rewritten — no longer original-byte faithful.
                entry.byte_exact = false;
                if entry.transformation.is_none() {
                    entry.transformation =
                        Some(crate::workspace_manifest::ContentTransformation::SecretRedaction);
                }
                dirty = true;
            }
        }
    }
    dirty
}

/// Validate that no old keys from `remap` remain in the event.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `event_has_stale_blob_ref` — see module docs for full workflow.
/// ```
pub fn event_has_stale_blob_ref(event: &TraceEvent, old_keys: &HashSet<String>) -> bool {
    if old_keys.is_empty() {
        return false;
    }
    collect_event_blob_keys(event)
        .iter()
        .any(|k| old_keys.contains(k))
}

fn collect_json_blob_keys_in_map(
    map: &std::collections::HashMap<String, serde_json::Value>,
    out: &mut HashSet<String>,
) {
    for (k, v) in map {
        let looks_blobish = k.contains("blob") || k.ends_with("_key") || k.contains("diff");
        match v {
            serde_json::Value::String(s) if looks_blobish && is_valid_blob_key(s) => {
                out.insert(s.clone());
            }
            serde_json::Value::Object(obj) => {
                let as_map: std::collections::HashMap<String, serde_json::Value> =
                    obj.iter().map(|(a, b)| (a.clone(), b.clone())).collect();
                collect_json_blob_keys_in_map(&as_map, out);
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    if let serde_json::Value::String(s) = item {
                        if is_valid_blob_key(s) {
                            out.insert(s.clone());
                        }
                    } else if let serde_json::Value::Object(obj) = item {
                        let as_map: std::collections::HashMap<String, serde_json::Value> =
                            obj.iter().map(|(a, b)| (a.clone(), b.clone())).collect();
                        collect_json_blob_keys_in_map(&as_map, out);
                    }
                }
            }
            _ => {}
        }
    }
}

fn remap_json_map_strings(
    map: &mut std::collections::HashMap<String, serde_json::Value>,
    remap: &HashMap<String, String>,
) -> bool {
    let mut dirty = false;
    let keys: Vec<String> = map.keys().cloned().collect();
    for k in keys {
        let Some(val) = map.get_mut(&k) else { continue };
        match val {
            serde_json::Value::String(s) => {
                if let Some(new_key) = remap.get(s.as_str()) {
                    *s = new_key.clone();
                    dirty = true;
                }
            }
            serde_json::Value::Object(obj) => {
                let mut nested: std::collections::HashMap<String, serde_json::Value> =
                    obj.iter().map(|(a, b)| (a.clone(), b.clone())).collect();
                if remap_json_map_strings(&mut nested, remap) {
                    *val = serde_json::Value::Object(nested.into_iter().collect());
                    dirty = true;
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr.iter_mut() {
                    if let serde_json::Value::String(s) = item {
                        if let Some(new_key) = remap.get(s.as_str()) {
                            *s = new_key.clone();
                            dirty = true;
                        }
                    } else if let serde_json::Value::Object(obj) = item {
                        let mut nested: std::collections::HashMap<String, serde_json::Value> =
                            obj.iter().map(|(a, b)| (a.clone(), b.clone())).collect();
                        if remap_json_map_strings(&mut nested, remap) {
                            *item = serde_json::Value::Object(nested.into_iter().collect());
                            dirty = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    dirty
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, TraceEvent};

    #[test]
    fn remaps_top_level_and_metadata() {
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        let mut ev = TraceEvent::new("r", EventSource::Terminal, "terminal.output");
        ev.output_blob = Some(old.clone());
        ev.metadata
            .insert("diff_blob_key".into(), serde_json::json!(old.clone()));
        let mut map = HashMap::new();
        map.insert(old.clone(), new.clone());
        assert!(remap_event_blob_refs(&mut ev, &map));
        assert_eq!(ev.output_blob.as_deref(), Some(new.as_str()));
        assert_eq!(
            ev.metadata.get("diff_blob_key").and_then(|v| v.as_str()),
            Some(new.as_str())
        );
        let old_set = HashSet::from([old]);
        assert!(!event_has_stale_blob_ref(&ev, &old_set));
    }
}
