/// Shared utility functions used across modules.
///
/// Truncate a string to `max` bytes, appending `…` if shortened.
///
/// The cut point is rounded down to a valid char boundary.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..s.floor_char_boundary(max)])
    }
}

/// HTML-escape the five standard entities.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Redact sensitive fields in a run JSON value (cwd → basename only).
pub fn redact_run(val: &mut serde_json::Value) {
    if let Some(obj) = val.as_object_mut() {
        if let Some(cwd) = obj.get("cwd").and_then(|v| v.as_str()) {
            let basename = std::path::Path::new(cwd)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "(redacted)".to_string());
            obj.insert("cwd".to_string(), serde_json::json!(basename));
        }
    }
}

/// Redact sensitive fields in an event JSON value (raw terminal, diff_preview).
pub fn redact_event(val: &mut serde_json::Value) {
    if let Some(obj) = val.as_object_mut() {
        if let Some(meta) = obj.get_mut("metadata").and_then(|v| v.as_object_mut()) {
            meta.remove("raw");
            if meta.contains_key("diff_preview") {
                meta.insert("diff_preview".to_string(), serde_json::json!("[REDACTED]"));
            }
        }
    }
}

/// Bookkeeping event kinds that carry no semantic signal for users.
pub fn is_bookkeeping(kind: &str) -> bool {
    matches!(
        kind,
        "pty.started"
            | "pty.stopped"
            | "git.observer.started"
            | "git.observer.stopped"
            | "filesystem.observer.started"
            | "filesystem.observer.stopped"
            | "process.observer.started"
            | "process.observer.stopped"
            | "terminal.recording"
            | "git.commit"
            | "git.commit.after"
    )
}

/// Return the first 8 characters of an id (or the whole string if shorter).
pub fn short_id(id: &str) -> &str {
    &id[..8.min(id.len())]
}

/// Merge run notes segments without clobbering prior parts.
///
/// Segments are joined with `"; "`. Empty parts are skipped. Duplicate exact
/// segments already present in `existing` are not re-appended.
pub fn merge_run_notes(existing: Option<String>, parts: &[&str]) -> String {
    let mut segments: Vec<String> = existing
        .unwrap_or_default()
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for p in parts {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        if !segments.iter().any(|s| s == p) {
            segments.push(p.to_string());
        }
    }
    segments.join("; ")
}

#[cfg(test)]
mod notes_tests {
    use super::merge_run_notes;

    #[test]
    fn merge_preserves_continuity_and_adapter() {
        let n = merge_run_notes(Some("auto_resume:abcdef12".into()), &["adapter:claude"]);
        assert!(n.contains("auto_resume:abcdef12"));
        assert!(n.contains("adapter:claude"));
        let n2 = merge_run_notes(Some(n), &["session:xyz"]);
        assert!(n2.contains("adapter:claude"));
        assert!(n2.contains("session:xyz"));
        assert!(n2.contains("auto_resume:abcdef12"));
    }

    #[test]
    fn merge_skips_duplicates() {
        let n = merge_run_notes(
            Some("adapter:claude".into()),
            &["adapter:claude", "claim:1"],
        );
        assert_eq!(n.matches("adapter:claude").count(), 1);
        assert!(n.contains("claim:1"));
    }
}
