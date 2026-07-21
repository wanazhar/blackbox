use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;

/// Field names whose **string values** are structural identifiers/refs and must
/// never be pattern-scanned when they appear outside free-form parents.
///
/// Free-form parents (`metadata`, `input`, `output`, …) always scan, so a nested
/// key literally named `status` or `kind` under tool payload still redacts secrets.
const STRUCTURAL_STRING_KEYS: &[&str] = &[
    "id",
    "run_id",
    "event_id",
    "parent_event_id",
    "parent_run_id",
    "sequence",
    "next_sequence",
    "input_blob",
    "output_blob",
    "error_blob",
    "environment_blob",
    "commit",
    "git_commit",
    "started_at",
    "ended_at",
    "status",
    "kind",
    "source",
    "side_effect",
    "adapter",
    "name",
];

/// JSON object keys that hold free-form / untrusted content. Descendants are
/// never allowlisted, even if the leaf key name matches a structural field.
const FREE_FORM_PARENTS: &[&str] = &[
    "metadata",
    "input",
    "output",
    "error",
    "preview",
    "notes",
    "command",
    "environment",
    "env",
];

/// Export-time redaction pass.
///
/// Applies a deeper secret scan before writing trace data to
/// an export file. This is an additional layer beyond the
/// capture-time redaction, catching anything that was missed.
///
/// Path-aware: structural identity/ref fields (run ids, blob keys, git SHAs,
/// sequences, enum discriminators) are left intact unless nested under a
/// free-form parent. Free-form string content is always scanned.
pub struct ExportRedactor {
    pub(crate) scanner: SecretScanner,
}

impl ExportRedactor {
    /// Create a new instance.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `new` — see module docs for full workflow.
    /// ```
    pub fn new(config: RedactionConfig) -> Self {
        Self {
            scanner: SecretScanner::new(config),
        }
    }

    /// Redact sensitive content from an export payload.
    ///
    /// Scans string fields in the serialized JSON value (except structural
    /// identifiers outside free-form parents) and replaces matched secrets
    /// with `[REDACTED]`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `redact_json` — see module docs for full workflow.
    /// ```
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        self.redact_json_inner(value, &[], 0, 32);
    }

    /// True when `key`'s string value should skip secret scanning.
    fn should_skip_string(path: &[&str], key: &str) -> bool {
        if path.iter().any(|p| FREE_FORM_PARENTS.contains(p)) {
            return false;
        }
        STRUCTURAL_STRING_KEYS.contains(&key)
    }

    /// Internal recursive redaction with path + depth tracking.
    ///
    /// Stops recursing at `max_depth` to prevent stack overflow
    /// on adversarially deep JSON.
    fn redact_json_inner(
        &self,
        value: &mut serde_json::Value,
        path: &[&str],
        depth: usize,
        max_depth: usize,
    ) {
        if depth > max_depth {
            return;
        }
        match value {
            serde_json::Value::String(s) => {
                // Root-level bare strings have no key; always scan.
                *s = self.scanner.redact(s);
            }
            serde_json::Value::Number(n) => {
                let s = n.to_string();
                let redacted = self.scanner.redact(&s);
                if redacted != s {
                    *value = serde_json::Value::String(redacted);
                }
            }
            serde_json::Value::Bool(b) => {
                let s = b.to_string();
                let redacted = self.scanner.redact(&s);
                if redacted != s {
                    *value = serde_json::Value::String(redacted);
                }
            }
            serde_json::Value::Object(obj) => {
                // Own the path as Strings so child recursion can extend it without
                // borrowing the live object keys.
                let path_owned: Vec<String> = path.iter().map(|s| (*s).to_string()).collect();
                let keys: Vec<String> = obj.keys().cloned().collect();
                for key in keys {
                    let skip = Self::should_skip_string(path, &key);
                    let Some(val) = obj.get_mut(&key) else {
                        continue;
                    };
                    if let serde_json::Value::String(s) = val {
                        if skip {
                            continue;
                        }
                        *s = self.scanner.redact(s);
                        continue;
                    }
                    let mut child_owned = path_owned.clone();
                    child_owned.push(key);
                    let child_refs: Vec<&str> = child_owned.iter().map(|s| s.as_str()).collect();
                    self.redact_json_inner(val, &child_refs, depth + 1, max_depth);
                }
            }
            serde_json::Value::Array(arr) => {
                for val in arr.iter_mut() {
                    self.redact_json_inner(val, path, depth + 1, max_depth);
                }
            }
            serde_json::Value::Null => {}
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn redactor() -> ExportRedactor {
        ExportRedactor::new(RedactionConfig::default())
    }

    #[test]
    fn redacts_simple_string_value() {
        let r = redactor();
        let mut val = json!("sk-abcdefghijklmnopqrstuvwxyz012345");
        r.redact_json(&mut val);
        let s = val.as_str().unwrap();
        assert!(s.contains("[REDACTED]"), "secret string should be redacted");
        assert!(!s.contains("sk-abcdef"), "original secret should be gone");
    }

    #[test]
    fn redacts_nested_objects() {
        let r = redactor();
        let mut val = json!({
            "server": {
                "auth": {
                    "token": "bearer abc123def456ghi789jkl012mno345pq"
                }
            }
        });
        r.redact_json(&mut val);
        let token = val["server"]["auth"]["token"].as_str().unwrap();
        assert!(
            token.contains("[REDACTED]"),
            "nested secret should be redacted"
        );
    }

    #[test]
    fn redacts_arrays() {
        let r = redactor();
        let mut val = json!([
            "plain text",
            "sk-abcdefghijklmnopqrstuvwxyz012345",
            "another plain string",
            "AKIAIOSFODNN7EXAMPLE"
        ]);
        r.redact_json(&mut val);
        let arr = val.as_array().unwrap();
        assert_eq!(arr[0].as_str().unwrap(), "plain text");
        assert!(arr[1].as_str().unwrap().contains("[REDACTED]"));
        assert_eq!(arr[2].as_str().unwrap(), "another plain string");
        assert!(arr[3].as_str().unwrap().contains("[REDACTED]"));
    }

    #[test]
    fn preserves_non_secret_strings() {
        let r = redactor();
        let mut val = json!({
            "name": "Alice",
            "age": 30,
            "greeting": "hello world"
        });
        r.redact_json(&mut val);
        assert_eq!(val["name"].as_str().unwrap(), "Alice");
        assert_eq!(val["greeting"].as_str().unwrap(), "hello world");
        assert_eq!(val["age"].as_i64().unwrap(), 30);
    }

    #[test]
    fn handles_empty_object() {
        let r = redactor();
        let mut val = json!({});
        r.redact_json(&mut val);
        assert!(val.as_object().unwrap().is_empty());
    }

    #[test]
    fn handles_deeply_nested_structure() {
        let r = redactor();
        let mut val = json!({
            "a": {
                "b": {
                    "c": {
                        "d": {
                            "e": {
                                "f": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
                            }
                        }
                    }
                }
            }
        });
        r.redact_json(&mut val);
        let deepest = val["a"]["b"]["c"]["d"]["e"]["f"].as_str().unwrap();
        assert!(
            deepest.contains("[REDACTED]"),
            "deeply nested secret should be redacted"
        );
    }

    #[test]
    fn mixed_types_preserve_non_strings() {
        // ExportRedactor.redact_json only processes String, Object, Array.
        // Number, Bool, and Null are left untouched.
        let r = redactor();
        let mut val = json!({
            "flag": true,
            "count": 42,
            "nothing": null,
            "label": "safe"
        });
        r.redact_json(&mut val);
        assert_eq!(val["flag"], json!(true));
        assert_eq!(val["count"], json!(42));
        assert_eq!(val["nothing"], json!(null));
        assert_eq!(val["label"].as_str().unwrap(), "safe");
    }

    #[test]
    fn applies_secret_scanner_patterns() {
        let r = redactor();
        let mut val = json!({
            "aws_key": "AKIAIOSFODNN7EXAMPLE",
            "openai_key": "sk-abcdefghijklmnopqrstuvwxyz012345",
            "github_token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
            "slack_token": concat!("xox", "b-1234567890-abcdefghij-abcdefghijklmnopqrstuvwx")
        });
        r.redact_json(&mut val);
        // Every secret value should be redacted
        assert!(val["aws_key"].as_str().unwrap().contains("[REDACTED]"));
        assert!(val["openai_key"].as_str().unwrap().contains("[REDACTED]"));
        assert!(val["github_token"].as_str().unwrap().contains("[REDACTED]"));
        assert!(val["slack_token"].as_str().unwrap().contains("[REDACTED]"));
    }

    // --- Path-aware structural allowlist ---

    #[test]
    fn preserves_structural_git_commit_and_blob_refs() {
        let r = redactor();
        let sha = "ea950d8180f520d808274579577db86bc6365a7a";
        let blob = "22c8e61f11fd0f02da754f5b2fa912f842c7ed27a056f5b38f882f820baf37d5";
        let run_id = "939b2397-08b7-43c8-8850-41fedb4f001a";
        let mut val = json!({
            "id": run_id,
            "run_id": run_id,
            "output_blob": blob,
            "input_blob": blob,
            "error_blob": blob,
            "started_at": "2026-07-12T14:15:01.338087081Z",
            "status": "Succeeded",
            "kind": "terminal.output",
            "source": "Terminal",
            "metadata": {
                "commit": sha
            }
        });
        // metadata.commit is under free-form parent — allowlist does NOT apply.
        // But git SHA alone is no longer matched by scanner patterns.
        r.redact_json(&mut val);
        assert_eq!(val["id"].as_str().unwrap(), run_id);
        assert_eq!(val["run_id"].as_str().unwrap(), run_id);
        assert_eq!(val["output_blob"].as_str().unwrap(), blob);
        assert_eq!(val["input_blob"].as_str().unwrap(), blob);
        assert_eq!(val["error_blob"].as_str().unwrap(), blob);
        assert_eq!(val["status"].as_str().unwrap(), "Succeeded");
        assert_eq!(val["kind"].as_str().unwrap(), "terminal.output");
        assert_eq!(val["metadata"]["commit"].as_str().unwrap(), sha);
    }

    #[test]
    fn top_level_commit_field_is_allowlisted() {
        let r = redactor();
        let sha = "ea950d8180f520d808274579577db86bc6365a7a";
        let mut val = json!({ "commit": sha, "git_commit": sha });
        r.redact_json(&mut val);
        assert_eq!(val["commit"].as_str().unwrap(), sha);
        assert_eq!(val["git_commit"].as_str().unwrap(), sha);
    }

    #[test]
    fn nested_structural_name_under_metadata_still_redacts_secrets() {
        // Path-aware: key "status" under metadata is free-form, not allowlisted.
        let r = redactor();
        let mut val = json!({
            "metadata": {
                "status": "sk-abcdefghijklmnopqrstuvwxyz012345",
                "kind": "password=supersecretvalue"
            }
        });
        r.redact_json(&mut val);
        assert!(
            val["metadata"]["status"]
                .as_str()
                .unwrap()
                .contains("[REDACTED]"),
            "secret under metadata.status must still redact"
        );
        assert!(
            val["metadata"]["kind"]
                .as_str()
                .unwrap()
                .contains("[REDACTED]"),
            "secret under metadata.kind must still redact"
        );
    }

    #[test]
    fn free_form_preview_still_redacts() {
        let r = redactor();
        let mut val = json!({
            "preview": "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz012345"
        });
        r.redact_json(&mut val);
        assert!(val["preview"].as_str().unwrap().contains("[REDACTED]"));
        assert!(!val["preview"].as_str().unwrap().contains("sk-abcdef"));
    }

    #[test]
    fn event_like_export_shape_preserves_structure_and_redacts_preview() {
        let r = redactor();
        let blob = "d1a7b60df83a72fc820ce76f1883d30dc36f3980ce7570692f7fe30e98ce5b7e";
        let mut val = json!({
            "id": "4bc8c9f7-4600-4c7c-bf30-a39aae08448a",
            "run_id": "939b2397-08b7-43c8-8850-41fedb4f001a",
            "sequence": "13",
            "kind": "terminal.output",
            "source": "Terminal",
            "status": "Success",
            "side_effect": "Unknown",
            "output_blob": blob,
            "metadata": {
                "preview": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12\n",
                "bytes": 40
            }
        });
        r.redact_json(&mut val);
        assert_eq!(val["output_blob"].as_str().unwrap(), blob);
        assert_eq!(val["kind"].as_str().unwrap(), "terminal.output");
        assert!(val["metadata"]["preview"]
            .as_str()
            .unwrap()
            .contains("[REDACTED]"));
        assert!(!val["metadata"]["preview"]
            .as_str()
            .unwrap()
            .contains("ghp_"));
    }
}
