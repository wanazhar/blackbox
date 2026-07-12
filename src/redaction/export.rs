use crate::redaction::scanner::SecretScanner;
use crate::redaction::RedactionConfig;

/// Export-time redaction pass.
///
/// Applies a deeper secret scan before writing trace data to
/// an export file. This is an additional layer beyond the
/// capture-time redaction, catching anything that was missed.
pub struct ExportRedactor {
    scanner: SecretScanner,
}

impl ExportRedactor {
    pub fn new(config: RedactionConfig) -> Self {
        Self {
            scanner: SecretScanner::new(config),
        }
    }

    /// Redact sensitive content from an export payload.
    ///
    /// Scans every string field in the serialized JSON value
    /// and replaces matched secrets with `[REDACTED]`.
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        self.redact_json_inner(value, 0, 32);
    }

    /// Internal recursive redaction with depth tracking.
    ///
    /// Stops recursing at `max_depth` to prevent stack overflow
    /// on adversarially deep JSON.
    fn redact_json_inner(&self, value: &mut serde_json::Value, depth: usize, max_depth: usize) {
        if depth > max_depth {
            return;
        }
        match value {
            serde_json::Value::String(s) => {
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
                for val in obj.values_mut() {
                    self.redact_json_inner(val, depth + 1, max_depth);
                }
            }
            serde_json::Value::Array(arr) => {
                for val in arr.iter_mut() {
                    self.redact_json_inner(val, depth + 1, max_depth);
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
        assert!(token.contains("[REDACTED]"), "nested secret should be redacted");
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
        assert!(deepest.contains("[REDACTED]"), "deeply nested secret should be redacted");
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
}
