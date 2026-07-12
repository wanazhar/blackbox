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
        match value {
            serde_json::Value::String(s) => {
                *s = self.scanner.redact(s);
            }
            serde_json::Value::Object(obj) => {
                for val in obj.values_mut() {
                    self.redact_json(val);
                }
            }
            serde_json::Value::Array(arr) => {
                for val in arr.iter_mut() {
                    self.redact_json(val);
                }
            }
            _ => {}
        }
    }
}
