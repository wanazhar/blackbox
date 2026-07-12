use crate::analysis::AnalysisPass;
use crate::core::event::{EventSource, EventStatus, TraceEvent};

/// Detects error conditions in event streams.
///
/// Flags events with error status, parses common error
/// output formats (test failures, compiler errors, stack traces),
/// and enriches the trace with structured error metadata.
pub struct ErrorDetector;

impl Default for ErrorDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorDetector {
    pub fn new() -> Self {
        Self
    }

    /// Check if an event represents an error condition.
    pub fn is_error(&self, event: &TraceEvent) -> bool {
        event.status == EventStatus::Error
            || event
                .metadata
                .get("exit_code")
                .and_then(|v| v.as_i64())
                .map(|c| c != 0)
                .unwrap_or(false)
    }

    /// Extract structured error information from output.
    ///
    /// Recognizes:
    /// - Rust compiler errors
    /// - TypeScript/JavaScript errors
    /// - Python tracebacks
    /// - Test framework failures
    /// - Generic process failures
    pub fn extract_errors(&self, event: &TraceEvent) -> Vec<StructuredError> {
        let output = self.get_output_text(event);
        if output.is_empty() {
            return Vec::new();
        }

        let mut errors = Vec::new();

        // Rust compiler errors: "error[E0xxx]: message"
        let lines: Vec<&str> = output.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            // error[E must appear at the start of a diagnostic line (after
            // optional whitespace), not in the middle of a warning message.
            if line.trim().starts_with("error[E") {
                let trimmed_line = line.trim();
                let rest = trimmed_line;
                if let Some(colon) = rest.find(": ") {
                    // Extract error code between "error[E" (6 chars) and "]" before ": ".
                    // Guard against malformed lines where "]" is missing or colon is too close.
                    if colon > 7 && rest.as_bytes().get(5) == Some(&b'[') {
                        let code = &rest[6..colon - 1]; // skip "error[", exclude trailing "]"
                        let message = &rest[colon + 2..];
                        // Location may be on the same line or the next line (Rust style)
                        let (file, line_num, col) = if self.parse_file_location(trimmed_line).0.is_some() {
                            self.parse_file_location(trimmed_line)
                        } else {
                            lines.get(i + 1).map(|next| self.parse_file_location(next)).unwrap_or((None, None, None))
                        };
                        errors.push(StructuredError {
                            error_type: format!("rustc[{}]", code),
                            message: message.to_string(),
                            file,
                            line: line_num,
                            column: col,
                        });
                    }
                }
            }
        }

        // TypeScript/JavaScript errors: "Error:", "TypeError:", "ReferenceError:", etc.
        let js_error_prefixes = [
            "Error:",
            "TypeError:",
            "ReferenceError:",
            "SyntaxError:",
            "RangeError:",
            "URIError:",
            "EvalError:",
        ];
        for line in output.lines() {
            let trimmed = line.trim();
            for prefix in &js_error_prefixes {
                if let Some(rest) = trimmed.strip_prefix(prefix) {
                    // Require whitespace or end-of-line after the error prefix
                    // to avoid matching identifiers like "MyError:"
                    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
                        continue;
                    }
                    let message = rest.trim().to_string();
                    let (file, line_num, col) = self.parse_file_location(trimmed);
                    errors.push(StructuredError {
                        error_type: "javascript".to_string(),
                        message,
                        file,
                        line: line_num,
                        column: col,
                    });
                    break;
                }
            }
        }

        // Python tracebacks: "Traceback (most recent call last):"
        // The traceback block ends at the first non-empty line after the
        // indented frames, or at the next "Traceback" header.  We scan
        // backward from the bottom and stop at those boundaries so we
        // don't pick up unrelated ": " patterns from other output.
        if output.contains("Traceback") {
            let lines: Vec<&str> = output.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if line.trim().starts_with("Traceback") {
                    // Scan backward from the last line to find the error line.
                    // Stop at traceback block boundaries: another "Traceback"
                    // header or a line starting with "File " (traceback frame).
                    for j in (i + 1..lines.len()).rev() {
                        let trimmed = lines[j].trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        // Stop at block boundaries — we've left this traceback
                        if trimmed.starts_with("Traceback") || trimmed.starts_with("File \"") {
                            break;
                        }
                        if let Some(colon_idx) = trimmed.find(": ") {
                            let error_type = trimmed[..colon_idx].to_string();
                            let message = trimmed[colon_idx + 2..].to_string();
                            let (file, line_num, col) = self.parse_file_location(trimmed);
                            errors.push(StructuredError {
                                error_type,
                                message,
                                file,
                                line: line_num,
                                column: col,
                            });
                            break;
                        }
                    }
                    break; // Only process first traceback
                }
            }
        }

        // Test framework failures: "FAILED", "failures:"
        // Anchor to line start to avoid false positives on lines like
        // "info: test completed, NOT FAILED" embedded in log output.
        if output.lines().any(|l| l.trim().starts_with("FAILED")) {
            let message = output
                .lines()
                .find(|l| l.trim().starts_with("FAILED"))
                .unwrap_or("")
                .trim()
                .to_string();
            let (file, line_num, col) = self.parse_file_location(&message);
            errors.push(StructuredError {
                error_type: "test_failure".to_string(),
                message,
                file,
                line: line_num,
                column: col,
            });
        } else if output.lines().any(|l| l.trim().starts_with("failures:")) {
            let message = output
                .lines()
                .find(|l| l.trim().starts_with("failures:"))
                .unwrap_or("")
                .trim()
                .to_string();
            errors.push(StructuredError {
                error_type: "test_failure".to_string(),
                message,
                file: None,
                line: None,
                column: None,
            });
        }

        // Generic error: non-zero exit without specific patterns above
        if errors.is_empty() && self.is_error(event) {
            let message = output.lines().next().unwrap_or("unknown error").trim().to_string();
            errors.push(StructuredError {
                error_type: "process_error".to_string(),
                message,
                file: None,
                line: None,
                column: None,
            });
        }

        errors
    }

    /// Extract output text from event metadata.
    ///
    /// Prefers full text fields; falls back to short previews.
    /// (Blob payloads require a store handle — use `inspect` for those.)
    fn get_output_text(&self, event: &TraceEvent) -> String {
        for key in &["output_full", "normalized", "preview", "output", "raw"] {
            if let Some(val) = event.metadata.get(*key) {
                if let Some(s) = val.as_str() {
                    return s.to_string();
                }
                // output may be a JSON value
                if *key == "output" {
                    return val.to_string();
                }
            }
        }
        String::new()
    }

    /// Parse file location from a line like " --> file.rs:10:5" or "at file.ts:10:5".
    fn parse_file_location(&self, line: &str) -> (Option<String>, Option<u32>, Option<u32>) {
        // Rust-style: " --> file.rs:10:5"
        if let Some(idx) = line.find(" --> ") {
            let location = &line[idx + 5..];
            return self.parse_colon_location(location);
        }
        // Node-style: "at file.ts:10:5" or "    at file.ts:10:5"
        if let Some(idx) = line.find(" at ") {
            let location = &line[idx + 4..];
            return self.parse_colon_location(location);
        }
        // Python-style: '  File "file.py", line 10'
        if let Some(idx) = line.find("File \"") {
            let after_quote = &line[idx + 6..];
            if let Some(end_quote) = after_quote.find('"') {
                let file = after_quote[..end_quote].to_string();
                let rest = &after_quote[end_quote..];
                if let Some(line_idx) = rest.find("line ") {
                    let num_str = &rest[line_idx + 5..];
                    let num_str: String = num_str.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(line_num) = num_str.parse::<u32>() {
                        return (Some(file), Some(line_num), None);
                    }
                }
                return (Some(file), None, None);
            }
        }
        (None, None, None)
    }

    /// Parse "file.rs:10:5" or "file.rs:10" location strings.
    fn parse_colon_location(&self, location: &str) -> (Option<String>, Option<u32>, Option<u32>) {
        let trimmed = location.trim();
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() >= 2 {
            let file = parts[0].to_string();
            if let Ok(line_num) = parts[1].parse::<u32>() {
                let col = parts.get(2).and_then(|s| s.parse::<u32>().ok());
                return (Some(file), Some(line_num), col);
            }
        }
        (None, None, None)
    }
}

/// A structured error extracted from event output.
#[derive(Debug, Clone)]
pub struct StructuredError {
    pub error_type: String,
    pub message: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

#[async_trait::async_trait]
impl AnalysisPass for ErrorDetector {
    fn name(&self) -> &'static str {
        "error-detector"
    }

    async fn analyze(&self, events: &[TraceEvent]) -> anyhow::Result<Vec<TraceEvent>> {
        let mut derived = Vec::new();
        for event in events {
            let errors = self.extract_errors(event);
            for err in errors {
                let mut meta = std::collections::HashMap::new();
                meta.insert(
                    "error_type".to_string(),
                    serde_json::Value::String(err.error_type),
                );
                meta.insert(
                    "message".to_string(),
                    serde_json::Value::String(err.message),
                );
                if let Some(file) = err.file {
                    meta.insert("file".to_string(), serde_json::Value::String(file));
                }
                if let Some(line) = err.line {
                    meta.insert("line".to_string(), serde_json::Value::Number(line.into()));
                }
                if let Some(col) = err.column {
                    meta.insert("column".to_string(), serde_json::Value::Number(col.into()));
                }
                meta.insert(
                    "source_event_id".to_string(),
                    serde_json::Value::String(event.id.clone()),
                );

                let mut derived_event =
                    TraceEvent::new(&event.run_id, EventSource::System, "analysis.error");
                derived_event.parent_event_id = Some(event.id.clone());
                derived_event.metadata = meta;
                derived.push(derived_event);
            }
        }
        Ok(derived)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_event(kind: &str, metadata: HashMap<String, serde_json::Value>) -> TraceEvent {
        let mut event = TraceEvent::new("run-1", EventSource::Terminal, kind);
        event.metadata = metadata;
        event
    }

    #[test]
    fn extract_rust_error() {
        let det = ErrorDetector::new();
        let mut meta = HashMap::new();
        meta.insert(
            "normalized".to_string(),
            serde_json::Value::String(
                "error[E0382]: borrow of moved value: `x`\n --> src/main.rs:10:5".to_string(),
            ),
        );
        let event = make_event("terminal.output", meta);
        let errors = det.extract_errors(&event);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].error_type, "rustc[E0382]");
        assert_eq!(errors[0].file.as_deref(), Some("src/main.rs"));
        assert_eq!(errors[0].line, Some(10));
    }

    #[test]
    fn extract_js_error() {
        let det = ErrorDetector::new();
        let mut meta = HashMap::new();
        meta.insert(
            "raw".to_string(),
            serde_json::Value::String(
                "TypeError: Cannot read property 'map' of undefined\n    at processItems (app.ts:42:10)"
                    .to_string(),
            ),
        );
        let event = make_event("terminal.output", meta);
        let errors = det.extract_errors(&event);
        assert!(!errors.is_empty());
        assert_eq!(errors[0].error_type, "javascript");
    }

    #[test]
    fn extract_python_error() {
        let det = ErrorDetector::new();
        let mut meta = HashMap::new();
        meta.insert(
            "normalized".to_string(),
            serde_json::Value::String(
                "Traceback (most recent call last):\n  File \"main.py\", line 10\n    foo()\nNameError: name 'foo' is not defined"
                    .to_string(),
            ),
        );
        let event = make_event("terminal.output", meta);
        let errors = det.extract_errors(&event);
        assert!(!errors.is_empty());
        assert_eq!(errors[0].error_type, "NameError");
    }

    #[test]
    fn extract_test_failure() {
        let det = ErrorDetector::new();
        let mut meta = HashMap::new();
        meta.insert(
            "normalized".to_string(),
            serde_json::Value::String(
                "test test_foo ... FAILED\nfailures:\n  test_foo".to_string(),
            ),
        );
        let event = make_event("terminal.output", meta);
        let errors = det.extract_errors(&event);
        assert!(!errors.is_empty());
        assert_eq!(errors[0].error_type, "test_failure");
    }

    #[test]
    fn no_output_returns_empty() {
        let det = ErrorDetector::new();
        let event = make_event("terminal.output", HashMap::new());
        let errors = det.extract_errors(&event);
        assert!(errors.is_empty());
    }
}
