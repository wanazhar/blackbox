use crate::redaction::{RedactionConfig, RedactionReason, RedactionRecord};
use regex::Regex;
use std::sync::LazyLock;

/// Compiled base patterns shared across all scanner instances.
/// Custom patterns from config are appended per-instance.
static BASE_PATTERNS: LazyLock<Vec<(RedactionReason, Regex)>> = LazyLock::new(|| {
    let mut patterns: Vec<(RedactionReason, Regex)> = Vec::new();

    let add = |patterns: &mut Vec<(RedactionReason, Regex)>, reason: RedactionReason, re: &str| {
        if let Ok(compiled) = Regex::new(re) {
            patterns.push((reason, compiled));
        }
    };

    add(
        &mut patterns,
        RedactionReason::AuthorizationHeader,
        r"(?i)(bearer|basic)\s+[A-Za-z0-9\-._~+/]+=*",
    );
    add(
        &mut patterns,
        RedactionReason::ApiKey,
        r#"(?i)api[_-]?key[_-]?\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}"#,
    );
    add(
        &mut patterns,
        RedactionReason::PatternMatch,
        r#"(?i)(secret|password|passwd|token|credential)[_-]?\s*[:=]\s*['"]?[^\s'"]{8,}"#,
    );
    add(
        &mut patterns,
        RedactionReason::ApiKey,
        r"(?i)\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b",
    );
    // GitHub fine-grained personal access tokens
    add(
        &mut patterns,
        RedactionReason::ApiKey,
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
    );
    add(
        &mut patterns,
        RedactionReason::ApiKey,
        r"\bsk-[A-Za-z0-9]{20,}\b",
    );
    add(
        &mut patterns,
        RedactionReason::ApiKey,
        r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b",
    );
    // Gemini / Google AI studio style keys already covered by AIza; also xai-
    add(
        &mut patterns,
        RedactionReason::ApiKey,
        r"\bxai-[A-Za-z0-9]{20,}\b",
    );
    add(
        &mut patterns,
        RedactionReason::CloudCredential,
        r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    );
    // AWS secret access key assignment (not bare 40-char base64 — that scars SHAs)
    add(
        &mut patterns,
        RedactionReason::CloudCredential,
        r#"(?i)(aws_secret_access_key|aws_session_token)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{16,}"#,
    );
    add(
        &mut patterns,
        RedactionReason::ApiKey,
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    );
    add(
        &mut patterns,
        RedactionReason::PatternMatch,
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    );
    add(
        &mut patterns,
        RedactionReason::SshKey,
        r"(?i)-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    );
    add(
        &mut patterns,
        RedactionReason::ConnectionString,
        r#"(?i)(postgres|mysql|mongodb|redis)://[^\s:]+:[^\s@]+@[^\s]+"#,
    );
    // Generic basic-auth URLs (https://user:pass@host)
    add(
        &mut patterns,
        RedactionReason::ConnectionString,
        r#"(?i)https?://[^/\s:@]+:[^/\s@]+@[^\s]+"#,
    );
    // Signed URL query params
    add(
        &mut patterns,
        RedactionReason::PatternMatch,
        r#"(?i)([?&](X-Amz-Signature|X-Amz-Credential|Signature|sig|access_token)=)[^&\s]{8,}"#,
    );
    // Cookie / session headers and assignments
    add(
        &mut patterns,
        RedactionReason::Cookie,
        r#"(?i)(set-cookie|cookie)\s*[:=]\s*[^\n;]{8,}"#,
    );
    add(
        &mut patterns,
        RedactionReason::Cookie,
        r#"(?i)(session[_-]?id|sessionid|phpsessid|jsessionid)\s*[:=]\s*['"]?[A-Za-z0-9+/=_-]{8,}"#,
    );
    // npm / pypi / netrc style tokens
    add(
        &mut patterns,
        RedactionReason::ApiKey,
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
    );
    add(
        &mut patterns,
        RedactionReason::ApiKey,
        r"\b(?:sk_live|pk_live|sk_test|pk_test)_[0-9a-zA-Z]{24,}\b",
    );
    add(
        &mut patterns,
        RedactionReason::ApiKey,
        r"\bnpm_[A-Za-z0-9]{36}\b",
    );
    add(
        &mut patterns,
        RedactionReason::ApiKey,
        r#"(?i)(_authToken|pypi-token|PYPI_TOKEN)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}"#,
    );
    // .netrc machine login password lines
    add(
        &mut patterns,
        RedactionReason::PatternMatch,
        r"(?i)(machine\s+\S+\s+login\s+\S+\s+password\s+)\S+",
    );
    // Intentionally NO whole-string base64/hex pattern (e.g. `^[A-Za-z0-9+/]{40,}={0,2}$`).
    // That class matched git SHAs, content-addressed blob keys, and other structural
    // identifiers. PEM private keys are covered by the BEGIN PRIVATE KEY header pattern.
    // Export-time structure is further protected by ExportRedactor's path-aware allowlist.

    patterns
});
/// Scans text content for secrets and sensitive patterns.
///
/// Pattern list is intentionally conservative but broader than the
/// original five-regex set: modern cloud tokens, JWTs, and PEM blocks.
#[derive(Clone)]
pub struct SecretScanner {
    config: RedactionConfig,
    patterns: Vec<(RedactionReason, Regex)>,
}

impl SecretScanner {
    pub fn new(config: RedactionConfig) -> Self {
        let mut patterns = BASE_PATTERNS.clone();

        // Custom patterns from config (compiled fresh per instance)
        for pat in &config.custom_patterns {
            if let Ok(compiled) = Regex::new(pat) {
                patterns.push((RedactionReason::PatternMatch, compiled));
            }
        }

        Self { config, patterns }
    }

    /// Scan text for secrets and return redaction records.
    pub fn scan(&self, text: &str, location: &str, event_id: Option<&str>) -> Vec<RedactionRecord> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut records = Vec::new();
        for (reason, re) in &self.patterns {
            if re.is_match(text) {
                records.push(RedactionRecord {
                    reason: reason.clone(),
                    pattern: re.as_str().to_string(),
                    location: location.to_string(),
                    event_id: event_id.map(String::from),
                });
            }
        }
        records
    }

    /// Collect merged byte-spans of secret matches in `text`.
    ///
    /// Spans are half-open `[start, end)` into the original string and
    /// never overlap after merging. Used by stream redaction to catch
    /// secrets that straddle PTY chunk boundaries.
    pub fn find_spans(&self, text: &str) -> Vec<(usize, usize)> {
        if !self.config.enabled || text.is_empty() {
            return Vec::new();
        }
        let mut spans: Vec<(usize, usize)> = Vec::new();
        for (_, re) in &self.patterns {
            for m in re.find_iter(text) {
                spans.push((m.start(), m.end()));
            }
        }
        spans.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for span in spans {
            if let Some(last) = merged.last_mut() {
                if span.0 <= last.1 {
                    last.1 = last.1.max(span.1);
                    continue;
                }
            }
            merged.push(span);
        }
        merged
    }

    /// Redact sensitive patterns from text, replacing with `[REDACTED]`.
    ///
    /// Uses a span-merging approach: all patterns are applied to the
    /// original text, non-overlapping match spans are collected, and
    /// replacement happens in a single pass. This prevents corruption
    /// where a previous `[REDACTED]` replacement would be re-matched
    /// by subsequent patterns.
    pub fn redact(&self, text: &str) -> String {
        if !self.config.enabled {
            return text.to_string();
        }

        let merged = self.find_spans(text);
        if merged.is_empty() {
            return text.to_string();
        }

        // Build the redacted string in a single pass.
        let mut result = String::with_capacity(text.len());
        let mut cursor = 0;
        for (start, end) in &merged {
            // Ensure we only slice at char boundaries (regex is UTF-8 safe,
            // but be defensive for adversarial inputs).
            let start = text.floor_char_boundary(*start);
            let end = text.floor_char_boundary(*end);
            if cursor < start {
                result.push_str(&text[cursor..start]);
            }
            result.push_str("[REDACTED]");
            cursor = end;
        }
        if cursor < text.len() {
            result.push_str(&text[cursor..]);
        }
        result
    }

    /// Redact every string in a command argv.
    pub fn redact_command(&self, command: &[String]) -> Vec<String> {
        command.iter().map(|s| self.redact(s)).collect()
    }

    /// Recursively redact all strings in a JSON value.
    ///
    /// Handles non-string values by converting them to string
    /// representation for pattern matching, preventing secret bypass
    /// via numeric or boolean JSON values.
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        self.redact_json_inner(value, 0, 32);
    }

    /// Internal recursive redaction with depth tracking.
    ///
    /// Stops recursing at `max_depth` (default 32) to prevent stack
    /// overflow on adversarially deep JSON.
    fn redact_json_inner(&self, value: &mut serde_json::Value, depth: usize, max_depth: usize) {
        if depth > max_depth {
            return;
        }
        match value {
            serde_json::Value::String(s) => {
                *s = self.redact(s);
            }
            serde_json::Value::Number(n) => {
                // Convert number to string for secret scanning
                let s = n.to_string();
                let redacted = self.redact(&s);
                if redacted != s {
                    // Number contained a secret pattern — replace with redacted string
                    *value = serde_json::Value::String(redacted);
                }
            }
            serde_json::Value::Bool(b) => {
                let s = b.to_string();
                let redacted = self.redact(&s);
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
    use crate::redaction::RedactionConfig;
    use serde_json::json;

    fn default_scanner() -> SecretScanner {
        SecretScanner::new(RedactionConfig::default())
    }

    #[test]
    fn redacts_openai_and_aws() {
        let s = default_scanner();
        let text = "key=sk-abcdefghijklmnopqrstuvwxyz012345 and AKIAIOSFODNN7EXAMPLE";
        let out = s.redact(text);
        assert!(!out.contains("sk-abcdef"));
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_command_argv() {
        let s = default_scanner();
        let cmd = vec![
            "sh".into(),
            "-c".into(),
            "echo sk-abcdefghijklmnopqrstuvwxyz012345".into(),
        ];
        let red = s.redact_command(&cmd);
        assert!(red[2].contains("[REDACTED]"));
        assert!(!red[2].contains("sk-abcdef"));
    }

    // --- GitHub tokens (ghp_*, gho_*, ghu_*, ghs_*, ghr_*) ---

    #[test]
    fn redacts_github_personal_token() {
        let s = default_scanner();
        let text = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12";
        let out = s.redact(text);
        assert_eq!(out, "[REDACTED]", "generic token= pattern matches first");
    }

    #[test]
    fn redacts_github_oauth_token() {
        let s = default_scanner();
        let text = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12 push";
        let out = s.redact(text);
        assert!(!out.contains("gho_"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_github_app_token() {
        let s = default_scanner();
        let text = "ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12";
        let out = s.redact(text);
        assert_eq!(out, "[REDACTED]");
    }

    #[test]
    fn redacts_github_refresh_token() {
        let s = default_scanner();
        let text = "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12";
        let out = s.redact(text);
        assert_eq!(out, "[REDACTED]");
    }

    #[test]
    fn redacts_github_runner_token() {
        let s = default_scanner();
        let text = "ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12";
        let out = s.redact(text);
        assert_eq!(out, "[REDACTED]");
    }

    // --- Slack tokens (xoxb-*, xoxp-*, xoxa-*, xoxr-*) ---

    #[test]
    fn redacts_slack_bot_token() {
        let s = default_scanner();
        let text = format!(
            "export SLACK_TOKEN={}",
            concat!(
                "xox",
                "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
            )
        );
        let out = s.redact(&text);
        assert!(!out.contains("xoxb-"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_slack_user_token() {
        let s = default_scanner();
        let text = concat!(
            "xox",
            "p-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
        );
        let out = s.redact(text);
        assert_eq!(out, "[REDACTED]");
    }

    #[test]
    fn redacts_slack_app_token() {
        let s = default_scanner();
        let text = concat!(
            "xox",
            "a-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
        );
        let out = s.redact(text);
        assert_eq!(out, "[REDACTED]");
    }

    #[test]
    fn redacts_slack_refresh_token() {
        let s = default_scanner();
        let text = concat!(
            "xox",
            "r-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
        );
        let out = s.redact(text);
        assert_eq!(out, "[REDACTED]");
    }

    // --- JWT redaction ---

    #[test]
    fn redacts_jwt_token() {
        let s = default_scanner();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let text = format!("Authorization: Bearer {}", jwt);
        let out = s.redact(&text);
        assert!(!out.contains("eyJhbGci"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn scan_returns_jwt_pattern_match() {
        let s = default_scanner();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef1234567890abcdef";
        let records = s.scan(jwt, "test", None);
        let jwt_records: Vec<_> = records
            .iter()
            .filter(|r| r.reason == RedactionReason::PatternMatch)
            .collect();
        assert!(!jwt_records.is_empty(), "should detect JWT as PatternMatch");
    }

    // --- SSH PEM key redaction ---

    #[test]
    fn redacts_ssh_pem_private_key() {
        let s = default_scanner();
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0...";
        let out = s.redact(text);
        assert!(!out.contains("BEGIN RSA PRIVATE KEY"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_openssh_private_key() {
        let s = default_scanner();
        let text = "-----BEGIN OPENSSH PRIVATE KEY-----";
        let out = s.redact(text);
        assert_eq!(out, "[REDACTED]");
    }

    #[test]
    fn redacts_ec_private_key() {
        let s = default_scanner();
        let text = "-----BEGIN EC PRIVATE KEY-----";
        let out = s.redact(text);
        assert_eq!(out, "[REDACTED]");
    }

    #[test]
    fn redacts_encrypted_private_key() {
        let s = default_scanner();
        let text = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        let out = s.redact(text);
        assert_eq!(out, "[REDACTED]");
    }

    // --- Connection string redaction ---

    #[test]
    fn redacts_postgres_connection_string() {
        let s = default_scanner();
        let text = "DATABASE_URL=postgres://admin:s3cret@db.example.com:5432/mydb";
        let out = s.redact(text);
        assert!(!out.contains("admin:s3cret"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_mysql_connection_string() {
        let s = default_scanner();
        let text = "mysql://root:passw0rd@localhost/mydb";
        let out = s.redact(text);
        assert!(!out.contains("root:passw0rd"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_mongodb_connection_string() {
        let s = default_scanner();
        let text = "mongodb://user:secret123@mongo.example.com:27017/db";
        let out = s.redact(text);
        assert!(!out.contains("user:secret123"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_redis_connection_string() {
        let s = default_scanner();
        let text = "redis://default:mypassword@redis.example.com:6379/0";
        let out = s.redact(text);
        assert!(!out.contains("mypassword"));
        assert!(out.contains("[REDACTED]"));
    }

    // --- Anthropic key redaction ---

    #[test]
    fn redacts_anthropic_key() {
        let s = default_scanner();
        let text = "key=sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456";
        let out = s.redact(text);
        assert!(!out.contains("sk-ant-api03"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn scan_detects_anthropic_key() {
        let s = default_scanner();
        let records = s.scan(
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456",
            "test",
            None,
        );
        assert!(
            records.iter().any(|r| r.reason == RedactionReason::ApiKey),
            "should detect Anthropic key as ApiKey"
        );
    }

    // --- redact_json with nested objects and arrays ---

    #[test]
    fn redact_json_nested_objects() {
        let s = default_scanner();
        let mut val = json!({
            "outer": {
                "inner": {
                    "key": "sk-abcdefghijklmnopqrstuvwxyz012345"
                }
            }
        });
        s.redact_json(&mut val);
        let inner_key = val["outer"]["inner"]["key"].as_str().unwrap();
        assert_eq!(inner_key, "[REDACTED]");
    }

    #[test]
    fn redact_json_arrays() {
        let s = default_scanner();
        let mut val = json!({
            "tokens": [
                "normal text",
                "sk-abcdefghijklmnopqrstuvwxyz012345",
                "another normal string"
            ]
        });
        s.redact_json(&mut val);
        let arr = val["tokens"].as_array().unwrap();
        assert_eq!(arr[0].as_str().unwrap(), "normal text");
        assert_eq!(arr[1].as_str().unwrap(), "[REDACTED]");
        assert_eq!(arr[2].as_str().unwrap(), "another normal string");
    }

    #[test]
    fn redact_json_mixed_nesting() {
        let s = default_scanner();
        let mut val = json!({
            "data": [
                {"token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12"},
                {"safe": "hello"}
            ]
        });
        s.redact_json(&mut val);
        let data = val["data"].as_array().unwrap();
        assert_eq!(data[0]["token"].as_str().unwrap(), "[REDACTED]");
        assert_eq!(data[1]["safe"].as_str().unwrap(), "hello");
    }

    // --- redact_json with non-string values (numbers, booleans) ---

    #[test]
    fn redact_json_numbers_pass_through_unchanged() {
        let s = default_scanner();
        let mut val = json!({"count": 42, "val": 1.234});
        s.redact_json(&mut val);
        assert_eq!(val["count"].as_i64().unwrap(), 42);
        assert_eq!(val["val"].as_f64().unwrap(), 1.234);
    }

    #[test]
    fn redact_json_booleans_pass_through_unchanged() {
        let s = default_scanner();
        let mut val = json!({"flag": true, "other": false});
        s.redact_json(&mut val);
        assert!(val["flag"].as_bool().unwrap());
        assert!(!val["other"].as_bool().unwrap());
    }

    #[test]
    fn redact_json_null_passes_through() {
        let s = default_scanner();
        let mut val = json!({"nothing": null});
        s.redact_json(&mut val);
        assert!(val["nothing"].is_null());
    }

    // --- scan() returns correct RedactionRecord fields ---

    #[test]
    fn scan_returns_correct_record_fields() {
        let s = default_scanner();
        let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12";
        let records = s.scan(text, "test_location", Some("evt-42"));
        assert!(!records.is_empty());
        let record = &records[0];
        assert_eq!(record.reason, RedactionReason::ApiKey);
        assert_eq!(record.location, "test_location");
        assert_eq!(record.event_id.as_deref(), Some("evt-42"));
        assert!(!record.pattern.is_empty());
    }

    #[test]
    fn scan_records_event_id_none_when_not_provided() {
        let s = default_scanner();
        let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12";
        let records = s.scan(text, "loc", None);
        assert!(records.iter().all(|r| r.event_id.is_none()));
    }

    // --- disabled config returns empty results ---

    #[test]
    fn disabled_config_returns_empty_redact() {
        let config = RedactionConfig {
            enabled: false,
            ..Default::default()
        };
        let s = SecretScanner::new(config);
        let text = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let out = s.redact(text);
        assert_eq!(out, text, "disabled scanner must not modify text");
    }

    #[test]
    fn disabled_config_returns_empty_scan() {
        let config = RedactionConfig {
            enabled: false,
            ..Default::default()
        };
        let s = SecretScanner::new(config);
        let records = s.scan("sk-abcdefghijklmnopqrstuvwxyz012345", "test", None);
        assert!(
            records.is_empty(),
            "disabled scanner must return no records"
        );
    }

    // --- custom patterns from config ---

    #[test]
    fn custom_patterns_detected_by_scan() {
        let config = RedactionConfig {
            enabled: true,
            custom_patterns: vec![r"(?i)my_secret_[a-z0-9]+".into()],
            ..Default::default()
        };
        let s = SecretScanner::new(config);
        let text = "val=my_secret_abcdef123456";
        let records = s.scan(text, "test", None);
        assert!(
            records
                .iter()
                .any(|r| r.reason == RedactionReason::PatternMatch),
            "custom pattern should be detected"
        );
    }

    #[test]
    fn custom_patterns_redacted() {
        let config = RedactionConfig {
            enabled: true,
            custom_patterns: vec![r"(?i)my_secret_[a-z0-9]+".into()],
            ..Default::default()
        };
        let s = SecretScanner::new(config);
        let text = "val=my_secret_abcdef123456";
        let out = s.redact(text);
        assert!(!out.contains("my_secret_abcdef123456"));
        assert!(out.contains("[REDACTED]"));
    }

    // --- sequential redaction doesn't corrupt text (C-09 fix) ---

    #[test]
    fn sequential_redaction_preserves_surrounding_text() {
        let s = default_scanner();
        let text = "prefix ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12 suffix";
        let out = s.redact(text);
        assert!(out.starts_with("prefix "));
        assert!(out.ends_with(" suffix"));
        assert_eq!(out, "prefix [REDACTED] suffix");
    }

    #[test]
    fn multiple_secrets_in_one_string_all_redacted() {
        let s = default_scanner();
        let text = "key1=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12 key2=sk-abcdefghijklmnopqrstuvwxyz012345";
        let out = s.redact(text);
        assert!(!out.contains("ghp_"));
        assert!(!out.contains("sk-abcdef"));
        assert_eq!(out, "key1=[REDACTED] key2=[REDACTED]");
    }

    #[test]
    fn redaction_does_not_corrupt_non_secret_text() {
        let s = default_scanner();
        let text = "The quick brown fox jumps over the lazy dog. No secrets here.";
        let out = s.redact(text);
        assert_eq!(out, text, "non-secret text must be unchanged");
    }

    #[test]
    fn redaction_preserves_adjacent_secret_fragments() {
        let s = default_scanner();
        let text = "postgres://admin:s3cret@db.com AKIAIOSFODNN7EXAMPLE";
        let out = s.redact(text);
        assert!(!out.contains("s3cret"));
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(out.contains("[REDACTED]"));
    }

    // --- scan returns multiple records for multi-pattern matches ---

    #[test]
    fn scan_returns_record_per_matching_pattern() {
        let s = default_scanner();
        let text = "key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12 and AKIAIOSFODNN7EXAMPLE";
        let records = s.scan(text, "loc", None);
        let reasons: Vec<_> = records.iter().map(|r| &r.reason).collect();
        assert!(
            reasons.contains(&&RedactionReason::ApiKey),
            "should find GitHub token"
        );
        assert!(
            reasons.contains(&&RedactionReason::CloudCredential),
            "should find AWS key"
        );
    }

    // --- Structural identifiers must NOT match (false-positive regression) ---

    #[test]
    fn does_not_redact_git_sha1() {
        let s = default_scanner();
        let sha = "ea950d8180f520d808274579577db86bc6365a7a";
        assert_eq!(s.redact(sha), sha);
        assert!(s.scan(sha, "git.commit", None).is_empty());
    }

    #[test]
    fn does_not_redact_sha256_blob_key() {
        let s = default_scanner();
        let key = "22c8e61f11fd0f02da754f5b2fa912f842c7ed27a056f5b38f882f820baf37d5";
        assert_eq!(s.redact(key), key);
        assert!(s.scan(key, "output_blob", None).is_empty());
    }

    #[test]
    fn does_not_redact_uuid() {
        let s = default_scanner();
        let id = "939b2397-08b7-43c8-8850-41fedb4f001a";
        assert_eq!(s.redact(id), id);
    }

    /// Golden matrix: each BASE_PATTERNS family still fires on a representative secret.
    #[test]
    fn base_patterns_golden_matrix_still_redacts_secrets() {
        let s = default_scanner();
        let cases: &[(&str, &str)] = &[
            ("bearer", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"),
            ("api_key", "api_key=abcdefghijklmnopqrstuvwxyz012345"),
            ("password", "password=supersecretvalue"),
            (
                "ghp",
                "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12",
            ),
            ("sk", "sk-abcdefghijklmnopqrstuvwxyz012345"),
            (
                "sk-ant",
                "sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456",
            ),
            ("akia", "AKIAIOSFODNN7EXAMPLE"),
            (
                "slack",
                concat!(
                    "xox",
                    "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
                ),
            ),
            (
                "jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            ),
            ("pem", "-----BEGIN RSA PRIVATE KEY-----"),
            (
                "postgres",
                "postgres://admin:s3cret@db.example.com:5432/mydb",
            ),
            (
                "google",
                // Pattern: AIza + exactly 35 [0-9A-Za-z\-_]
                "AIzaSyAabcdefghijklmnopqrstuvwxyz012345",
            ),
            (
                "stripe",
                // Pattern requires 24+ alnum after sk_live_ — split for GitHub push protection
                concat!("sk_live_", "abcdefghijklmnopqrstuvwx"),
            ),
            (
                "npm",
                "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            ),
        ];
        for (name, secret) in cases {
            let out = s.redact(secret);
            assert!(
                out.contains("[REDACTED]"),
                "BASE pattern family '{name}' should redact sample; got {out:?}"
            );
            assert!(
                out != *secret || secret.contains("[REDACTED]"),
                "BASE pattern family '{name}' left secret intact"
            );
        }
    }
}
