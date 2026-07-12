use crate::redaction::{RedactionConfig, RedactionReason, RedactionRecord};
use regex::Regex;

/// Scans text content for secrets and sensitive patterns.
///
/// Pattern list is intentionally conservative but broader than the
/// original five-regex set: modern cloud tokens, JWTs, and PEM blocks.
pub struct SecretScanner {
    config: RedactionConfig,
    patterns: Vec<(RedactionReason, Regex)>,
}

impl SecretScanner {
    pub fn new(config: RedactionConfig) -> Self {
        let mut patterns: Vec<(RedactionReason, Regex)> = Vec::new();

        let add = |patterns: &mut Vec<(RedactionReason, Regex)>, reason: RedactionReason, re: &str| {
            if let Ok(compiled) = Regex::new(re) {
                patterns.push((reason, compiled));
            }
        };

        // Authorization header: Bearer or Basic tokens
        add(
            &mut patterns,
            RedactionReason::AuthorizationHeader,
            r"(?i)(bearer|basic)\s+[A-Za-z0-9\-._~+/]+=*",
        );
        // API key assignment: api_key = "..." or apiKey: '...'
        add(
            &mut patterns,
            RedactionReason::ApiKey,
            r#"(?i)api[_-]?key[_-]?\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}"#,
        );
        // Generic secret assignment in shell/env style
        add(
            &mut patterns,
            RedactionReason::PatternMatch,
            r#"(?i)(secret|password|passwd|token|credential)[_-]?\s*[:=]\s*['"]?[^\s'"]{8,}"#,
        );
        // GitHub tokens
        add(
            &mut patterns,
            RedactionReason::ApiKey,
            r"(?i)\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b",
        );
        // OpenAI-style / legacy sk- keys
        add(
            &mut patterns,
            RedactionReason::ApiKey,
            r"\bsk-[A-Za-z0-9]{20,}\b",
        );
        // Anthropic-style keys
        add(
            &mut patterns,
            RedactionReason::ApiKey,
            r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b",
        );
        // AWS access key id
        add(
            &mut patterns,
            RedactionReason::CloudCredential,
            r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
        );
        // Slack tokens
        add(
            &mut patterns,
            RedactionReason::ApiKey,
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        );
        // JWT (three base64url segments)
        add(
            &mut patterns,
            RedactionReason::PatternMatch,
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        );
        // SSH / PEM private key markers
        add(
            &mut patterns,
            RedactionReason::SshKey,
            r"(?i)-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        );
        // Connection strings with credentials
        add(
            &mut patterns,
            RedactionReason::ConnectionString,
            r#"(?i)(postgres|mysql|mongodb|redis)://[^\s:]+:[^\s@]+@[^\s]+"#,
        );

        // Custom patterns from config
        for pat in &config.custom_patterns {
            add(&mut patterns, RedactionReason::PatternMatch, pat);
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

    /// Redact sensitive patterns from text, replacing with `[REDACTED]`.
    pub fn redact(&self, text: &str) -> String {
        if !self.config.enabled {
            return text.to_string();
        }
        let mut result = text.to_string();
        for (_, re) in &self.patterns {
            result = re.replace_all(&result, "[REDACTED]").to_string();
        }
        result
    }

    /// Redact every string in a command argv.
    pub fn redact_command(&self, command: &[String]) -> Vec<String> {
        command.iter().map(|s| self.redact(s)).collect()
    }

    /// Recursively redact all strings in a JSON value.
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => {
                *s = self.redact(s);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redaction::RedactionConfig;

    #[test]
    fn redacts_openai_and_aws() {
        let s = SecretScanner::new(RedactionConfig::default());
        let text = "key=sk-abcdefghijklmnopqrstuvwxyz012345 and AKIAIOSFODNN7EXAMPLE";
        let out = s.redact(text);
        assert!(!out.contains("sk-abcdef"));
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_command_argv() {
        let s = SecretScanner::new(RedactionConfig::default());
        let cmd = vec![
            "sh".into(),
            "-c".into(),
            "echo sk-abcdefghijklmnopqrstuvwxyz012345".into(),
        ];
        let red = s.redact_command(&cmd);
        assert!(red[2].contains("[REDACTED]"));
        assert!(!red[2].contains("sk-abcdef"));
    }
}
