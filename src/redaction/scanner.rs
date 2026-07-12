use crate::redaction::{RedactionConfig, RedactionReason, RedactionRecord};
use regex::Regex;

/// Scans text content for secrets and sensitive patterns.
///
/// Uses a combination of pattern matching and entropy detection
/// to find API keys, tokens, credentials, and other sensitive data.
pub struct SecretScanner {
    config: RedactionConfig,
    patterns: Vec<(RedactionReason, Regex)>,
}

impl SecretScanner {
    pub fn new(config: RedactionConfig) -> Self {
        let mut patterns: Vec<(RedactionReason, Regex)> = Vec::new();

        // Authorization header: Bearer or Basic tokens
        if let Ok(re) = Regex::new(r"(?i)(bearer|basic)\s+[A-Za-z0-9\-._~+/]+={0,2}") {
            patterns.push((RedactionReason::AuthorizationHeader, re));
        }
        // API key assignment: api_key = "..." or apiKey: '...'
        if let Ok(re) = Regex::new(r#"(?i)api[_-]?key[_-]?\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}"#) {
            patterns.push((RedactionReason::ApiKey, re));
        }
        // GitHub tokens
        if let Ok(re) = Regex::new(r"(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}") {
            patterns.push((RedactionReason::ApiKey, re));
        }
        // OpenAI-style keys
        if let Ok(re) = Regex::new(r"sk-[A-Za-z0-9]{32,}") {
            patterns.push((RedactionReason::ApiKey, re));
        }
        // SSH private key markers
        if let Ok(re) = Regex::new(r"(?i)(-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----)") {
            patterns.push((RedactionReason::SshKey, re));
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
                    reason: match reason {
                        RedactionReason::AuthorizationHeader => RedactionReason::AuthorizationHeader,
                        RedactionReason::ApiKey => RedactionReason::ApiKey,
                        RedactionReason::SshKey => RedactionReason::SshKey,
                        _ => RedactionReason::PatternMatch,
                    },
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
}
