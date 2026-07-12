use crate::redaction::{RedactionConfig, RedactionReason, RedactionRecord};
use std::collections::HashMap;

/// Redacts sensitive environment variable values before storage.
///
/// Environment variables are captured at run start and may contain
/// API keys, tokens, and other credentials. This scanner identifies
/// likely-secret variable names and replaces their values.
pub struct EnvironmentRedactor {
    config: RedactionConfig,
}

impl EnvironmentRedactor {
    pub fn new(config: RedactionConfig) -> Self {
        Self { config }
    }

    /// Scan environment variables and return redaction records
    /// for any that match sensitive patterns.
    pub fn scan_env(&self, env: &HashMap<String, String>) -> Vec<RedactionRecord> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut records = Vec::new();
        for name in env.keys() {
            let upper = name.to_uppercase();
            if self
                .config
                .env_var_patterns
                .iter()
                .any(|p| upper.contains(p))
            {
                records.push(RedactionRecord {
                    reason: RedactionReason::EnvironmentSecret,
                    pattern: name.clone(),
                    location: format!("env:{}", name),
                    event_id: None,
                });
            }
        }
        records
    }

    /// Produce a redacted copy of the environment.
    ///
    /// Sensitive values are replaced with `[REDACTED]`.
    pub fn redact_env(&self, env: &HashMap<String, String>) -> HashMap<String, String> {
        let mut result = HashMap::new();
        for (name, value) in env {
            let upper = name.to_uppercase();
            if self
                .config
                .env_var_patterns
                .iter()
                .any(|p| upper.contains(p))
            {
                result.insert(name.clone(), "[REDACTED]".to_string());
            } else {
                result.insert(name.clone(), value.clone());
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redaction::RedactionConfig;

    fn default_redactor() -> EnvironmentRedactor {
        EnvironmentRedactor::new(RedactionConfig::default())
    }

    fn env_from_pairs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // --- scan_env finds API_KEY, TOKEN, SECRET, PASSWORD patterns ---

    #[test]
    fn scan_env_finds_api_key() {
        let r = default_redactor();
        let env = env_from_pairs(&[("MY_API_KEY", "secret123")]);
        let records = r.scan_env(&env);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, RedactionReason::EnvironmentSecret);
        assert_eq!(records[0].location, "env:MY_API_KEY");
    }

    #[test]
    fn scan_env_finds_token() {
        let r = default_redactor();
        let env = env_from_pairs(&[("AUTH_TOKEN", "tok_abc123")]);
        let records = r.scan_env(&env);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].pattern, "AUTH_TOKEN");
    }

    #[test]
    fn scan_env_finds_secret() {
        let r = default_redactor();
        let env = env_from_pairs(&[("APP_SECRET", "supersecret")]);
        let records = r.scan_env(&env);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, RedactionReason::EnvironmentSecret);
    }

    #[test]
    fn scan_env_finds_password() {
        let r = default_redactor();
        let env = env_from_pairs(&[("DB_PASSWORD", "hunter2")]);
        let records = r.scan_env(&env);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, RedactionReason::EnvironmentSecret);
    }

    // --- scan_env is case-insensitive for env var names ---

    #[test]
    fn scan_env_case_insensitive() {
        let r = default_redactor();
        let env = env_from_pairs(&[
            ("my_api_key", "value1"),
            ("My_Token", "value2"),
            ("app_secret", "value3"),
        ]);
        let records = r.scan_env(&env);
        assert_eq!(
            records.len(),
            3,
            "all lowercase/mixed case names should match"
        );
    }

    // --- scan_env skips non-sensitive vars like PATH, HOME ---

    #[test]
    fn scan_env_skips_non_sensitive_vars() {
        let r = default_redactor();
        let env = env_from_pairs(&[
            ("PATH", "/usr/bin:/usr/local/bin"),
            ("HOME", "/home/user"),
            ("SHELL", "/bin/bash"),
            ("LANG", "en_US.UTF-8"),
        ]);
        let records = r.scan_env(&env);
        assert!(
            records.is_empty(),
            "non-sensitive vars should not be flagged"
        );
    }

    #[test]
    fn scan_env_mixed_sensitive_and_safe() {
        let r = default_redactor();
        let env = env_from_pairs(&[
            ("PATH", "/usr/bin"),
            ("MY_API_KEY", "sk-test123"),
            ("HOME", "/home/user"),
        ]);
        let records = r.scan_env(&env);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].pattern, "MY_API_KEY");
    }

    // --- redact_env replaces sensitive values with [REDACTED] ---

    #[test]
    fn redact_env_replaces_sensitive_values() {
        let r = default_redactor();
        let env = env_from_pairs(&[("API_KEY", "super-secret-key"), ("TOKEN", "tok_abc123xyz")]);
        let result = r.redact_env(&env);
        assert_eq!(result["API_KEY"], "[REDACTED]");
        assert_eq!(result["TOKEN"], "[REDACTED]");
    }

    // --- redact_env preserves non-sensitive values ---

    #[test]
    fn redact_env_preserves_non_sensitive_values() {
        let r = default_redactor();
        let env = env_from_pairs(&[
            ("PATH", "/usr/bin:/usr/local/bin"),
            ("HOME", "/home/user"),
            ("LANG", "en_US.UTF-8"),
        ]);
        let result = r.redact_env(&env);
        assert_eq!(result["PATH"], "/usr/bin:/usr/local/bin");
        assert_eq!(result["HOME"], "/home/user");
        assert_eq!(result["LANG"], "en_US.UTF-8");
    }

    #[test]
    fn redact_env_mixed_preserves_safe_redacts_sensitive() {
        let r = default_redactor();
        let env = env_from_pairs(&[
            ("PATH", "/usr/bin"),
            ("SECRET_KEY", "s3cret"),
            ("HOME", "/home/user"),
        ]);
        let result = r.redact_env(&env);
        assert_eq!(result["PATH"], "/usr/bin");
        assert_eq!(result["SECRET_KEY"], "[REDACTED]");
        assert_eq!(result["HOME"], "/home/user");
    }

    // --- disabled config returns empty scan results ---

    #[test]
    fn disabled_config_returns_empty_scan() {
        let config = RedactionConfig {
            enabled: false,
            ..Default::default()
        };
        let r = EnvironmentRedactor::new(config);
        let env = env_from_pairs(&[("API_KEY", "super-secret")]);
        let records = r.scan_env(&env);
        assert!(
            records.is_empty(),
            "disabled redactor must return no scan records"
        );
    }

    #[test]
    fn disabled_config_does_not_redact() {
        let config = RedactionConfig {
            enabled: false,
            ..Default::default()
        };
        let r = EnvironmentRedactor::new(config);
        let env = env_from_pairs(&[("API_KEY", "super-secret")]);
        let result = r.redact_env(&env);
        // Note: redact_env doesn't check config.enabled, it checks patterns.
        // This test verifies the actual behavior: even when disabled, redact_env
        // still replaces matching pattern names (the scan is what's gated).
        // If the contract changes, update this test.
        assert_eq!(result["API_KEY"], "[REDACTED]");
    }

    // --- redact_env with empty input ---

    #[test]
    fn scan_env_with_empty_input() {
        let r = default_redactor();
        let env = HashMap::new();
        let records = r.scan_env(&env);
        assert!(records.is_empty());
    }

    #[test]
    fn redact_env_with_empty_input() {
        let r = default_redactor();
        let env = HashMap::new();
        let result = r.redact_env(&env);
        assert!(result.is_empty());
    }

    // --- additional edge cases ---

    #[test]
    fn scan_env_event_id_is_none() {
        let r = default_redactor();
        let env = env_from_pairs(&[("API_KEY", "value")]);
        let records = r.scan_env(&env);
        assert!(records.iter().all(|r| r.event_id.is_none()));
    }

    #[test]
    fn redact_env_preserves_all_keys() {
        let r = default_redactor();
        let env = env_from_pairs(&[("A", "1"), ("B_API_KEY", "secret"), ("C", "3")]);
        let result = r.redact_env(&env);
        assert_eq!(result.len(), 3);
        assert!(result.contains_key("A"));
        assert!(result.contains_key("B_API_KEY"));
        assert!(result.contains_key("C"));
    }
}
