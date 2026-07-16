use crate::redaction::scanner::SecretScanner;
use crate::redaction::{RedactionConfig, RedactionReason, RedactionRecord};
use std::collections::HashMap;

/// Redacts sensitive environment variable values before storage.
///
/// Environment variables are captured at run start and may contain
/// API keys, tokens, and other credentials. Redaction is two-pass:
/// 1. Name denylist (substring match on the variable name)
/// 2. Value scan with [`SecretScanner`] (catches secrets in oddly-named vars)
pub struct EnvironmentRedactor {
    config: RedactionConfig,
    scanner: SecretScanner,
}

impl EnvironmentRedactor {
    pub fn new(config: RedactionConfig) -> Self {
        let scanner = SecretScanner::new(config.clone());
        Self { config, scanner }
    }

    fn name_is_sensitive(&self, name: &str) -> bool {
        let upper = name.to_uppercase();
        self.config
            .env_var_patterns
            .iter()
            .any(|p| upper.contains(p))
    }

    /// Scan environment variables and return redaction records
    /// for name matches and value-pattern matches.
    pub fn scan_env(&self, env: &HashMap<String, String>) -> Vec<RedactionRecord> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut records = Vec::new();
        for (name, value) in env {
            if self.name_is_sensitive(name) {
                records.push(RedactionRecord {
                    reason: RedactionReason::EnvironmentSecret,
                    pattern: name.clone(),
                    location: format!("env:{}", name),
                    event_id: None,
                });
                continue;
            }
            // Value scan: oddly named vars carrying tokens/URLs with secrets
            let hits = self.scanner.scan(value, &format!("env:{}", name), None);
            for h in hits {
                records.push(h);
            }
        }
        records
    }

    /// Produce a redacted copy of the environment.
    ///
    /// Sensitive names become `[REDACTED]`. Other values are pattern-scanned
    /// so secrets in `DATABASE_URL`-style or oddly named vars still die.
    pub fn redact_env(&self, env: &HashMap<String, String>) -> HashMap<String, String> {
        if !self.config.enabled {
            return env.clone();
        }
        let mut result = HashMap::with_capacity(env.len());
        for (name, value) in env {
            if self.name_is_sensitive(name) {
                result.insert(name.clone(), "[REDACTED]".to_string());
            } else {
                let redacted = self.scanner.redact(value);
                result.insert(name.clone(), redacted);
            }
        }
        result
    }

    /// Redact in place (single map — lower peak RAM than clone + redact).
    pub fn redact_env_in_place(&self, env: &mut HashMap<String, String>) {
        if !self.config.enabled {
            return;
        }
        for (name, value) in env.iter_mut() {
            if self.name_is_sensitive(name) {
                *value = "[REDACTED]".to_string();
            } else {
                let redacted = self.scanner.redact(value);
                *value = redacted;
            }
        }
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

    #[test]
    fn redact_env_replaces_sensitive_values() {
        let r = default_redactor();
        let env = env_from_pairs(&[("API_KEY", "super-secret-key"), ("TOKEN", "tok_abc123xyz")]);
        let result = r.redact_env(&env);
        assert_eq!(result["API_KEY"], "[REDACTED]");
        assert_eq!(result["TOKEN"], "[REDACTED]");
    }

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
        // When disabled, pass through unchanged.
        assert_eq!(result["API_KEY"], "super-secret");
    }

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

    #[test]
    fn value_scan_redacts_openai_key_in_odd_name() {
        let r = default_redactor();
        // Name does not match denylist; value is a classic OpenAI-style key.
        let env = env_from_pairs(&[("SVC_CFG", "sk-abcdefghijklmnopqrstuvwxyz012345")]);
        let result = r.redact_env(&env);
        assert!(
            !result["SVC_CFG"].contains("sk-abcdef"),
            "value scan must redact API key material: got {}",
            result["SVC_CFG"]
        );
    }

    #[test]
    fn name_database_url_is_redacted_wholesale() {
        let r = default_redactor();
        let env = env_from_pairs(&[(
            "DATABASE_URL",
            "postgres://user:hunter2@db.internal:5432/app",
        )]);
        let result = r.redact_env(&env);
        assert_eq!(result["DATABASE_URL"], "[REDACTED]");
    }

    #[test]
    fn redact_env_in_place_single_map() {
        let r = default_redactor();
        let mut env = env_from_pairs(&[("PATH", "/bin"), ("API_KEY", "secret")]);
        r.redact_env_in_place(&mut env);
        assert_eq!(env["PATH"], "/bin");
        assert_eq!(env["API_KEY"], "[REDACTED]");
    }
}
