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
            if self.config.env_var_patterns.iter().any(|p| upper.contains(p)) {
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
            if self.config.env_var_patterns.iter().any(|p| upper.contains(p)) {
                result.insert(name.clone(), "[REDACTED]".to_string());
            } else {
                result.insert(name.clone(), value.clone());
            }
        }
        result
    }
}
