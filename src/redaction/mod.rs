pub mod environment;
pub mod export;
pub mod scanner;
pub mod stream;

pub use stream::{StreamRedactor, DEFAULT_STREAM_WINDOW};

/// A record that redaction occurred at a specific location.
#[derive(Debug, Clone)]
pub struct RedactionRecord {
    /// Why the content was redacted
    pub reason: RedactionReason,

    /// The pattern that matched (e.g., "OPENAI_API_KEY")
    pub pattern: String,

    /// Where the redaction was applied
    pub location: String,

    /// Event ID where redaction occurred
    pub event_id: Option<String>,
}

/// Reason for redaction, matching PRD section 17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionReason {
    /// Environment variable containing a secret
    EnvironmentSecret,
    /// HTTP authorization header
    AuthorizationHeader,
    /// API key or bearer token
    ApiKey,
    /// Cookie value
    Cookie,
    /// SSH private key material
    SshKey,
    /// .env file value
    DotEnvValue,
    /// Cloud credential
    CloudCredential,
    /// Database connection string containing credentials
    ConnectionString,
    /// Generic pattern-based match
    PatternMatch,
}

/// Redaction configuration.
#[derive(Debug, Clone)]
pub struct RedactionConfig {
    /// Whether redaction is enabled
    pub enabled: bool,
    /// Additional custom patterns (regex)
    pub custom_patterns: Vec<String>,
    /// Environment variable name patterns to redact
    pub env_var_patterns: Vec<String>,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            custom_patterns: Vec::new(),
            env_var_patterns: vec![
                "API_KEY".into(),
                "TOKEN".into(),
                "SECRET".into(),
                "PASSWORD".into(),
                "CREDENTIAL".into(),
                "PRIVATE_KEY".into(),
                "ACCESS_KEY".into(),
                "SESSION_KEY".into(),
            ],
        }
    }
}
