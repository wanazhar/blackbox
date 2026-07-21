//! CLI text/JSON output helpers (daily-driver 0.2).

use serde::Serialize;

/// How the CLI should print results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// `Text` variant.
    Text,
    /// `Json` variant.
    Json,
}

impl OutputMode {
    /// Build from flag.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_flag` — see module docs for full workflow.
    /// ```
    pub fn from_flag(json: bool) -> Self {
        if json {
            OutputMode::Json
        } else {
            OutputMode::Text
        }
    }
}

/// Closed set of CLI error codes for the JSON envelope (`blackbox.cli/v1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CliErrorCode {
    /// `NotFound` variant.
    NotFound,
    /// `Ambiguous` variant.
    Ambiguous,
    /// `InvalidArgs` variant.
    InvalidArgs,
    /// `StoreError` variant.
    StoreError,
    /// `SchemaTooNew` variant.
    SchemaTooNew,
    /// `Unsupported` variant.
    Unsupported,
    /// `Internal` variant.
    Internal,
}

/// Structured CLI error for JSON (and optional mapping from anyhow).
#[derive(Debug, Clone, Serialize)]
pub struct CliErrorBody {
    /// Code.
    pub code: CliErrorCode,
    /// Message.
    pub message: String,
}

/// Success / failure envelope for `--json`.
#[derive(Debug, Serialize)]
pub struct CliEnvelope<T: Serialize> {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Schema identifier string.
    pub schema: &'static str,
    /// Command argv.
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Data.
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Error.
    pub error: Option<CliErrorBody>,
}

/// `CLI_SCHEMA` constant.
pub const CLI_SCHEMA: &str = "blackbox.cli/v1";

/// Emit a successful JSON envelope to stdout.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `emit_ok` — see module docs for full workflow.
/// ```
pub fn emit_ok<T: Serialize>(command: &str, data: &T) -> anyhow::Result<()> {
    let env = CliEnvelope {
        ok: true,
        schema: CLI_SCHEMA,
        command: command.to_string(),
        data: Some(data),
        error: None,
    };
    println!("{}", serde_json::to_string_pretty(&env)?);
    Ok(())
}

/// Emit a failure JSON envelope to stdout.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `emit_err` — see module docs for full workflow.
/// ```
pub fn emit_err(
    command: &str,
    code: CliErrorCode,
    message: impl Into<String>,
) -> anyhow::Result<()> {
    let env = CliEnvelope::<serde_json::Value> {
        ok: false,
        schema: CLI_SCHEMA,
        command: command.to_string(),
        data: None,
        error: Some(CliErrorBody {
            code,
            message: message.into(),
        }),
    };
    println!("{}", serde_json::to_string_pretty(&env)?);
    Ok(())
}

/// Map common anyhow messages into CLI error codes (best-effort).
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `classify_anyhow` — see module docs for full workflow.
/// ```
pub fn classify_anyhow(err: &anyhow::Error) -> CliErrorCode {
    let msg = err.to_string().to_lowercase();
    if msg.contains("not found") || msg.contains("no runs recorded") {
        CliErrorCode::NotFound
    } else if msg.contains("ambiguous") {
        CliErrorCode::Ambiguous
    } else if msg.contains("schema") && msg.contains("newer") {
        CliErrorCode::SchemaTooNew
    } else if msg.contains("unknown status")
        || msg.contains("invalid")
        || msg.contains("pass --")
        || msg.contains("conflicting")
    {
        CliErrorCode::InvalidArgs
    } else if msg.contains("sqlite") || msg.contains("database") || msg.contains("i/o") {
        CliErrorCode::StoreError
    } else {
        CliErrorCode::Internal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn envelope_ok_serializes() {
        let env = CliEnvelope {
            ok: true,
            schema: CLI_SCHEMA,
            command: "runs".into(),
            data: Some(json!({"runs": []})),
            error: None,
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains(CLI_SCHEMA));
    }

    #[test]
    fn classify_not_found() {
        let e = anyhow::anyhow!("run not found: abc");
        assert_eq!(classify_anyhow(&e), CliErrorCode::NotFound);
    }
}
