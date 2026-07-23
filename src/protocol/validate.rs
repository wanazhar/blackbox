//! Lightweight structural validation against published protocol rules.
//!
//! Full JSON Schema documents live under `/spec/schemas`. This module enforces
//! the subset of rules needed for CI and the conformance runner without pulling
//! a heavy schema engine into the library.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::schema::{find_schema, is_known_schema};

/// Validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationError {
    /// JSON pointer-ish path (e.g. `/schema`, `/id`).
    pub path: String,
    /// Human-readable message.
    pub message: String,
}

/// Aggregate validation report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Whether the object is acceptable under the rules checked here.
    pub ok: bool,
    /// Schema id when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// Errors (empty when ok).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ValidationError>,
    /// Non-fatal notices (unknown provisional fields, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<ValidationError>,
}

impl ValidationReport {
    fn fail(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            schema: None,
            errors: vec![ValidationError {
                path: path.into(),
                message: message.into(),
            }],
            warnings: vec![],
        }
    }
}

/// Validate that `schema` is a known or well-formed forward-compatible id.
pub fn validate_schema_id(schema: &str) -> Result<(), String> {
    if schema.is_empty() {
        return Err("schema id is empty".into());
    }
    if !schema.starts_with("blackbox.") {
        return Err(format!("schema id must start with 'blackbox.': {schema}"));
    }
    if !schema.contains('/') {
        return Err(format!("schema id must include /vN version: {schema}"));
    }
    // Known catalog always ok; unknown `blackbox.*./vN` allowed as forward-compatible
    // provisional (consumer must not reject solely for unknown minor schema).
    if is_known_schema(schema) {
        return Ok(());
    }
    // Accept well-formed unknown ids for forward compatibility.
    if schema
        .split('/')
        .next_back()
        .is_some_and(|v| v.starts_with('v') && v[1..].chars().all(|c| c.is_ascii_digit()))
    {
        return Ok(());
    }
    Err(format!("malformed schema version in id: {schema}"))
}

/// Structural validation of a protocol JSON object.
pub fn validate_json_object(value: &Value) -> ValidationReport {
    let obj = match value.as_object() {
        Some(o) => o,
        None => return ValidationReport::fail("", "root must be a JSON object"),
    };

    let mut report = ValidationReport {
        ok: true,
        schema: None,
        errors: vec![],
        warnings: vec![],
    };

    let schema = match obj.get("schema").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            report.ok = false;
            report.errors.push(ValidationError {
                path: "/schema".into(),
                message: "required field 'schema' missing".into(),
            });
            return report;
        }
    };
    report.schema = Some(schema.clone());

    if let Err(msg) = validate_schema_id(&schema) {
        report.ok = false;
        report.errors.push(ValidationError {
            path: "/schema".into(),
            message: msg,
        });
        return report;
    }

    // Reject non-finite numbers anywhere.
    if let Err(path) = reject_non_finite(value, "") {
        report.ok = false;
        report.errors.push(ValidationError {
            path,
            message: "non-finite number is forbidden".into(),
        });
    }

    // Per-schema required fields (minimal wire contracts).
    match schema.as_str() {
        "blackbox.run/v1" => {
            require_string(obj, "id", &mut report);
            require_string_enum(
                obj,
                "status",
                &[
                    "pending",
                    "running",
                    "succeeded",
                    "failed",
                    "cancelled",
                    "unknown",
                    // Also accept PascalCase as produced by current Rust serde.
                    "Pending",
                    "Running",
                    "Succeeded",
                    "Failed",
                    "Cancelled",
                    "Unknown",
                ],
                &mut report,
            );
            require_string(obj, "started_at", &mut report);
        }
        "blackbox.event/v1" => {
            require_string(obj, "id", &mut report);
            require_string(obj, "run_id", &mut report);
            require_u64_field(obj, "sequence", &mut report);
            require_string(obj, "kind", &mut report);
            require_string(obj, "started_at", &mut report);
        }
        "blackbox.evidence.event/v1" => {
            require_string(obj, "id", &mut report);
            require_string(obj, "source", &mut report);
            require_string(obj, "action", &mut report);
            require_string(obj, "ingested_at", &mut report);
        }
        "blackbox.security.decision/v1" => {
            require_string(obj, "id", &mut report);
            require_string(obj, "provider", &mut report);
            require_string(obj, "decision", &mut report);
            require_string(obj, "action_hash", &mut report);
            require_string(obj, "decided_at", &mut report);
        }
        "blackbox.commitment.run/v1" => {
            require_string(obj, "run_id", &mut report);
            require_string(obj, "root_hash", &mut report);
            require_u64_field(obj, "event_count", &mut report);
        }
        "blackbox.reconcile.outcome/v1" => {
            require_string(obj, "id", &mut report);
            require_string(obj, "outcome", &mut report);
        }
        "blackbox.boundary/v1"
        | "blackbox.boundary.finding/v1"
        | "blackbox.forensic.pack/v1"
        | "blackbox.incident/v1"
        | "blackbox.verification.receipt/v1"
        | "blackbox.containment.receipt/v1" => {
            require_string(obj, "id", &mut report);
        }
        _ => {
            if find_schema(&schema).is_none() {
                report.warnings.push(ValidationError {
                    path: "/schema".into(),
                    message: format!("unknown schema id (forward-compatible): {schema}"),
                });
            }
        }
    }

    report
}

fn require_string(
    obj: &serde_json::Map<String, Value>,
    field: &str,
    report: &mut ValidationReport,
) {
    match obj.get(field) {
        Some(Value::String(s)) if !s.is_empty() => {}
        Some(Value::String(_)) => {
            report.ok = false;
            report.errors.push(ValidationError {
                path: format!("/{field}"),
                message: format!("field '{field}' must be a non-empty string"),
            });
        }
        Some(_) => {
            report.ok = false;
            report.errors.push(ValidationError {
                path: format!("/{field}"),
                message: format!("field '{field}' must be a string"),
            });
        }
        None => {
            report.ok = false;
            report.errors.push(ValidationError {
                path: format!("/{field}"),
                message: format!("required field '{field}' missing"),
            });
        }
    }
}

fn require_string_enum(
    obj: &serde_json::Map<String, Value>,
    field: &str,
    allowed: &[&str],
    report: &mut ValidationReport,
) {
    match obj.get(field).and_then(|v| v.as_str()) {
        Some(s) if allowed.contains(&s) => {}
        Some(s) => {
            report.ok = false;
            report.errors.push(ValidationError {
                path: format!("/{field}"),
                message: format!("field '{field}' value '{s}' not in allowed set"),
            });
        }
        None => {
            report.ok = false;
            report.errors.push(ValidationError {
                path: format!("/{field}"),
                message: format!("required field '{field}' missing or not a string"),
            });
        }
    }
}

fn require_u64_field(
    obj: &serde_json::Map<String, Value>,
    field: &str,
    report: &mut ValidationReport,
) {
    match obj.get(field) {
        Some(Value::Number(n)) if n.as_u64().is_some() || n.as_i64().is_some_and(|i| i >= 0) => {}
        Some(_) => {
            report.ok = false;
            report.errors.push(ValidationError {
                path: format!("/{field}"),
                message: format!("field '{field}' must be a non-negative integer"),
            });
        }
        None => {
            report.ok = false;
            report.errors.push(ValidationError {
                path: format!("/{field}"),
                message: format!("required field '{field}' missing"),
            });
        }
    }
}

fn reject_non_finite(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(path.to_string());
                }
            }
            Ok(())
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                reject_non_finite(v, &format!("{path}/{i}"))?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (k, v) in map {
                reject_non_finite(v, &format!("{path}/{k}"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid_run_object() {
        let v = json!({
            "schema": "blackbox.run/v1",
            "id": "run-abc",
            "status": "Succeeded",
            "started_at": "2026-07-23T00:00:00Z"
        });
        let r = validate_json_object(&v);
        assert!(r.ok, "{r:?}");
    }

    #[test]
    fn missing_schema_fails() {
        let v = json!({"id": "x"});
        let r = validate_json_object(&v);
        assert!(!r.ok);
    }

    #[test]
    fn security_decision_requires_action_hash() {
        let v = json!({
            "schema": "blackbox.security.decision/v1",
            "id": "d1",
            "provider": "opa",
            "decision": "deny",
            "decided_at": "2026-07-23T00:00:00Z"
        });
        let r = validate_json_object(&v);
        assert!(!r.ok);
        assert!(r.errors.iter().any(|e| e.path == "/action_hash"));
    }
}
