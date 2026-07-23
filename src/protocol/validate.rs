//! Lightweight structural validation against published protocol rules.
//!
//! Full JSON Schema documents live under `/spec/schemas`. This module enforces
//! the fail-closed wire invariants needed by embedders at runtime; CI also
//! compiles and executes every published schema.

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
    // Unknown *fields* are forward compatible. Unknown schema versions are not:
    // interpreting a v2 object with v1 semantics could upgrade integrity.
    if is_known_schema(schema) {
        return Ok(());
    }
    if schema
        .split('/')
        .next_back()
        .is_some_and(|v| v.starts_with('v') && v[1..].chars().all(|c| c.is_ascii_digit()))
    {
        return Err(format!("unsupported schema id: {schema}"));
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
            require_timestamp(obj, "started_at", &mut report);
        }
        "blackbox.event/v1" => {
            require_string(obj, "id", &mut report);
            require_string(obj, "run_id", &mut report);
            require_u64_field(obj, "sequence", &mut report);
            require_string(obj, "kind", &mut report);
            require_timestamp(obj, "started_at", &mut report);
        }
        "blackbox.evidence.event/v1" => {
            require_string(obj, "id", &mut report);
            require_string(obj, "source", &mut report);
            require_string(obj, "sensor", &mut report);
            require_string(obj, "source_event_id", &mut report);
            require_string(obj, "action", &mut report);
            require_timestamp(obj, "ingested_at", &mut report);
        }
        "blackbox.security.decision/v1" => {
            require_string(obj, "id", &mut report);
            require_string(obj, "provider", &mut report);
            require_string(obj, "decision", &mut report);
            require_string(obj, "action_hash", &mut report);
            require_hash(obj, "action_hash", &mut report);
            require_timestamp(obj, "decided_at", &mut report);
        }
        "blackbox.commitment.run/v1" => {
            require_string(obj, "run_id", &mut report);
            require_string(obj, "root_hash", &mut report);
            require_hash(obj, "root_hash", &mut report);
            require_u64_field(obj, "event_count", &mut report);
        }
        "blackbox.reconcile.outcome/v1" => {
            require_string(obj, "id", &mut report);
            require_string(obj, "outcome", &mut report);
        }
        "blackbox.boundary/v1" => {
            require_string(obj, "run_id", &mut report);
            require_hash(obj, "policy_hash", &mut report);
            require_timestamp(obj, "resolved_at", &mut report);
            require_object(obj, "contract", &mut report);
        }
        "blackbox.boundary.finding/v1" => {
            require_string(obj, "id", &mut report);
            require_string(obj, "run_id", &mut report);
            require_string(obj, "detector", &mut report);
            require_timestamp(obj, "created_at", &mut report);
        }
        "blackbox.boundary.finding.decision/v1" => {
            for field in [
                "observation",
                "policy_disposition",
                "evidence_integrity",
                "identity_confidence",
                "correlation_confidence",
                "observed_effect",
                "violation_state",
                "severity",
            ] {
                require_string(obj, field, &mut report);
            }
        }
        "blackbox.forensic.pack/v1" => {
            require_string(obj, "run_id", &mut report);
            require_timestamp(obj, "created_at", &mut report);
            require_hash(obj, "pack_hash", &mut report);
        }
        "blackbox.incident/v1" => {
            require_string(obj, "id", &mut report);
            require_timestamp(obj, "created_at", &mut report);
        }
        "blackbox.verification.receipt/v1" | "blackbox.containment.receipt/v1" => {
            require_string(obj, "id", &mut report);
            require_string(obj, "run_id", &mut report);
            require_timestamp(obj, "created_at", &mut report);
        }
        _ => {
            debug_assert!(find_schema(&schema).is_some());
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

fn require_object(
    obj: &serde_json::Map<String, Value>,
    field: &str,
    report: &mut ValidationReport,
) {
    if !obj.get(field).is_some_and(Value::is_object) {
        report.ok = false;
        report.errors.push(ValidationError {
            path: format!("/{field}"),
            message: format!("required field '{field}' missing or not an object"),
        });
    }
}

fn require_hash(obj: &serde_json::Map<String, Value>, field: &str, report: &mut ValidationReport) {
    match obj.get(field).and_then(Value::as_str) {
        Some(value)
            if value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) => {}
        _ => {
            report.ok = false;
            report.errors.push(ValidationError {
                path: format!("/{field}"),
                message: format!("field '{field}' must be 64 lowercase hex characters"),
            });
        }
    }
}

fn require_timestamp(
    obj: &serde_json::Map<String, Value>,
    field: &str,
    report: &mut ValidationReport,
) {
    let valid = obj.get(field).and_then(Value::as_str).is_some_and(|value| {
        value.ends_with('Z')
            && chrono::DateTime::parse_from_rfc3339(value)
                .is_ok_and(|parsed| parsed.offset().local_minus_utc() == 0)
    });
    if !valid {
        report.ok = false;
        report.errors.push(ValidationError {
            path: format!("/{field}"),
            message: format!("field '{field}' must be an unambiguous RFC 3339 UTC timestamp"),
        });
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

    #[test]
    fn unsupported_versions_and_ambiguous_timestamps_fail() {
        let unsupported = validate_json_object(&json!({
            "schema": "blackbox.run/v99",
            "id": "r",
            "status": "running",
            "started_at": "2026-07-23T00:00:00Z"
        }));
        assert!(!unsupported.ok);
        assert_eq!(unsupported.errors[0].path, "/schema");

        let ambiguous = validate_json_object(&json!({
            "schema": "blackbox.run/v1",
            "id": "r",
            "status": "running",
            "started_at": "2026-07-23 00:00:00"
        }));
        assert!(!ambiguous.ok);
        assert!(ambiguous
            .errors
            .iter()
            .any(|error| error.path == "/started_at"));
    }
}
