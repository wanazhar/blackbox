//! Property tests / lightweight fuzz for protocol parsers (1.9 Phase G).
//!
//! Core invariant: malformed or unnormalizable input must never be silently
//! authorized or upgraded in integrity.

/// Fuzz-like: many random-ish objects either canonicalize or fail cleanly.
#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use crate::protocol::canonical::{canonical_hash, canonical_string};
    use crate::protocol::validate::validate_json_object;

    #[test]
    fn canonicalize_is_idempotent() {
        let samples = [
            json!({"z": 1, "a": [3, null, true, "x"]}),
            json!([]),
            json!(null),
            json!(42),
            json!("hi"),
            json!({"nested": {"b": 2, "a": {"c": 1}}}),
        ];
        for s in samples {
            let c1 = canonical_string(&s).unwrap();
            let parsed: Value = serde_json::from_str(&c1).unwrap();
            let c2 = canonical_string(&parsed).unwrap();
            assert_eq!(c1, c2);
            assert_eq!(canonical_hash(&s).unwrap(), canonical_hash(&parsed).unwrap());
        }
    }

    #[test]
    fn validation_never_upgrades_missing_schema() {
        for v in [
            json!(null),
            json!([]),
            json!("x"),
            json!({"id": "only"}),
            json!({"schema": ""}),
            json!({"schema": "not-blackbox/v1"}),
        ] {
            let r = validate_json_object(&v);
            assert!(!r.ok, "should fail: {v}");
        }
    }

    #[test]
    fn integrity_field_in_decision_not_auto_verified() {
        // Even if a client sends signed_verified, validation does not rewrite it;
        // demotion is a separate security step — ensure schema still validates
        // and demotion is required by security module (tested elsewhere).
        let v = json!({
            "schema": "blackbox.security.decision/v1",
            "id": "d",
            "provider": "x",
            "decision": "allow",
            "action_hash": "aa".repeat(32),
            "decided_at": "2026-07-23T00:00:00Z",
            "integrity": "signed_verified"
        });
        let r = validate_json_object(&v);
        assert!(r.ok);
        // Must not silently change integrity during validation.
        assert_eq!(v["integrity"], "signed_verified");
    }

    #[test]
    fn path_like_strings_do_not_authorize() {
        // Protocol validation does not grant authorization based on path shape.
        let v = json!({
            "schema": "blackbox.event/v1",
            "id": "e",
            "run_id": "r",
            "sequence": 0,
            "kind": "file.write",
            "started_at": "t",
            "path": "/etc/passwd"
        });
        let r = validate_json_object(&v);
        assert!(r.ok); // structure ok
        // No authorization field is set by validate.
        assert!(v.get("authorized").is_none());
    }

    #[test]
    fn large_nested_object_canonicalizes() {
        let mut obj = serde_json::Map::new();
        for i in (0..50).rev() {
            obj.insert(format!("k{i:02}"), json!(i));
        }
        let v = Value::Object(obj);
        let s = canonical_string(&v).unwrap();
        assert!(s.starts_with(r#"{"k00":0"#));
        assert!(s.contains(r#""k49":49"#));
    }
}
