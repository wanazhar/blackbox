//! 1.9 Phase A: protocol test vectors and schema catalog checks.
//!
//! Exit gate: two independently ordered encoders produce the same canonical
//! bytes/hash; published vectors under `/test-vectors` pass validation.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

use blackbox::protocol::{
    canonical_hash, canonical_string, find_schema, validate_json_object, SCHEMA_CATALOG,
    SURFACE_INVENTORY,
};

#[derive(Debug, Deserialize)]
struct VectorFile {
    id: String,
    #[allow(dead_code)]
    description: Option<String>,
    expect: String,
    #[serde(default)]
    input: Option<Value>,
    #[serde(default)]
    expected_canonical: Option<String>,
    #[serde(default)]
    expected_hash: Option<String>,
    #[serde(default)]
    expected_error_path: Option<String>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_vectors(dir: &str) -> Vec<(PathBuf, VectorFile)> {
    let root = repo_root().join("test-vectors").join(dir);
    if !root.is_dir() {
        return vec![];
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let v: VectorFile = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        out.push((path, v));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn catalog_matches_spec_file() {
    let path = repo_root().join("spec/schemas/catalog.json");
    let text = fs::read_to_string(&path).expect("catalog.json");
    let catalog: Value = serde_json::from_str(&text).unwrap();
    let schemas = catalog["schemas"].as_array().expect("schemas array");
    assert_eq!(
        schemas.len(),
        SCHEMA_CATALOG.len(),
        "spec catalog length must match SCHEMA_CATALOG"
    );
    for (i, entry) in schemas.iter().enumerate() {
        let id = entry["id"].as_str().unwrap();
        assert_eq!(id, SCHEMA_CATALOG[i].id, "catalog order mismatch at {i}");
        assert!(find_schema(id).is_some());
    }
}

#[test]
fn surface_inventory_nonempty() {
    assert!(SURFACE_INVENTORY.len() >= 10);
    assert!(SURFACE_INVENTORY.iter().any(|s| s.name == "blackbox.run/v1"));
    assert!(SURFACE_INVENTORY
        .iter()
        .any(|s| s.name == "blackbox.security.decision/v1"));
}

#[test]
fn valid_vectors_pass() {
    for (path, v) in load_vectors("valid") {
        assert_eq!(v.expect, "pass", "{}", path.display());
        let input = v.input.expect("input");
        let report = validate_json_object(&input);
        assert!(
            report.ok,
            "vector {} failed: {:?}",
            v.id,
            report.errors
        );
    }
}

#[test]
fn invalid_vectors_fail() {
    for (path, v) in load_vectors("invalid") {
        assert_eq!(v.expect, "fail", "{}", path.display());
        let input = v.input.expect("input");
        let report = validate_json_object(&input);
        assert!(!report.ok, "vector {} unexpectedly passed", v.id);
        if let Some(ep) = &v.expected_error_path {
            assert!(
                report.errors.iter().any(|e| e.path == *ep),
                "vector {} expected error at {ep}, got {:?}",
                v.id,
                report.errors
            );
        }
    }
}

#[test]
fn canonical_vectors_match() {
    for (path, v) in load_vectors("canonical") {
        assert_eq!(v.expect, "canonical", "{}", path.display());
        let input = v.input.expect("input");
        let got = canonical_string(&input).unwrap();
        let hash = canonical_hash(&input).unwrap();
        if let Some(exp) = &v.expected_canonical {
            assert_eq!(got, *exp, "canonical mismatch for {}", v.id);
        }
        if let Some(exp_h) = &v.expected_hash {
            assert_eq!(hash, *exp_h, "hash mismatch for {}", v.id);
        }
        assert_eq!(hash.len(), 64);
    }
}

#[test]
fn dual_encoder_same_hash() {
    // Encoder A: insertion order schema, id, status
    let mut a = serde_json::Map::new();
    a.insert("schema".into(), Value::String("blackbox.run/v1".into()));
    a.insert("id".into(), Value::String("run-dual".into()));
    a.insert("status".into(), Value::String("failed".into()));
    a.insert(
        "started_at".into(),
        Value::String("2026-07-23T01:00:00Z".into()),
    );

    // Encoder B: reverse insertion order
    let mut b = serde_json::Map::new();
    b.insert(
        "started_at".into(),
        Value::String("2026-07-23T01:00:00Z".into()),
    );
    b.insert("status".into(), Value::String("failed".into()));
    b.insert("id".into(), Value::String("run-dual".into()));
    b.insert("schema".into(), Value::String("blackbox.run/v1".into()));

    let va = Value::Object(a);
    let vb = Value::Object(b);
    assert_eq!(
        canonical_string(&va).unwrap(),
        canonical_string(&vb).unwrap()
    );
    assert_eq!(canonical_hash(&va).unwrap(), canonical_hash(&vb).unwrap());
}

#[test]
fn rust_run_serializes_with_validatable_envelope() {
    use blackbox::core::run::{Run, RunStatus};
    let run = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
    let mut value = serde_json::to_value(&run).unwrap();
    // Protocol envelope adds schema field for wire form.
    if let Value::Object(ref mut map) = value {
        map.insert("schema".into(), Value::String("blackbox.run/v1".into()));
        // Normalize status to string already present via serde.
        let _ = map.get("status");
    }
    // Ensure required protocol fields exist on Rust type.
    assert!(value.get("id").and_then(|v| v.as_str()).is_some());
    assert!(value.get("started_at").is_some());
    assert_eq!(run.status, RunStatus::Pending);

    let report = validate_json_object(&value);
    assert!(
        report.ok,
        "Rust Run envelope should validate: {:?}",
        report.errors
    );
}

#[test]
fn rust_event_envelope_validates() {
    use blackbox::core::event::{EventSource, TraceEvent};
    let mut ev = TraceEvent::new("run-1", EventSource::Tool, "tool.call");
    ev.sequence = 1;
    let mut value = serde_json::to_value(&ev).unwrap();
    if let Value::Object(ref mut map) = value {
        map.insert("schema".into(), Value::String("blackbox.event/v1".into()));
    }
    let report = validate_json_object(&value);
    assert!(report.ok, "{:?}", report.errors);
}

#[test]
fn schema_files_exist() {
    for name in [
        "run.v1.json",
        "event.v1.json",
        "security_decision.v1.json",
        "commitment_run.v1.json",
        "reconcile_outcome.v1.json",
        "native_ingest.v1.json",
        "catalog.json",
    ] {
        let p = repo_root().join("spec/schemas").join(name);
        assert!(p.is_file(), "missing schema file {}", p.display());
        let v: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        assert!(v.is_object());
    }
}

#[test]
fn provisional_field_included_in_hash() {
    let base = serde_json::json!({
        "schema": "blackbox.event/v1",
        "id": "e1",
        "run_id": "r1",
        "sequence": 0,
        "kind": "tool.call",
        "started_at": "2026-07-23T00:00:00Z"
    });
    let mut with_extra = base.clone();
    with_extra
        .as_object_mut()
        .unwrap()
        .insert("x_extra".into(), Value::String("keep-me".into()));
    assert_ne!(
        canonical_hash(&base).unwrap(),
        canonical_hash(&with_extra).unwrap()
    );
}
