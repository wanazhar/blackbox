//! 1.9 Phase A: protocol test vectors and schema catalog checks.
//!
//! Exit gate: two independently ordered encoders produce the same canonical
//! bytes/hash; published vectors under `/test-vectors` pass validation.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{json, Value};

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
    #[serde(default)]
    raw_input: Option<String>,
    #[serde(default)]
    expected_error: Option<String>,
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
        let v: VectorFile =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
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
    assert!(SURFACE_INVENTORY
        .iter()
        .any(|s| s.name == "blackbox.run/v1"));
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
        assert!(report.ok, "vector {} failed: {:?}", v.id, report.errors);
    }
}

#[test]
fn invalid_vectors_fail() {
    for (path, v) in load_vectors("invalid") {
        if v.expect == "fail_raw" {
            let error =
                blackbox::protocol::parse_json_strict(v.raw_input.as_deref().expect("raw_input"))
                    .unwrap_err()
                    .to_string();
            if let Some(expected) = v.expected_error.as_deref() {
                assert!(error.contains(expected), "{}: {error}", path.display());
            }
            continue;
        }
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
    let catalog: Value = serde_json::from_str(
        &fs::read_to_string(repo_root().join("spec/schemas/catalog.json")).unwrap(),
    )
    .unwrap();
    for entry in catalog["schemas"].as_array().unwrap() {
        let name = entry["file"].as_str().expect("catalog file");
        let p = repo_root().join("spec/schemas").join(name);
        assert!(p.is_file(), "missing schema file {}", p.display());
        let v: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        let validator = jsonschema::validator_for(&v)
            .unwrap_or_else(|error| panic!("schema {} does not compile: {error}", p.display()));
        assert_eq!(
            v["properties"]["schema"]["const"],
            entry["id"],
            "{} protocol id does not match catalog",
            p.display()
        );
        assert!(
            !validator.is_valid(&json!({"schema": "blackbox.invalid/v1"})),
            "{} accepts a different protocol id",
            p.display()
        );
    }
}

fn schema_for(protocol_id: &str) -> Value {
    let catalog: Value = serde_json::from_str(
        &fs::read_to_string(repo_root().join("spec/schemas/catalog.json")).unwrap(),
    )
    .unwrap();
    let file = catalog["schemas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == protocol_id)
        .and_then(|entry| entry["file"].as_str())
        .unwrap_or_else(|| panic!("schema not cataloged: {protocol_id}"));
    serde_json::from_str(&fs::read_to_string(repo_root().join("spec/schemas").join(file)).unwrap())
        .unwrap()
}

fn assert_published_schema_accepts(value: &Value) {
    let protocol_id = value["schema"].as_str().expect("schema string");
    let schema = schema_for(protocol_id);
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{protocol_id}: {errors:?}\n{value:#}");
}

#[test]
fn valid_vectors_match_published_schemas() {
    for (path, vector) in load_vectors("valid") {
        let input = vector.input.expect("input");
        assert_published_schema_accepts(&input);
        assert!(
            validate_json_object(&input).ok,
            "runtime validation differs for {}",
            path.display()
        );
    }
}

#[test]
fn invalid_vectors_are_rejected_by_published_schemas() {
    for (path, vector) in load_vectors("invalid") {
        let Some(input) = vector.input else {
            continue;
        };
        let Some(protocol_id) = input["schema"].as_str() else {
            continue;
        };
        if find_schema(protocol_id).is_none() {
            continue;
        }
        let schema = schema_for(protocol_id);
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(
            !validator.is_valid(&input),
            "published schema accepted invalid vector {}",
            path.display()
        );
    }
}

#[test]
fn rust_protocol_objects_match_published_schemas() {
    use blackbox::commitment::build_run_commitment;
    use blackbox::conformance::{run_conformance, ConformanceLevel};
    use blackbox::core::event::{EventSource, TraceEvent};
    use blackbox::core::run::Run;
    use blackbox::otlp::LossLedger;
    use blackbox::security::{ActionFingerprint, DecisionKind, SecurityDecision};

    let run = Run::new(vec!["true".into()], "/tmp".into());
    let mut run_value = serde_json::to_value(&run).unwrap();
    run_value["schema"] = json!("blackbox.run/v1");
    assert_published_schema_accepts(&run_value);

    let mut event = TraceEvent::new(&run.id, EventSource::System, "run.started");
    event.sequence = 1;
    let mut event_value = serde_json::to_value(&event).unwrap();
    event_value["schema"] = json!("blackbox.event/v1");
    assert_published_schema_accepts(&event_value);

    let fingerprint = ActionFingerprint::tool("read", None);
    let decision = SecurityDecision::builder("harness", DecisionKind::Allow, fingerprint.hash())
        .action(fingerprint)
        .build();
    assert_published_schema_accepts(&serde_json::to_value(decision).unwrap());

    let commitment = build_run_commitment(&run.id, &[event], &[], None, None, true);
    assert_published_schema_accepts(&serde_json::to_value(commitment).unwrap());

    let report = run_conformance(
        ConformanceLevel::Core,
        Some(&repo_root().join("test-vectors")),
    );
    assert_published_schema_accepts(&serde_json::to_value(report).unwrap());

    let loss = LossLedger::new("export");
    assert_published_schema_accepts(&serde_json::to_value(loss).unwrap());
}

#[test]
fn signature_vector_is_reproducible_and_reports_key_states() {
    use blackbox::commitment::{sign_run_root, verify_run_root_signature, SignatureStatus};
    use ed25519_dalek::SigningKey;

    let value: Value = serde_json::from_str(
        &fs::read_to_string(repo_root().join("test-vectors/signature/ed25519-run-root.json"))
            .unwrap(),
    )
    .unwrap();
    let seed: [u8; 32] = hex::decode(value["seed"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let key = SigningKey::from_bytes(&seed);
    let root = value["root_hash"].as_str().unwrap();
    let signed = sign_run_root(&key, root);
    assert_eq!(signed.public_key, value["public_key"]);
    assert_eq!(signed.signature, value["signature"]);
    assert_eq!(
        verify_run_root_signature(
            &signed,
            root,
            Some(std::slice::from_ref(&signed.public_key)),
            &[]
        ),
        SignatureStatus::Valid
    );
    assert_eq!(
        verify_run_root_signature(&signed, root, Some(&["ff".repeat(32)]), &[]),
        SignatureStatus::UnknownKey
    );
    assert_eq!(
        verify_run_root_signature(
            &signed,
            root,
            None,
            std::slice::from_ref(&signed.public_key)
        ),
        SignatureStatus::RevokedKey
    );
    assert_eq!(
        verify_run_root_signature(&signed, &"cd".repeat(32), None, &[]),
        SignatureStatus::Invalid
    );
}

#[tokio::test]
async fn portable_migration_vector_round_trips_to_v2() {
    use std::sync::Arc;

    use blackbox::export::portable::{export_portable, import_portable};
    use blackbox::storage::store::InMemoryStore;
    use blackbox::storage::TraceStore;

    let vector: Value = serde_json::from_str(
        &fs::read_to_string(repo_root().join("test-vectors/migration/portable-v1-to-v2.json"))
            .unwrap(),
    )
    .unwrap();
    let input = serde_json::to_string(&vector["input"]).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
    let imported = import_portable(store.as_ref(), &input, false)
        .await
        .unwrap();
    let run = store.get_run(&imported.run_id).await.unwrap().unwrap();
    let events = store.get_events(&imported.run_id).await.unwrap();
    let exported = export_portable(store.as_ref(), &run, &events, true)
        .await
        .unwrap();
    let output: Value = serde_json::from_str(&exported).unwrap();
    assert_eq!(output["schema"], "blackbox.portable/v2");
    assert_eq!(output["version"], 2);
    assert_eq!(output["run"]["id"], vector["expected"]["run_id"]);
    assert_eq!(output["events"].as_array().unwrap().len(), 0);
    assert_published_schema_accepts(&output);
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
