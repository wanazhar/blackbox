//! Property gates for protocol parsing, canonicalization, normalization, and import.

use std::collections::BTreeMap;
use std::sync::Arc;

use blackbox::boundary::{normalize_path, normalize_url};
use blackbox::export::portable::import_portable;
use blackbox::protocol::{canonical_string, parse_json_strict};
use blackbox::storage::store::InMemoryStore;
use blackbox::storage::TraceStore;
use proptest::prelude::*;
use serde_json::Value;

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|value| Value::Number(value.into())),
        any::<String>().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::btree_map(any::<String>(), inner, 0..8).prop_map(object_from_btree),
        ]
    })
}

fn object_from_btree(values: BTreeMap<String, Value>) -> Value {
    Value::Object(values.into_iter().collect())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn canonical_form_is_idempotent(value in json_value()) {
        let first = canonical_string(&value).unwrap();
        let parsed = parse_json_strict(&first).unwrap();
        let second = canonical_string(&parsed).unwrap();
        prop_assert_eq!(first, second);
    }

    #[test]
    fn strict_parser_and_normalizers_never_panic(raw in any::<String>()) {
        let _ = parse_json_strict(&raw);
        let _ = normalize_url(&raw);
        let _ = normalize_path(&raw);
    }

    #[test]
    fn duplicate_keys_always_fail_closed(key in any::<String>(), left in any::<i64>(), right in any::<i64>()) {
        let key = serde_json::to_string(&key).unwrap();
        let raw = format!("{{{key}:{left},{key}:{right}}}");
        prop_assert!(parse_json_strict(&raw).is_err());
    }

    #[test]
    fn malformed_portable_input_never_partially_imports(raw in any::<String>()) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let store: Arc<dyn TraceStore> = Arc::new(InMemoryStore::new());
        let _ = runtime.block_on(import_portable(store.as_ref(), &raw, false));
        let runs = runtime.block_on(store.list_runs()).unwrap();
        prop_assert!(runs.is_empty(), "malformed input created a run");
    }
}
