//! 1.6 F: adapter protocol validation.

use blackbox::adapter_protocol::{
    validate_adapter_event, validate_adapter_manifest, AdapterManifest, ADAPTER_PROTOCOL,
};

#[test]
fn valid_manifest_and_event() {
    let m = AdapterManifest {
        name: "custom".into(),
        protocol: ADAPTER_PROTOCOL.into(),
        command: vec!["blackbox-adapter-custom".into()],
        detect_basenames: vec!["custom-agent".into()],
        capabilities: vec!["tool_calls".into()],
        version: Some("0.1".into()),
    };
    assert!(validate_adapter_manifest(&m).ok);
    let line = r#"{"kind":"tool.call","source_sequence":1,"tool_name":"Bash"}"#;
    assert!(validate_adapter_event(line).ok);
}

#[test]
fn rejects_oversized_and_invalid() {
    let big = format!(
        r#"{{"kind":"x","source_sequence":1,"pad":"{}"}}"#,
        "x".repeat(2 * 1024 * 1024)
    );
    assert!(!validate_adapter_event(&big).ok);
    assert!(!validate_adapter_event("not-json").ok);
}
