//! A2 — Permanent redaction regression gate (1.1 adoption bar).
//!
//! Structural identifiers must never be scarred by secret scanners or export
//! redaction. Known secrets in free-form text must still die.
//!
//! This suite is always-on (`cargo test`); do not feature-gate it.

use blackbox::redaction::export::ExportRedactor;
use blackbox::redaction::scanner::SecretScanner;
use blackbox::redaction::RedactionConfig;
use serde_json::json;

fn scanner() -> SecretScanner {
    SecretScanner::new(RedactionConfig::default())
}

fn export_redactor() -> ExportRedactor {
    ExportRedactor::new(RedactionConfig::default())
}

/// Pure structural strings that must survive capture-time `SecretScanner::redact`.
fn structural_survivors() -> Vec<&'static str> {
    vec![
        // git SHA-1
        "ea950d8180f520d808274579577db86bc6365a7a",
        // content-addressed blob key (sha256 hex)
        "22c8e61f11fd0f02da754f5b2fa912f842c7ed27a056f5b38f882f820baf37d5",
        "d1a7b60df83a72fc820ce76f1883d30dc36f3980ce7570692f7fe30e98ce5b7e",
        // UUID run/event ids
        "939b2397-08b7-43c8-8850-41fedb4f001a",
        "4bc8c9f7-4600-4c7c-bf30-a39aae08448a",
        // short ids / enum-ish
        "Succeeded",
        "terminal.output",
        "tool.call",
        // ISO-ish timestamp fragment without secrets
        "2026-07-12T14:15:01.338087081Z",
    ]
}

/// Free-form secrets that must be redacted.
fn free_form_secrets() -> Vec<&'static str> {
    vec![
        "AKIAIOSFODNN7EXAMPLE",
        "sk-abcdefghijklmnopqrstuvwxyz012345",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12",
        "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz012345",
        "password=supersecretvalue",
    ]
}

#[test]
fn a2_scanner_preserves_structural_strings() {
    let s = scanner();
    for sample in structural_survivors() {
        let out = s.redact(sample);
        assert_eq!(
            out, sample,
            "capture scanner must not alter structural string: {sample}"
        );
        assert!(
            s.scan(sample, "gate", None).is_empty(),
            "capture scanner must not flag structural string as secret: {sample}"
        );
    }
}

#[test]
fn a2_scanner_redacts_known_secrets() {
    let s = scanner();
    for sample in free_form_secrets() {
        let out = s.redact(sample);
        assert!(
            out.contains("[REDACTED]") || out != sample,
            "secret must not survive capture redaction unchanged: {sample} → {out}"
        );
        // Common secret prefixes must not remain
        assert!(
            !out.contains("AKIAIOSFODNN7")
                && !out.contains("sk-abcdef")
                && !out.contains("ghp_ABCDEF"),
            "secret material leaked after redaction: {out}"
        );
    }
}

#[test]
fn a2_export_preserves_structural_fields() {
    let r = export_redactor();
    let sha = "ea950d8180f520d808274579577db86bc6365a7a";
    let blob = "22c8e61f11fd0f02da754f5b2fa912f842c7ed27a056f5b38f882f820baf37d5";
    let run_id = "939b2397-08b7-43c8-8850-41fedb4f001a";
    let mut val = json!({
        "id": run_id,
        "run_id": run_id,
        "event_id": run_id,
        "parent_run_id": run_id,
        "sequence": "13",
        "output_blob": blob,
        "input_blob": blob,
        "error_blob": blob,
        "environment_blob": blob,
        "commit": sha,
        "git_commit": sha,
        "started_at": "2026-07-12T14:15:01.338087081Z",
        "ended_at": "2026-07-12T14:16:01.338087081Z",
        "status": "Succeeded",
        "kind": "terminal.output",
        "source": "Terminal",
        "side_effect": "Unknown",
        "adapter": "claude",
        "name": "fix-login",
        "metadata": {
            "preview": "safe preview without secrets",
            "bytes": 12
        }
    });
    r.redact_json(&mut val);

    assert_eq!(val["id"], run_id);
    assert_eq!(val["run_id"], run_id);
    assert_eq!(val["output_blob"], blob);
    assert_eq!(val["input_blob"], blob);
    assert_eq!(val["error_blob"], blob);
    assert_eq!(val["environment_blob"], blob);
    assert_eq!(val["commit"], sha);
    assert_eq!(val["git_commit"], sha);
    assert_eq!(val["status"], "Succeeded");
    assert_eq!(val["kind"], "terminal.output");
    assert_eq!(val["source"], "Terminal");
    assert_eq!(val["adapter"], "claude");
    assert_eq!(val["name"], "fix-login");
    assert_eq!(val["sequence"], "13");
}

#[test]
fn a2_export_redacts_free_form_and_metadata_secrets() {
    let r = export_redactor();
    let blob = "d1a7b60df83a72fc820ce76f1883d30dc36f3980ce7570692f7fe30e98ce5b7e";
    let mut val = json!({
        "id": "4bc8c9f7-4600-4c7c-bf30-a39aae08448a",
        "output_blob": blob,
        "kind": "terminal.output",
        "metadata": {
            "preview": "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12 leaked\n",
            "status": "sk-abcdefghijklmnopqrstuvwxyz012345"
        },
        "preview": "AKIAIOSFODNN7EXAMPLE"
    });
    r.redact_json(&mut val);

    assert_eq!(val["output_blob"], blob);
    assert_eq!(val["kind"], "terminal.output");
    assert!(val["metadata"]["preview"]
        .as_str()
        .unwrap()
        .contains("[REDACTED]"));
    assert!(!val["metadata"]["preview"]
        .as_str()
        .unwrap()
        .contains("ghp_"));
    assert!(val["metadata"]["status"]
        .as_str()
        .unwrap()
        .contains("[REDACTED]"));
    assert!(val["preview"].as_str().unwrap().contains("[REDACTED]"));
}

#[test]
fn a2_export_blob_map_keys_survive_redaction_shape() {
    // Portable archives use blob digests as object keys; redacting keys would
    // break reassembly. ExportRedactor scans values; keys are object field names.
    let r = export_redactor();
    let key = "22c8e61f11fd0f02da754f5b2fa912f842c7ed27a056f5b38f882f820baf37d5";
    let mut val = json!({
        "blobs": {
            key: "plain text blob body with no secrets"
        },
        "runs": [{
            "id": "939b2397-08b7-43c8-8850-41fedb4f001a",
            "git_commit": "ea950d8180f520d808274579577db86bc6365a7a"
        }]
    });
    r.redact_json(&mut val);
    let blobs = val["blobs"].as_object().expect("blobs object");
    assert!(
        blobs.contains_key(key),
        "blob map key must survive export redaction; keys={:?}",
        blobs.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        val["runs"][0]["git_commit"],
        "ea950d8180f520d808274579577db86bc6365a7a"
    );
}

#[test]
fn a2_mixed_text_redacts_secret_keeps_sha_nearby() {
    let s = scanner();
    let sha = "ea950d8180f520d808274579577db86bc6365a7a";
    let text = format!("commit {sha} key=sk-abcdefghijklmnopqrstuvwxyz012345");
    let out = s.redact(&text);
    assert!(
        out.contains(sha),
        "SHA adjacent to secret must remain: {out}"
    );
    assert!(
        out.contains("[REDACTED]") || !out.contains("sk-abcdef"),
        "secret must be redacted: {out}"
    );
}
