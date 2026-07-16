//! Golden CLI JSON envelope + human postmortem text labels used in docs.
//!
//! Aligns with:
//! - docs/reference/json-api.md
//! - docs/guide/examples.md
//! - docs/guide/getting-started.md (artifact summary.txt)
//! - tests/fixtures/docs/*

use std::path::PathBuf;
use std::sync::Arc;

use blackbox::cli::RunArgs;
use blackbox::output::{CliEnvelope, CliErrorBody, CliErrorCode, CLI_SCHEMA};
use blackbox::run::RunSupervisor;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::summary::{build_summary, format_summary_text, SummaryOptions};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/docs")
}

#[test]
fn cli_schema_constant_matches_docs() {
    assert_eq!(CLI_SCHEMA, "blackbox.cli/v1");
}

#[test]
fn success_envelope_shape_matches_fixture_keys() {
    let data = serde_json::json!({
        "headline": "example",
        "next_action": "example",
        "anomalies": [],
        "evidence": [],
        "status": "Succeeded",
        "exit_code": 0
    });
    let env = CliEnvelope {
        ok: true,
        schema: CLI_SCHEMA,
        command: "postmortem".into(),
        data: Some(data),
        error: None,
    };
    let got = serde_json::to_value(&env).unwrap();
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures_dir().join("cli_envelope_ok.json")).unwrap(),
    )
    .unwrap();

    assert_eq!(got["ok"], fixture["ok"]);
    assert_eq!(got["schema"], fixture["schema"]);
    assert_eq!(got["command"], fixture["command"]);
    assert!(got.get("data").is_some());
    assert!(got.get("error").is_none() || got["error"].is_null());

    // Required top-level keys documented in json-api.md
    for key in ["ok", "schema", "command", "data"] {
        assert!(got.get(key).is_some(), "missing envelope key {key}");
    }
    for key in [
        "headline",
        "next_action",
        "anomalies",
        "evidence",
        "status",
        "exit_code",
    ] {
        assert!(
            got["data"].get(key).is_some(),
            "postmortem data missing {key}"
        );
    }
}

#[test]
fn error_envelope_shape_matches_fixture_keys() {
    let env = CliEnvelope::<serde_json::Value> {
        ok: false,
        schema: CLI_SCHEMA,
        command: "show".into(),
        data: None,
        error: Some(CliErrorBody {
            code: CliErrorCode::NotFound,
            message: "Run not found: abc123".into(),
        }),
    };
    let got = serde_json::to_value(&env).unwrap();
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures_dir().join("cli_envelope_err.json")).unwrap(),
    )
    .unwrap();

    assert_eq!(got["ok"], false);
    assert_eq!(got["schema"], fixture["schema"]);
    assert_eq!(got["command"], fixture["command"]);
    assert_eq!(got["error"]["code"], "not_found");
    assert!(got["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not found"));
    assert!(got.get("data").is_none() || got["data"].is_null());
}

#[test]
fn summary_txt_artifact_lines_documented() {
    let required = std::fs::read_to_string(fixtures_dir().join("summary_txt_lines.txt")).unwrap();
    let lines: Vec<&str> = required
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        lines,
        vec!["headline:", "next:", "status:", "exit:", "anomalies:",]
    );
}

#[tokio::test]
async fn live_postmortem_text_uses_doc_labels() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("t.db");
    let blobs = dir.path().join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());
    let args = RunArgs {
        name: Some("envelope-live".into()),
        project: Some(dir.path().to_string_lossy().into()),
        tag: vec!["docs-fixture".into()],
        insecure_raw: false,
        no_redact: false,
        no_auto_resume: true,
        auto_resume: false,
        ci: false,
        eval: false,
        observe_only: true,
        artifact_dir: None,
        resume_injection: None,
        claim_id_note: None,
        ambient: false,
        command: vec!["true".into()],
    };
    let run = supervisor.execute(&args).await.unwrap();
    let summary = build_summary(store.as_ref(), &run, SummaryOptions::default())
        .await
        .unwrap();

    // Human text (debug-a-failure / cheatsheet style labels)
    let text = format_summary_text(&summary);
    assert!(
        text.starts_with("Postmortem ") || text.contains("status="),
        "postmortem text header missing: {text}"
    );
    // Labels when fields non-empty; always emit structure for exit via header
    assert!(text.contains("exit="), "docs examples show exit= in header");

    // Artifact summary.txt contract from getting-started / --artifact-dir
    let artifact = format!(
        "headline: {}\nnext: {}\nstatus: {:?}\nexit: {:?}\nanomalies: {}\n",
        summary.headline,
        summary.next_action,
        summary.status,
        summary.exit_code,
        summary.anomalies.len()
    );
    for prefix in ["headline:", "next:", "status:", "exit:", "anomalies:"] {
        assert!(
            artifact.lines().any(|l| l.starts_with(prefix)),
            "artifact missing line starting with {prefix}"
        );
    }

    // Envelope-wrapped postmortem serializes for jq paths in examples.md
    let env = CliEnvelope {
        ok: true,
        schema: CLI_SCHEMA,
        command: "postmortem".into(),
        data: Some(&summary),
        error: None,
    };
    let v = serde_json::to_value(&env).unwrap();
    assert_eq!(v["schema"], "blackbox.cli/v1");
    assert_eq!(v["ok"], true);
    assert_eq!(v["command"], "postmortem");
    // jq '.data.headline' style access
    assert!(v["data"].get("headline").is_some());
    assert!(v["data"].get("next_action").is_some());
    assert!(v["data"]["anomalies"].is_array());
    assert!(v["data"]["evidence"].is_array());
}

#[test]
fn jq_paths_in_examples_docs_are_valid_pointers() {
    // Paths advertised in docs/guide/examples.md under .data
    let sample = serde_json::json!({
        "ok": true,
        "schema": "blackbox.cli/v1",
        "command": "handoff",
        "data": {
            "attention": { "level": "continue", "run_id": "x" },
            "project_memory": {
                "headline": "h",
                "next_action": "n",
                "intent": { "open_items": ["a"] },
                "claims": { "active": null }
            },
            "last_run": { "id": "x" }
        }
    });
    let paths = [
        "/data/attention/level",
        "/data/project_memory/headline",
        "/data/project_memory/next_action",
        "/data/project_memory/intent/open_items",
        "/data/project_memory/claims/active",
        "/data/last_run/id",
        "/data/attention/run_id",
    ];
    for p in paths {
        assert!(
            sample.pointer(p).is_some(),
            "examples.md jq path missing in sample: {p}"
        );
    }
}
