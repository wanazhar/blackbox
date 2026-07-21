//! 1.6 A: scrub remaps nested workspace-manifest content hashes after redaction.

use std::sync::Arc;

use blackbox::core::checkpoint::Checkpoint;
use blackbox::core::event::{EventSource, EventStatus, TraceEvent};
use blackbox::core::run::Run;
use blackbox::crypto::content_key;
use blackbox::scrub::scrub_store;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::workspace_manifest::{
    ManifestEntry, ManifestEntryType, WorkspaceManifest, WORKSPACE_MANIFEST_VERSION,
};
use chrono::Utc;

#[tokio::test]
async fn scrub_rewrites_nested_manifest_content_hashes() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let run = Run::new(vec!["echo".into()], "/tmp".into());
    store.insert_run(&run).await.unwrap();

    // File blob with a secret (AWS-style key that the scanner redacts).
    let secret_body = b"token=AKIAIOSFODNN7EXAMPLE\n";
    let old_file_key = content_key(secret_body);
    store.store_blob(secret_body).await.unwrap();

    let clean_body = b"hello";
    let clean_key = content_key(clean_body);
    store.store_blob(clean_body).await.unwrap();

    let manifest = WorkspaceManifest {
        version: WORKSPACE_MANIFEST_VERSION,
        root: "/tmp/proj".into(),
        captured_at: Utc::now(),
        entries: vec![
            ManifestEntry {
                path: "secret.env".into(),
                entry_type: ManifestEntryType::File,
                content_hash: Some(old_file_key.clone()),
                size: Some(secret_body.len() as u64),
                mode: None,
                symlink_target: None,
                target_scope: None,
                followed: false,
                git_state: "unknown".into(),
                complete: true,
                skip_reason: None,
                transformation: None,
                byte_exact: true,
            },
            ManifestEntry {
                path: "ok.txt".into(),
                entry_type: ManifestEntryType::File,
                content_hash: Some(clean_key.clone()),
                size: Some(clean_body.len() as u64),
                mode: None,
                symlink_target: None,
                target_scope: None,
                followed: false,
                git_state: "unknown".into(),
                complete: true,
                skip_reason: None,
                transformation: None,
                byte_exact: true,
            },
        ],
        files_total: 2,
        bytes_total: (secret_body.len() + clean_body.len()) as u64,
        capture_complete: true,
        limitations: vec![],
    };
    let manifest_json = manifest.to_json().unwrap();
    let old_manifest_key = content_key(manifest_json.as_bytes());
    store.store_blob(manifest_json.as_bytes()).await.unwrap();

    // Attach the secret as an event output so top-level remap is covered.
    let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
    ev.status = EventStatus::Success;
    ev.output_blob = Some(old_file_key.clone());
    store.insert_event(&ev).await.unwrap();

    let mut cp = Checkpoint::new(&run.id, &ev.id, "/tmp");
    cp.filesystem_manifest_blob = Some(old_manifest_key.clone());
    store.insert_checkpoint(&cp).await.unwrap();

    let report = scrub_store(store.clone(), false, Some("all"), None)
        .await
        .unwrap();
    assert!(
        report.blobs_rewritten >= 1,
        "expected nested/file blobs rewritten: {report:?}"
    );

    // Event top-level ref remapped.
    let events = store.get_events(&run.id).await.unwrap();
    let new_event_key = events[0].output_blob.as_ref().unwrap();
    assert_ne!(new_event_key, &old_file_key);
    let new_bytes = store
        .load_blob(&blackbox::core::blob::BlobReference::try_new(new_event_key.clone(), 0).unwrap())
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&new_bytes).contains("AKIAIOSFODNN7"));

    // Checkpoint manifest blob remapped and nested content_hash updated.
    let cps = store.get_checkpoints(&run.id).await.unwrap();
    let new_manifest_key = cps[0]
        .filesystem_manifest_blob
        .as_ref()
        .expect("manifest key");
    // Manifest JSON itself may or may not change key depending on nested-only rewrite.
    let manifest_bytes = store
        .load_blob(
            &blackbox::core::blob::BlobReference::try_new(new_manifest_key.clone(), 0).unwrap(),
        )
        .await
        .unwrap();
    let updated: WorkspaceManifest =
        serde_json::from_slice(&manifest_bytes).expect("manifest still valid JSON");
    let secret_entry = updated
        .entries
        .iter()
        .find(|e| e.path == "secret.env")
        .unwrap();
    let nested_hash = secret_entry.content_hash.as_ref().unwrap();
    assert_ne!(
        nested_hash, &old_file_key,
        "nested content_hash must be remapped after scrub"
    );
    assert_eq!(nested_hash, new_event_key);
    assert!(!secret_entry.byte_exact);
    // Clean file hash unchanged.
    let ok = updated.entries.iter().find(|e| e.path == "ok.txt").unwrap();
    assert_eq!(ok.content_hash.as_deref(), Some(clean_key.as_str()));
}
