//! 1.5 W1: workspace manifest capture + restore completeness.

use std::sync::Arc;

use blackbox::storage::sqlite::SqliteStore;
use blackbox::workspace_manifest::{
    capture_workspace_manifest, restore_workspace_manifest, validate_rel_path, ManifestLimits,
};

#[tokio::test]
async fn untracked_and_binary_restore() {
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("readme.md"), b"# hello").unwrap();
    std::fs::write(src.path().join("data.bin"), &[0u8, 1, 2, 255, 128]).unwrap();
    std::fs::create_dir_all(src.path().join("nested")).unwrap();
    std::fs::write(src.path().join("nested/untracked.txt"), b"side effect").unwrap();

    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let manifest = capture_workspace_manifest(
        src.path(),
        Some(store.as_ref()),
        ManifestLimits::default(),
    )
    .await
    .unwrap();

    assert!(manifest.files_total >= 3);
    assert!(manifest.entries.iter().any(|e| e.path == "data.bin"
        && e.content_hash.is_some()
        && e.complete));

    let dest = tempfile::tempdir().unwrap();
    let report = restore_workspace_manifest(&manifest, dest.path(), store.as_ref())
        .await
        .unwrap();
    assert!(report.complete, "{report:?}");
    assert_eq!(
        std::fs::read(dest.path().join("data.bin")).unwrap(),
        vec![0u8, 1, 2, 255, 128]
    );
    assert_eq!(
        std::fs::read_to_string(dest.path().join("nested/untracked.txt")).unwrap(),
        "side effect"
    );
}

#[tokio::test]
async fn partial_restore_reported() {
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("ok.txt"), b"ok").unwrap();
    // File over limit → incomplete capture
    let big = vec![b'z'; 2000];
    std::fs::write(src.path().join("huge.bin"), &big).unwrap();

    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let limits = ManifestLimits {
        max_file_bytes: 500,
        ..Default::default()
    };
    let manifest = capture_workspace_manifest(src.path(), Some(store.as_ref()), limits)
        .await
        .unwrap();
    assert!(!manifest.capture_complete || manifest.entries.iter().any(|e| !e.complete));

    let dest = tempfile::tempdir().unwrap();
    let report = restore_workspace_manifest(&manifest, dest.path(), store.as_ref())
        .await
        .unwrap();
    assert!(!report.complete, "incomplete capture must not claim complete restore");
    assert!(report.skipped >= 1 || !report.limitations.is_empty());
    assert!(dest.path().join("ok.txt").exists());
    assert!(!dest.path().join("huge.bin").exists());
}

#[tokio::test]
async fn symlink_explicit_behavior() {
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("target.txt"), b"data").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("target.txt", src.path().join("link.txt")).unwrap();
    }
    #[cfg(not(unix))]
    {
        return;
    }

    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let manifest = capture_workspace_manifest(
        src.path(),
        Some(store.as_ref()),
        ManifestLimits::default(),
    )
    .await
    .unwrap();
    let link = manifest
        .entries
        .iter()
        .find(|e| e.path == "link.txt")
        .expect("symlink entry");
    assert_eq!(
        link.symlink_target.as_deref(),
        Some("target.txt")
    );

    let dest = tempfile::tempdir().unwrap();
    let report = restore_workspace_manifest(&manifest, dest.path(), store.as_ref())
        .await
        .unwrap();
    assert!(report.complete || report.restored >= 1, "{report:?}");
    let meta = std::fs::symlink_metadata(dest.path().join("link.txt")).unwrap();
    assert!(meta.file_type().is_symlink());
}

#[test]
fn paths_cannot_escape() {
    assert!(validate_rel_path("ok").is_ok());
    assert!(validate_rel_path("../escape").is_err());
    assert!(validate_rel_path("/tmp/x").is_err());
}
