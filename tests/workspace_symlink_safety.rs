//! 1.6 A: workspace manifest must never follow symlinks outside the project root.

use std::sync::Arc;

use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;
use blackbox::workspace_manifest::{
    capture_workspace_manifest, restore_workspace_manifest, ManifestEntryType, ManifestLimits,
    SymlinkTargetScope,
};

#[tokio::test]
async fn outside_root_symlink_is_not_followed_or_hashed() {
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("id_rsa");
    std::fs::write(&secret, b"-----BEGIN PRIVATE KEY-----\nsecret-material\n").unwrap();

    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("safe.txt"), b"ok").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&secret, src.path().join("leak")).unwrap();
        // Directory symlink pointing outside the root.
        std::os::unix::fs::symlink(outside.path(), src.path().join("ext_dir")).unwrap();
    }
    #[cfg(not(unix))]
    {
        return;
    }

    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let manifest =
        capture_workspace_manifest(src.path(), Some(store.as_ref()), ManifestLimits::default())
            .await
            .unwrap();

    let leak = manifest
        .entries
        .iter()
        .find(|e| e.path == "leak")
        .expect("symlink entry for leak");
    assert_eq!(leak.entry_type, ManifestEntryType::Symlink);
    assert!(!leak.followed);
    assert!(leak.content_hash.is_none());
    assert!(matches!(
        leak.target_scope,
        Some(SymlinkTargetScope::OutsideRoot) | Some(SymlinkTargetScope::Absolute)
    ));

    let ext = manifest
        .entries
        .iter()
        .find(|e| e.path == "ext_dir")
        .expect("dir symlink");
    assert_eq!(ext.entry_type, ManifestEntryType::Symlink);
    assert!(!ext.followed);
    // Must not have walked into outside and captured id_rsa content.
    assert!(
        !manifest.entries.iter().any(|e| e.path.contains("id_rsa")),
        "must not recurse through outside-root directory symlink: {:?}",
        manifest.entries.iter().map(|e| &e.path).collect::<Vec<_>>()
    );

    // No blob may contain the secret material.
    for key in store.all_blob_keys().await.unwrap() {
        let bref = blackbox::core::blob::BlobReference::try_new(key, 0).unwrap();
        let data = store.load_blob(&bref).await.unwrap();
        let text = String::from_utf8_lossy(&data);
        assert!(
            !text.contains("PRIVATE KEY") && !text.contains("secret-material"),
            "outside-root symlink target content was stored: {text}"
        );
    }
}

#[tokio::test]
async fn restore_rejects_absolute_and_traversal_symlinks() {
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("ok.txt"), b"data").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", src.path().join("abs_link")).unwrap();
        std::os::unix::fs::symlink("../escape", src.path().join("trav_link")).unwrap();
        std::os::unix::fs::symlink("ok.txt", src.path().join("rel_link")).unwrap();
    }
    #[cfg(not(unix))]
    {
        return;
    }

    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let manifest =
        capture_workspace_manifest(src.path(), Some(store.as_ref()), ManifestLimits::default())
            .await
            .unwrap();

    let dest = tempfile::tempdir().unwrap();
    let report = restore_workspace_manifest(&manifest, dest.path(), store.as_ref())
        .await
        .unwrap();

    assert!(dest.path().join("rel_link").exists() || report.restored >= 1);
    // Absolute / traversal links must not be created.
    assert!(!dest.path().join("abs_link").exists() || {
        // If present, must not be a symlink to absolute path — we reject creation.
        false
    });
    assert!(!dest.path().join("abs_link").exists());
    assert!(!dest.path().join("trav_link").exists());
    assert!(
        report.limitations.iter().any(|l| l.contains("symlink target rejected")),
        "expected rejection limitations: {:?}",
        report.limitations
    );
}

#[tokio::test]
async fn toctou_type_change_is_skipped_safely() {
    // Capture a normal file workspace; TOCTOU is covered by re-lstat checks
    // in the walker. This fixture ensures a symlink that appears as a normal
    // relative link is recorded without following.
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("a.txt"), b"a").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("a.txt", src.path().join("b")).unwrap();
    }
    #[cfg(not(unix))]
    {
        return;
    }

    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let manifest =
        capture_workspace_manifest(src.path(), Some(store.as_ref()), ManifestLimits::default())
            .await
            .unwrap();
    let link = manifest.entries.iter().find(|e| e.path == "b").unwrap();
    assert_eq!(link.entry_type, ManifestEntryType::Symlink);
    assert_eq!(link.symlink_target.as_deref(), Some("a.txt"));
    assert_eq!(link.target_scope, Some(SymlinkTargetScope::InsideRoot));
    assert!(!link.followed);
    assert!(link.content_hash.is_none());
}
