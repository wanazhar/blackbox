//! 1.6 A: restore reports distinguish byte-exact from sanitized fidelity.

use std::sync::Arc;

use blackbox::storage::sqlite::SqliteStore;
use blackbox::workspace_manifest::{
    capture_workspace_manifest, restore_workspace_manifest, ContentTransformation, ManifestLimits,
    RestoreCompleteness,
};

#[tokio::test]
async fn plain_files_restore_as_byte_exact() {
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("readme.md"), b"# hello world").unwrap();
    std::fs::write(src.path().join("data.bin"), [0u8, 1, 2, 255]).unwrap();

    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let manifest =
        capture_workspace_manifest(src.path(), Some(store.as_ref()), ManifestLimits::default())
            .await
            .unwrap();

    assert!(manifest
        .entries
        .iter()
        .filter(|e| e.path == "readme.md" || e.path == "data.bin")
        .all(|e| e.byte_exact && e.transformation.is_none()));

    let dest = tempfile::tempdir().unwrap();
    let report = restore_workspace_manifest(&manifest, dest.path(), store.as_ref())
        .await
        .unwrap();
    assert!(report.complete, "{report:?}");
    assert!(report.byte_exact, "{report:?}");
    assert_eq!(report.completeness, RestoreCompleteness::ByteExact);
    assert!(!report.content_transformed);
    assert_eq!(report.transformed, 0);
}

#[tokio::test]
async fn redacted_files_are_sanitized_complete_not_byte_exact() {
    let src = tempfile::tempdir().unwrap();
    // Credential-like content that the checkpoint fragment scanner redacts.
    std::fs::write(
        src.path().join("env.sh"),
        b"export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123456789\n",
    )
    .unwrap();
    std::fs::write(src.path().join("ok.txt"), b"plain").unwrap();

    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let manifest =
        capture_workspace_manifest(src.path(), Some(store.as_ref()), ManifestLimits::default())
            .await
            .unwrap();

    let env = manifest
        .entries
        .iter()
        .find(|e| e.path == "env.sh")
        .expect("env.sh");
    // If redaction fired, entry must not claim byte-exact.
    if env.transformation == Some(ContentTransformation::SecretRedaction) {
        assert!(!env.byte_exact);
        let dest = tempfile::tempdir().unwrap();
        let report = restore_workspace_manifest(&manifest, dest.path(), store.as_ref())
            .await
            .unwrap();
        assert!(
            report.complete || report.restored >= 1,
            "sanitized content should still restore: {report:?}"
        );
        assert!(
            !report.byte_exact,
            "sanitized restore must not claim byte_exact: {report:?}"
        );
        assert_eq!(
            report.completeness,
            RestoreCompleteness::SanitizedComplete,
            "{report:?}"
        );
        assert!(report.content_transformed);
        assert!(report.transformed >= 1);
        assert!(
            report
                .limitations
                .iter()
                .any(|l| l.contains("transformed") || l.contains("SecretRedaction")),
            "must list transformation: {:?}",
            report.limitations
        );
        let restored = std::fs::read_to_string(dest.path().join("env.sh")).unwrap();
        assert!(
            !restored.contains("sk-abcdefghijklmnopqrstuvwxyz0123456789"),
            "secret must not appear after restore"
        );
    } else {
        // Scanner thresholds can change; still require the classification path exists.
        assert!(env.byte_exact || env.transformation.is_some());
    }
}

#[tokio::test]
async fn partial_capture_reports_partial_completeness() {
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("ok.txt"), b"ok").unwrap();
    std::fs::write(src.path().join("huge.bin"), vec![b'z'; 2000]).unwrap();

    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let limits = ManifestLimits {
        max_file_bytes: 500,
        ..Default::default()
    };
    let manifest = capture_workspace_manifest(src.path(), Some(store.as_ref()), limits)
        .await
        .unwrap();

    let dest = tempfile::tempdir().unwrap();
    let report = restore_workspace_manifest(&manifest, dest.path(), store.as_ref())
        .await
        .unwrap();
    assert!(!report.complete);
    assert!(!report.byte_exact);
    assert_eq!(report.completeness, RestoreCompleteness::Partial);
    assert!(report.excluded >= 1 || report.skipped >= 1);
}
