//! 1.5: path-safe transactional patch restore (absolute/traversal rejected).

use blackbox::replay::sandbox::{
    apply_git_diff, parse_patch_paths, validate_patch_path, workspace_capability_report,
};
use blackbox::replay::ReplayPolicy;

#[test]
fn absolute_and_traversal_fixtures_fail_before_modification() {
    let ws = tempfile::tempdir().unwrap();
    std::fs::write(ws.path().join("keep.txt"), b"original").unwrap();

    for (label, patch) in [
        (
            "absolute",
            "diff --git a/x b/x\n--- a/x\n+++ /tmp/evil\n@@ -0,0 +1 @@\n+pwn\n",
        ),
        (
            "traversal",
            "diff --git a/x b/x\n--- a/x\n+++ b/../../evil\n@@ -0,0 +1 @@\n+pwn\n",
        ),
    ] {
        let err = apply_git_diff(ws.path(), patch).unwrap_err();
        assert!(
            err.to_string().contains("rejected")
                || err.to_string().contains("absolute")
                || err.to_string().contains("traversal"),
            "{label}: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(ws.path().join("keep.txt")).unwrap(),
            "original",
            "{label}: workspace modified"
        );
    }
}

#[test]
fn parse_and_validate_helpers() {
    let paths = parse_patch_paths(
        "diff --git a/src/a.rs b/src/a.rs\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -1 +1 @@\n-a\n+b\n",
    )
    .unwrap();
    assert!(paths.iter().any(|p| p == "src/a.rs"));
    assert!(validate_patch_path("src/a.rs").is_ok());
    assert!(validate_patch_path("/etc/passwd").is_err());
}

#[test]
fn workspace_capabilities_do_not_claim_kernel_isolation() {
    let caps = workspace_capability_report(ReplayPolicy::Sandbox);
    let text = caps
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("temporary-directory"));
    assert!(text.contains("not available") || text.contains("workspace-only"));
    assert!(!text.to_lowercase().contains("bubblewrap"));
}
