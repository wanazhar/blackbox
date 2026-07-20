//! 1.5 C1: filesystem capture must not silently expand via symlinks / escapes.

use std::fs;
use std::path::Path;

use blackbox::capture::filesystem::{FilesystemCapture, PathScope, SymlinkPolicy};

#[test]
fn project_symlink_to_home_does_not_expand_scope() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), b"secret").unwrap();

    // Symlink from project into outside (home-like).
    let link = root.path().join("escape-link");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
    }
    #[cfg(not(unix))]
    {
        let _ = (root, outside, link);
        return;
    }

    // Default policy: Ignore symlink paths entirely.
    let scope = FilesystemCapture::classify_path(root.path(), &link, SymlinkPolicy::Ignore);
    assert_eq!(scope, PathScope::Ignored);

    // LinkOnly: labeled symlink, not followed as in-root content.
    let scope = FilesystemCapture::classify_path(root.path(), &link, SymlinkPolicy::LinkOnly);
    assert_eq!(scope, PathScope::Symlink);

    // FollowWithinRoot: resolved target is outside → OutsideRoot.
    let scope = FilesystemCapture::classify_path(
        root.path(),
        &link.join("secret.txt"),
        SymlinkPolicy::FollowWithinRoot,
    );
    // Path may not resolve if intermediate is link; either OutsideRoot or Ignored is fine,
    // but never InRoot for the outside secret.
    assert_ne!(
        scope,
        PathScope::InRoot,
        "must not treat escaped secret as in-root"
    );
}

#[test]
fn shared_ignore_matches_workspace_manifest() {
    assert!(FilesystemCapture::should_ignore(Path::new(
        "/p/node_modules/x"
    )));
    assert!(FilesystemCapture::should_ignore(Path::new("/p/target/y")));
    assert!(FilesystemCapture::should_ignore(Path::new(
        "/p/.blackbox/db"
    )));
    assert!(!FilesystemCapture::should_ignore(Path::new(
        "/p/src/main.rs"
    )));
}

#[test]
fn absolute_outside_path_is_out_of_scope() {
    let root = tempfile::tempdir().unwrap();
    let outside = std::env::temp_dir().join(format!("bb-escape-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("f"), b"x").unwrap();

    let scope = FilesystemCapture::classify_path(
        root.path(),
        &outside.join("f"),
        SymlinkPolicy::FollowWithinRoot,
    );
    assert_eq!(scope, PathScope::OutsideRoot);
    let _ = fs::remove_dir_all(&outside);
}
