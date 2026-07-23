//! 1.9 architecture and single-package publication contract.

use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn protocol_api_has_no_cli_or_storage_dependencies() {
    let protocol = root().join("src/protocol");
    for entry in fs::read_dir(protocol).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        for forbidden in ["rusqlite", "clap::", "crate::cli", "crate::storage"] {
            assert!(
                !source.contains(forbidden),
                "{} leaks forbidden protocol dependency {forbidden}",
                path.display()
            );
        }
    }
}

#[test]
fn only_top_level_package_is_publishable() {
    let mut manifests = Vec::new();
    collect_manifests(&root(), &mut manifests);
    assert!(
        manifests
            .iter()
            .any(|path| path == &root().join("Cargo.toml")),
        "top-level Cargo.toml missing"
    );
    for manifest in manifests {
        let text = fs::read_to_string(&manifest).unwrap();
        if manifest == root().join("Cargo.toml") {
            assert!(text.contains("name = \"blackbox-recorder\""));
        } else {
            assert!(
                text.contains("publish = false"),
                "private package must set publish = false: {}",
                manifest.display()
            );
        }
    }
}

fn collect_manifests(directory: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if path.is_dir() {
            if matches!(name, "target" | ".git" | ".blackbox" | "release-artifacts") {
                continue;
            }
            collect_manifests(&path, out);
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
}
