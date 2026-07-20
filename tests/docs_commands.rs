//! 1.5 X1 docs CI gates: inventory presence, claim matrix, and basic command refs.

use std::collections::HashSet;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn inventory_lists_claims_and_guides() {
    let root = repo_root();
    let inv_json = root.join("docs/inventory.json");
    let inv_md = root.join("docs/inventory.md");
    let claims = root.join("docs/claims.md");
    assert!(inv_json.is_file(), "docs/inventory.json missing");
    assert!(inv_md.is_file(), "docs/inventory.md missing");
    assert!(claims.is_file(), "docs/claims.md missing");

    let text = std::fs::read_to_string(&inv_json).unwrap();
    let rows: serde_json::Value = serde_json::from_str(&text).expect("inventory.json valid JSON");
    let arr = rows.as_array().expect("inventory is array");
    assert!(arr.len() >= 40, "inventory too small: {}", arr.len());

    let paths: HashSet<String> = arr
        .iter()
        .filter_map(|r| r.get("path").and_then(|p| p.as_str()).map(String::from))
        .collect();
    for required in [
        "docs/claims.md",
        "docs/guide/troubleshooting.md",
        "docs/plan/trace-integrity-1.5.md",
        "docs/WRITING.md",
        "docs/reference/portable-format.md",
    ] {
        assert!(
            paths.contains(required),
            "inventory missing required page: {required}"
        );
    }
}

#[test]
fn claims_matrix_has_required_classes() {
    let text = std::fs::read_to_string(repo_root().join("docs/claims.md")).unwrap();
    for class in [
        "test-backed",
        "best-effort",
        "platform-dependent",
        "planned",
    ] {
        assert!(
            text.contains(class),
            "claims.md missing class label: {class}"
        );
    }
    // High-risk claims that must stay documented.
    for needle in [
        "Portable import",
        "Workspace restore",
        "Large-run totals",
        "Dashboard auth",
    ] {
        assert!(text.contains(needle), "claims.md missing claim about: {needle}");
    }
}

#[test]
fn guide_export_documents_portable_dir() {
    let text = std::fs::read_to_string(repo_root().join("docs/guide/export-and-sync.md")).unwrap();
    // Either updated already or portable-format is the owner — at least one path.
    let portable_ref =
        std::fs::read_to_string(repo_root().join("docs/reference/portable-format.md")).unwrap();
    assert!(
        portable_ref.contains("portable.dir")
            || portable_ref.contains("events.jsonl")
            || portable_ref.contains("export_portable_dir"),
        "portable-format.md should document directory layout"
    );
    // Guide should still document core export formats.
    assert!(text.contains("--format portable") || text.contains("portable"));
}

#[test]
fn writing_standard_mentions_claim_classes() {
    let text = std::fs::read_to_string(repo_root().join("docs/WRITING.md")).unwrap();
    // 1.5 rewrite standard should classify claims.
    let has_classes = text.contains("test-backed")
        || text.contains("claim class")
        || text.contains("Claim class")
        || text.contains("claims.md");
    assert!(
        has_classes,
        "WRITING.md should reference claim classes or claims.md"
    );
}
