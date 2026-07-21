//! 1.6 F: multi-project index is metadata-only.

use std::fs;

use blackbox::projects::{
    default_index_path, discover_project_stores, ProjectIndexQuery, ProjectRegistry,
};

#[test]
fn discover_and_query_metadata_only() {
    let root = tempfile::tempdir().unwrap();
    let proj = root.path().join("proj-a");
    let bb = proj.join(".blackbox");
    fs::create_dir_all(&bb).unwrap();
    fs::write(bb.join("blackbox.db"), b"not-a-real-db").unwrap();

    let found = discover_project_stores(&[root.path().to_path_buf()]);
    assert!(
        found.iter().any(|e| e.project_root == proj),
        "expected project discovery: {:?}",
        found
    );
    // No transcripts/blobs in index entries.
    for e in &found {
        assert!(e.store_path.ends_with("blackbox.db"));
    }

    let mut reg = ProjectRegistry::empty();
    for e in found {
        reg.upsert(e);
    }
    let idx = root.path().join("index.json");
    reg.save(&idx).unwrap();
    let loaded = ProjectRegistry::load(&idx).unwrap();
    let hits = loaded.query(&ProjectIndexQuery {
        name_substr: Some("proj-a".into()),
        limit: Some(10),
    });
    assert_eq!(hits.len(), 1);

    // default path helper is absolute-ish
    let _ = default_index_path();
}
