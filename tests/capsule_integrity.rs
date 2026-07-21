//! 1.6 E: capsules declare completeness; sanitized cannot be byte-exact.

use std::sync::Arc;

use blackbox::capsule::{create_capsule, inspect_capsule, CapsuleCreateOpts, CapsuleCompleteness};
use blackbox::core::event::{EventSource, TraceEvent};
use blackbox::core::run::{Run, RunStatus};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

#[tokio::test]
async fn capsule_is_sanitized_not_byte_exact() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let mut run = Run::new(vec!["echo".into(), "hi".into()], "/tmp".into());
    run.status = RunStatus::Succeeded;
    store.insert_run(&run).await.unwrap();
    let mut ev = TraceEvent::new(&run.id, EventSource::Terminal, "terminal.output");
    ev.sequence = 1;
    store.insert_event(&ev).await.unwrap();

    let json = create_capsule(
        store.as_ref(),
        &run,
        &[],
        None,
        CapsuleCreateOpts {
            include_receipts: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let report = inspect_capsule(&json).unwrap();
    assert!(!matches!(
        report.completeness,
        CapsuleCompleteness::ByteExact
    ));
    assert!(!report.manifest.model_replay_deterministic);
    assert!(matches!(
        report.completeness,
        CapsuleCompleteness::SanitizedComplete
            | CapsuleCompleteness::Partial
            | CapsuleCompleteness::MetadataOnly
    ));
}
