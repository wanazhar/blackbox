//! Incident cursor pagination + aggregates (1.7 scale).

use std::sync::Arc;

use blackbox::incident::{
    attach_to_incident, compute_incident_aggregates, decode_incident_cursor, Incident,
    IncidentAttachmentKind,
};
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

#[tokio::test]
async fn list_incidents_page_exhausts_with_cursor() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    for i in 0..15 {
        let mut inc = Incident::new(Some(format!("inc-{i}")));
        // Distinct timestamps for stable order
        inc.created_at = chrono::Utc::now() - chrono::Duration::seconds(i as i64);
        inc.id = format!("inc-{i:03}");
        attach_to_incident(
            &mut inc,
            IncidentAttachmentKind::Run,
            format!("run-{i}"),
            None::<String>,
        );
        store.upsert_incident(&inc).await.unwrap();
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let page = store
            .list_incidents_page(cursor.as_ref(), 5)
            .await
            .unwrap();
        pages += 1;
        for i in &page.incidents {
            assert!(seen.insert(i.id.clone()), "duplicate {}", i.id);
        }
        if !page.has_more {
            break;
        }
        cursor = Some(decode_incident_cursor(page.next_cursor.as_deref().unwrap()).unwrap());
        assert!(pages < 10, "pagination did not terminate");
    }
    assert_eq!(seen.len(), 15);
    assert!(pages >= 3);
}

#[tokio::test]
async fn aggregates_from_incident() {
    let mut inc = Incident::new(Some("swarm".into()));
    attach_to_incident(&mut inc, IncidentAttachmentKind::Run, "r1", None::<String>);
    attach_to_incident(&mut inc, IncidentAttachmentKind::Run, "r2", None::<String>);
    let a = compute_incident_aggregates(&inc, 4, 1, 3, 10, 2, 1);
    assert_eq!(a.run_count, 2);
    assert_eq!(a.attachment_count, 2);
    assert_eq!(a.finding_count, 4);
    assert_eq!(a.critical_findings, 1);
    assert_eq!(a.reuse_count, 1);
}
