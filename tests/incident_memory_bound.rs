//! Linux peak-memory qualification for bounded incident graph assembly.

#![cfg(target_os = "linux")]

use blackbox::boundary::{EntityKind, EvidenceEdge, EvidenceRelation};
use blackbox::core::event::Confidence;
use blackbox::evidence::{EvidenceAction, ExternalEvidenceEvent};
use blackbox::incident::{
    attach_to_incident, build_incident_graph_with_limits, GraphInputs, Incident,
    IncidentAttachmentKind, IncidentGraphLimits,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

const RECORD_COUNT: usize = 10_000;
const MAX_ASSEMBLY_PEAK_GROWTH_BYTES: u64 = 32 * 1024 * 1024;

struct TrackingAllocator;

static CURRENT_BYTES: AtomicU64 = AtomicU64::new(0);
static PEAK_BYTES: AtomicU64 = AtomicU64::new(0);

fn record_allocation(size: usize) {
    let current = CURRENT_BYTES.fetch_add(size as u64, Ordering::Relaxed) + size as u64;
    let mut peak = PEAK_BYTES.load(Ordering::Relaxed);
    while current > peak {
        match PEAK_BYTES.compare_exchange_weak(peak, current, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(observed) => peak = observed,
        }
    }
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegates the exact layout to the system allocator.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegates the exact layout to the system allocator.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        CURRENT_BYTES.fetch_sub(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: pointer and layout came from this allocator's system allocation.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: delegates the original allocation and requested size to System.
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() {
            if new_size >= layout.size() {
                record_allocation(new_size - layout.size());
            } else {
                CURRENT_BYTES.fetch_sub((layout.size() - new_size) as u64, Ordering::Relaxed);
            }
        }
        new_pointer
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

#[test]
fn ten_thousand_record_graph_assembly_has_measured_peak_bound() {
    let mut incident = Incident::new(Some("memory qualification".into()));
    attach_to_incident(
        &mut incident,
        IncidentAttachmentKind::Run,
        "run-memory",
        None::<String>,
    );

    // Inputs are constructed before the baseline. This test measures incremental
    // graph-assembly working memory; importer count/byte limits bound the input set.
    let mut external = Vec::with_capacity(RECORD_COUNT);
    let mut edges = Vec::with_capacity(RECORD_COUNT);
    for index in 0..RECORD_COUNT {
        let mut event = ExternalEvidenceEvent::new(
            "memory",
            "fixture",
            format!("source-{index:05}"),
            EvidenceAction::NetworkConnect,
        );
        event.id = format!("evidence-{index:05}");
        event.linked_run_id = Some("run-memory".into());
        // Unique destinations exercise the worst-case technique maps.
        event.destination = Some(format!("unique-{index:05}.example"));
        external.push(event);

        let mut edge = EvidenceEdge::new(
            EntityKind::Run,
            "run-memory",
            EntityKind::ExternalEvidence,
            format!("evidence-{index:05}"),
            EvidenceRelation::CredentialUse,
            Confidence::StronglyCorrelated,
        );
        edge.id = format!("edge-{index:05}");
        edge.run_id = Some("run-memory".into());
        edges.push(edge);
    }

    let baseline = CURRENT_BYTES.load(Ordering::SeqCst);
    PEAK_BYTES.store(baseline, Ordering::SeqCst);
    let graph = build_incident_graph_with_limits(
        &incident,
        &GraphInputs {
            external,
            edges,
            ..Default::default()
        },
        IncidentGraphLimits {
            nodes: 64,
            edges: 64,
            flows: 64,
            techniques: 64,
        },
    );
    let growth = PEAK_BYTES.load(Ordering::SeqCst).saturating_sub(baseline);

    assert_eq!(graph.evidence_count, RECORD_COUNT);
    assert_eq!(graph.edge_count, Some(RECORD_COUNT));
    assert_eq!(graph.technique_count, Some(RECORD_COUNT + 1));
    assert_eq!(graph.nodes.len(), 64);
    assert_eq!(graph.edges.len(), 64);
    assert_eq!(graph.flows.len(), 64);
    assert_eq!(graph.techniques.len(), 64);
    assert!(
        growth <= MAX_ASSEMBLY_PEAK_GROWTH_BYTES,
        "incident graph assembly peak grew by {growth} bytes; budget is {MAX_ASSEMBLY_PEAK_GROWTH_BYTES}"
    );
    eprintln!(
        "incident graph assembly peak growth: {growth} bytes for {RECORD_COUNT} evidence + edges"
    );
}
