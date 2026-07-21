//! WS6 — Local overhead benchmark harness (soft, non-CI-blocking).
//!
//! Run locally (not part of default CI wall-time gates):
//!
//! ```bash
//! cargo test --test overhead_bench -- --nocapture --ignored
//! ```
//!
//! Measures Blackbox-supervised vs direct execution for a few scenarios and
//! prints p50-style timings. Hard asserts use generous budgets only.

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use blackbox::cli::RunArgs;
use blackbox::run::RunSupervisor;
use blackbox::storage::sqlite::SqliteStore;
use blackbox::storage::TraceStore;

const SAMPLES: usize = 5;

fn percentile(mut vals: Vec<u128>, p: f64) -> u128 {
    if vals.is_empty() {
        return 0;
    }
    vals.sort_unstable();
    let idx = ((p / 100.0) * (vals.len() as f64 - 1.0)).round() as usize;
    vals[idx.min(vals.len() - 1)]
}

fn direct_ms(cmd: &[&str]) -> u128 {
    let t0 = Instant::now();
    let status = Command::new(cmd[0])
        .args(&cmd[1..])
        .status()
        .expect("direct spawn");
    assert!(status.success());
    t0.elapsed().as_millis()
}

async fn supervised_ms(command: Vec<String>, label: &str) -> (u128, u64, usize) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("bench.db");
    let blobs = dir.path().join("blobs");
    let store = SqliteStore::open_with_blobs(&db, &blobs).unwrap();
    let store: Arc<dyn TraceStore> = Arc::new(store);
    let supervisor = RunSupervisor::new(store.clone());

    let args = RunArgs {
        name: Some(label.into()),
        project: Some(dir.path().to_string_lossy().into()),
        tag: vec!["bench".into()],
        insecure_raw: false,
        no_redact: false,
        no_auto_resume: true,
        auto_resume: false,
        ci: false,
        eval: false,
        observe_only: true,
        artifact_dir: None,
        resume_injection: None,
        claim_id_note: None,
        ambient: false,
        command,
        ..Default::default()
    };

    let t0 = Instant::now();
    let run = supervisor.execute(&args).await.expect("supervised run");
    let ms = t0.elapsed().as_millis();
    let events = store.count_events(&run.id).await.unwrap_or(0);
    let blob_bytes: u64 = std::fs::read_dir(&blobs)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0);
    assert_eq!(run.exit_code, Some(0));
    (ms, blob_bytes, events)
}

fn print_row(name: &str, direct: &[u128], supervised: &[u128], events: usize, blobs: u64) {
    println!(
        "{name:28} direct p50={:>5}ms p95={:>5}ms | blackbox p50={:>5}ms p95={:>5}ms | events={events} blobs={blobs}B",
        percentile(direct.to_vec(), 50.0),
        percentile(direct.to_vec(), 95.0),
        percentile(supervised.to_vec(), 50.0),
        percentile(supervised.to_vec(), 95.0),
    );
}

#[tokio::test]
#[ignore = "local overhead bench — run with --ignored; soft budgets only"]
async fn bench_suite_local() {
    println!("\n═══ Blackbox overhead bench (local) ═══");
    println!("samples={SAMPLES}  platform={}", std::env::consts::OS);

    // 1. Minimal command
    let mut d = Vec::new();
    let mut s = Vec::new();
    let mut events = 0usize;
    let mut blobs = 0u64;
    for _ in 0..SAMPLES {
        d.push(direct_ms(&["true"]));
        let (ms, b, e) = supervised_ms(vec!["true".into()], "bench-true").await;
        s.push(ms);
        events = e;
        blobs = b;
    }
    print_row("true (startup)", &d, &s, events, blobs);
    // Soft wall: supervised true should stay under 15s p95 in debug.
    assert!(
        percentile(s.clone(), 95.0) < 15_000,
        "true p95 too high: {}",
        percentile(s, 95.0)
    );

    // 2. High-volume PTY output
    d.clear();
    s.clear();
    for _ in 0..SAMPLES {
        d.push(direct_ms(&[
            "sh",
            "-c",
            "i=0; while [ $i -lt 200 ]; do echo line-$i-xxxxxxxxxxxxxxxxxxxx; i=$((i+1)); done",
        ]));
        let (ms, b, e) = supervised_ms(
            vec![
                "sh".into(),
                "-c".into(),
                "i=0; while [ $i -lt 200 ]; do echo line-$i-xxxxxxxxxxxxxxxxxxxx; i=$((i+1)); done"
                    .into(),
            ],
            "bench-pty",
        )
        .await;
        s.push(ms);
        events = e;
        blobs = b;
    }
    print_row("high-volume PTY (200 lines)", &d, &s, events, blobs);

    // 3. Quiet multi-file tree (no changes) — just ls
    d.clear();
    s.clear();
    for _ in 0..SAMPLES {
        d.push(direct_ms(&[
            "sh",
            "-c",
            "find . -maxdepth 2 -type f | head -50",
        ]));
        let (ms, b, e) = supervised_ms(
            vec![
                "sh".into(),
                "-c".into(),
                "find . -maxdepth 2 -type f | head -50".into(),
            ],
            "bench-find",
        )
        .await;
        s.push(ms);
        events = e;
        blobs = b;
    }
    print_row("find (shallow)", &d, &s, events, blobs);

    // 4. Nested process tree
    d.clear();
    s.clear();
    for _ in 0..SAMPLES {
        d.push(direct_ms(&[
            "sh",
            "-c",
            "sh -c 'sh -c \"echo nested; sleep 0.05\"'",
        ]));
        let (ms, b, e) = supervised_ms(
            vec![
                "sh".into(),
                "-c".into(),
                "sh -c 'sh -c \"echo nested; sleep 0.05\"'".into(),
            ],
            "bench-tree",
        )
        .await;
        s.push(ms);
        events = e;
        blobs = b;
    }
    print_row("nested process tree", &d, &s, events, blobs);

    // 5. Long-ish sleep simulation
    let (ms, b, e) = supervised_ms(
        vec!["sh".into(), "-c".into(), "sleep 0.2; echo done".into()],
        "bench-sleep",
    )
    .await;
    println!(
        "{:28} blackbox wall={ms}ms events={e} blobs={b}B (single sample)",
        "sleep 0.2 harness sim"
    );

    println!("═══ end bench ═══\n");
}

#[tokio::test]
async fn soft_true_overhead_still_bounded() {
    // Always-on soft guard (duplicates A6 but under observe-only for neutrality).
    let (ms, _, _) = supervised_ms(vec!["true".into()], "soft-true").await;
    assert!(ms < 12_000, "observe-only true overhead too high: {ms}ms");
}

/// Utility for scripts: measure event write throughput via direct store inserts.
#[tokio::test]
async fn event_write_throughput_smoke() {
    let store = Arc::new(SqliteStore::open_memory().unwrap());
    let mut run = blackbox::core::run::Run::new(vec!["bench".into()], "/tmp".into());
    run.status = blackbox::core::run::RunStatus::Succeeded;
    store.insert_run(&run).await.unwrap();

    let n = 500usize;
    let t0 = Instant::now();
    for i in 0..n {
        let mut ev = blackbox::core::event::TraceEvent::new(
            &run.id,
            blackbox::core::event::EventSource::System,
            "bench.event",
        );
        ev.sequence = i as u64;
        store.insert_event(&ev).await.unwrap();
    }
    let elapsed = t0.elapsed();
    let rate = n as f64 / elapsed.as_secs_f64().max(0.001);
    println!(
        "event write throughput: {n} events in {:?} ({rate:.0} ev/s)",
        elapsed
    );
    // Soft: at least 50 events/s even on slow debug builds.
    assert!(rate > 50.0, "event write too slow: {rate:.1} ev/s");
    // Bound wall time for the smoke (avoid hanging suites).
    assert!(elapsed < Duration::from_secs(30));
}
