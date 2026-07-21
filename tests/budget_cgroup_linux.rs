//! 1.6 F: cgroup v2 budget apply is best-effort and honest about capability.

use blackbox::budget::{
    cgroup_v2_memory_writable, linux_enforcement_status_with_cgroup, BudgetCapability,
    BudgetPolicy, CgroupScope,
};

#[test]
fn cgroup_probe_and_capability_honesty() {
    let policy = BudgetPolicy {
        max_memory_bytes: Some(128 * 1024 * 1024),
        max_cpu_percent: Some(25),
        max_processes: Some(128),
        max_wall_secs: Some(60),
        ..Default::default()
    };

    let applied = CgroupScope::create_for_pid(std::process::id(), &policy);
    let report = applied.as_ref().map(|(_, r)| r.clone());
    let caps = linux_enforcement_status_with_cgroup(&policy, report.as_ref());

    let mem = caps.iter().find(|c| c.name == "memory").unwrap();
    let cpu = caps.iter().find(|c| c.name == "cpu").unwrap();
    let wall = caps.iter().find(|c| c.name == "wall_time").unwrap();

    // Wall is always enforced via watchdog when configured.
    assert!(matches!(wall.capability, BudgetCapability::Enforced));

    if let Some(ref r) = report {
        if r.memory_enforced {
            assert!(matches!(mem.capability, BudgetCapability::Enforced));
        } else {
            // Host without writable memory.max must not claim hard cgroup enforcement.
            assert!(
                matches!(
                    mem.capability,
                    BudgetCapability::ObservedOnly | BudgetCapability::Unavailable
                ),
                "unexpected memory capability {:?}",
                mem.capability
            );
        }
        if r.cpu_enforced {
            assert!(matches!(cpu.capability, BudgetCapability::Enforced));
        }
    } else {
        // No cgroup leaf — still must not crash; probe may be false.
        let _ = cgroup_v2_memory_writable();
        assert!(
            matches!(
                mem.capability,
                BudgetCapability::ObservedOnly | BudgetCapability::Unavailable
            ),
            "{:?}",
            mem.capability
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn prlimit_as_applied_for_memory_policy_on_child_api() {
    use blackbox::budget::apply_child_rlimits;
    let notes = apply_child_rlimits(
        std::process::id(),
        &BudgetPolicy {
            max_memory_bytes: Some(512 * 1024 * 1024),
            ..Default::default()
        },
    );
    // Either applied or explicitly unavailable — never silent.
    assert!(
        notes.iter().any(|n| n.contains("RLIMIT_AS")),
        "expected RLIMIT_AS note, got {notes:?}"
    );
}
