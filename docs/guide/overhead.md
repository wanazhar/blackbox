# Overhead & storage cost

Blackbox is meant to stay enabled. This page documents how to measure capture
overhead locally and how `stats` / `doctor` report cost.

> **Note:** Full micro-benchmarks are **local-only** soft checks. They are not
> hard CI release gates (and should not be used as flaky performance tests).

---

## 1. Soft smoke (always-on)

```bash
# A6 — supervising `true` must stay under a generous wall budget
cargo test --test overhead_smoke

# Extra soft checks (observe-only true + event write rate)
cargo test --test overhead_bench soft_true
cargo test --test overhead_bench event_write
```

These use multi-second budgets suitable for debug builds.

---

## 2. Full local suite (ignored by default)

```bash
cargo test --test overhead_bench -- --ignored --nocapture
```

Scenarios (supervised vs direct):

| Scenario | What it measures |
|---|---|
| `true` (startup) | Minimal command supervision overhead |
| High-volume PTY | 200 short output lines |
| Shallow `find` | FS watcher / quiet tree |
| Nested process tree | `/proc` poller cost on Linux |
| Sleep harness sim | Longer-lived child |

Reports **p50 / p95** wall times for direct vs blackbox, plus event count and
blob growth for the last sample.

### Suggested environment fields (publish with release notes)

| Field | Example |
|---|---|
| OS | Linux x86_64 / Linux aarch64 |
| Kernel | `uname -r` |
| CPU | model name + cores |
| Rust | `rustc --version` |
| Build | `cargo test` (debug) or `cargo test --release` |
| Disk | SSD / tmpfs for store |
| Blackbox | `cargo package version` |

Record results in release notes, not as hard CI thresholds.

---

## 3. Product surfaces

### `blackbox stats`

Reports:

- DB + blob sizes and soft storage warnings
- **Average events per sampled run**
- **Average blob bytes per run**

```bash
blackbox stats
blackbox stats --json
```

### `blackbox doctor`

Reports store size, capture config, and **observe-only / continuity mode**.

```bash
blackbox doctor
blackbox doctor --json
```

---

## 4. Soft warnings

Blackbox emits soft (non-fatal) guidance when:

- Total store size exceeds ~1 GiB or blobs exceed ~512 MiB (`doctor` / `stats`)
- Capture overhead smoke budgets are exceeded in tests

There is no hard kill of ambient capture on size alone; use `blackbox gc` /
retention config when stores grow.

---

## 5. Result table template

Copy into CHANGELOG / release notes after:

```bash
cargo test --test overhead_bench -- --ignored --nocapture
```

```text
Blackbox overhead (debug build, N samples)

Machine: <os> <cpu>
Version: <x.y.z>

Scenario                     direct p50   blackbox p50   blackbox p95
true (startup)               ___ ms       ___ ms         ___ ms
high-volume PTY (200 lines)  ___ ms       ___ ms         ___ ms
find (shallow)               ___ ms       ___ ms         ___ ms
nested process tree          ___ ms       ___ ms         ___ ms
```

### Soft smoke (always-on CI, this tree)

| Check | Budget | Status |
|---|---|---|
| `overhead_smoke` supervising `true` | < 8s debug | gated in `tests/overhead_smoke.rs` |
| `overhead_bench` soft_true (observe-only) | < 12s | always-on |
| event write throughput | > 50 ev/s | always-on |

`blackbox doctor` now reports **daily-driver score** (observe-only, redaction clean, store size, last capture quality, capture lag). Aim for `daily-driver: ready` before leaving ambient wrap installed.

---

## 6. Related

- [Security](security.md) — redaction is always-on by default (small CPU cost)
- [Configuration](configuration.md) — retention / wrap list
- CLI: `blackbox stats`, `blackbox doctor`, `blackbox gc`
