# Doctor and capture quality

**Answers:** How to read `blackbox doctor`, what daily-driver score means, how per-run capture coverage is scored, and what to do when quality is low.

Related: [troubleshooting](troubleshooting.md) · [overhead](overhead.md) · [configuration](configuration.md) · TUI `c` panel (capture quality).

---

## Quick commands

```bash
blackbox doctor
blackbox doctor --json | jq .
blackbox stats
blackbox show latest --tui     # press c for coverage panel
blackbox postmortem latest     # includes capture_coverage when present
```

---

## 1. What `doctor` is for

`doctor` diagnoses **environment + store health + trust posture** for leaving blackbox on. It is not a postmortem of agent logic (use [debug-a-failure](debug-a-failure.md) for that).

Use it when:

- First install / enable  
- Ambient capture “does nothing”  
- Disk is growing  
- You care whether ambient is safe enough to leave on  

---

## 2. Doctor fields (operator map)

| Field / area | Meaning |
|---|---|
| `version` / `schema_version` | Binary + SQLite schema |
| `db_path` / `blob_dir` / `project_root` | Where data lives (unexpected path → env/legacy db) |
| `db_exists` / `blob_dir_exists` | Missing dirs → enable or first run not done |
| `store_size_bytes` / `blob_bytes` / `total_storage_bytes` | Disk footprint |
| `storage_warning` | Soft size warning (not a hard fail) |
| `run_count` / `running_count` | Orphan `Running` → crash recovery needed |
| `fts5` | Full-text search backend status |
| `secrets_clean` | Soft redaction hygiene signal when present |
| `config` | enabled, wrap list, retention |
| `blackbox_on_path` | Wrappers need binary on PATH |
| `shell_integration_hint` | Install/uninstall shell tips |
| `continuity_mode` / `observe_only` / `product_mode` notes | Recorder vs continuity |
| `memory_file_present` / `memory_age_secs` | MEMORY pack freshness |
| `claims_active` / `unresolved_failure_id` / `attention_level` | Sticky multi-agent / failure state |
| `last_capture_quality` | Quality score from latest run’s `capture.coverage` |
| `recorder_neutrality_supported` | Host supports hard recorder neutrality (Unix; 1.4) |
| `nest_guard` | Nest implementation (`supervisor_pid_marker`) |
| **`daily_driver_score`** | Soft 0–100 readiness for ambient trust |
| **`daily_driver_ready`** | `true` when score ≥ 80 and no hard blockers |
| **`daily_driver_notes`** | Human reasons (tips, penalties, crypto, eval, neutrality, …) |

JSON shape: `DoctorView` in `src/views.rs`. Envelope: [../reference/json-api.md](../reference/json-api.md).

### Daily-driver score (how to read it)

| Result | Meaning |
|---|---|
| `daily_driver_ready: true` (score ≥ 80) | Reasonable to leave ambient on (still read notes) |
| Score mid-range | Fix notes (PATH, permissions, retention, quality) |
| Low score / not ready | Do not treat ambient as “set and forget” yet |

Typical **penalties / notes** (non-exhaustive; code is source of truth):

| Situation | Effect (approx.) |
|---|---|
| Large store / progressive GC tips | −5 each tip |
| Orphan `Running` runs | −10 |
| Binary not on PATH | −5 |
| Last run quality &lt; 40% | −15 |
| Last run capture lag note | −10 |
| `capture.warning` on last run | −10 |
| Last run **adapter drought** (`capture.warning` / `adapter_drought`) | −10 (extra note) |
| Redaction / enable issues | can block “ready” |

Notes also include **informational** tips (encrypt_blobs, backup vault, eval harness, product_mode, native_log_scope) that may not all subtract score.

### Adapter drought (structured tools missing)

Known harness adapters (`claude`, `codex`, `aider`, `gemini`, `cursor`, `opencode`, `grok`) normally emit structured `tool.call` events. When a **long enough** run finishes with **zero** `tool.call` events, blackbox records honesty signals:

| Surface | What you see |
|---|---|
| `capture.coverage` notes | Text note: `adapter drought: harness=… produced 0 tool.call events…` |
| `capture.warning` event | `metadata.warning = "adapter_drought"` (+ message) |
| `doctor` daily-driver notes | “last run adapter drought … check stream-json / native logs” |

**Threshold:** tool_call_count == 0 **and** (event count ≥ 20 **or** duration ≥ 5s). Short setup samples (`true` / echo) do not fire. Generic adapter is excluded.

**What to do:** confirm the harness is writing stream-json / native logs blackbox can parse; check `native_log_scope`; see [adapters.md](adapters.md). The PTY timeline still exists — drought is about **structured** tools, not total silence.

---

## 3. Per-run capture coverage

At end of run, blackbox writes a system event:

| | |
|---|---|
| **kind** | `capture.coverage` |
| **metadata.coverage** | `CaptureCoverage` object |

### Surfaces

| Surface | What it reflects |
|---|---|
| `pty` | Terminal I/O under the supervised PTY |
| `process` | Process-tree observer |
| `git` | Git snapshot / dirty signals |
| `filesystem` | FS observer events |
| `environment` | Env capture events |
| `native_logs` | Harness log poller (when enabled) |
| (others) | e.g. network placeholder — often disabled |

### Surface status

| Status | Meaning | Quality weight |
|---|---|---|
| `complete` | Operated normally (process requires full observer lifecycle) | 1.0 |
| `partial` | Some events with known gaps | 0.5 |
| `failed` | Enabled but failed | 0.1 |
| `unavailable` | Surface could apply but was not observed | 0.0 |
| `disabled` | Intentionally off (omitted from score denominator) | — |
| `not_applicable` | Does not apply to this run (e.g. non-git tree); **excluded** from score | — |
| `unknown` | Not established | 0.0 |

**Applicability (1.4 C1):** git is `not_applicable` when the project is not a git repository. Native logs are `not_applicable` for the generic adapter (no native surface) and `disabled` when `native_log_scope=off`. Network stays `unavailable` (may have occurred; not captured) — never `not_applicable`.

**Process completeness (1.4 C2):** process is not `complete` merely because process events exist. It needs observer started, root `process.spawned`, tree snapshot, observer stopped, backend identity, and no material lag.

### Quality score algorithm

Weighted average over **applicable** surfaces (excludes `disabled` and `not_applicable`), then ×100, rounded, clamped 0–100:

| Surface | Weight |
|---|---|
| pty | 30% |
| process | 25% |
| git | 15% |
| filesystem | 15% |
| environment | 5% |
| native_logs | 10% |

Coverage JSON also includes **`contributions`**: per-surface `weight`, `points`, `status`, and `excluded` so agents can audit the math (1.4 C3).

Non-git runs with all applicable surfaces complete can reach **100%**.

Implementation: `CaptureCoverage::compute_quality_score` / `compute_contributions` in `src/capture/coverage.rs`.

### Where you see it

```bash
blackbox postmortem latest --json | jq '.data.capture_coverage // .data.summary.capture_coverage'
blackbox timeline latest --kind capture.coverage
# TUI: mode c (capture quality)
blackbox doctor --json | jq '.data.last_capture_quality, .data.daily_driver_score'
```

Notes inside coverage may mention **capture lag** (store falling behind writers) — doctor penalizes lag strings in notes.

---

## 4. What to do when quality is low

| Symptom | Checks |
|---|---|
| Low PTY | Did the process run under `blackbox run` / ambient? PTY failures in timeline? |
| No process tree | Platform limits; `process_subreaper` / dense poll knobs |
| Git failed / empty | Not a git repo; git timeout; dirty ignore of `.blackbox/` |
| FS quiet | Short run with no writes; observer filters |
| native_logs empty | `native_log_scope=off` or project-only with logs only in home |
| Capture lag | Disk pressure; huge event rate; see overhead guide |

Minimal repro:

```bash
blackbox run --observe-only -- true
blackbox doctor
blackbox show latest --tui   # c
```

If `true` scores poorly only on optional surfaces, that can be normal. A long agent run with quality &lt; 40 needs investigation.

---

## 5. `stats` vs `doctor`

| | `doctor` | `stats` |
|---|---|---|
| Goal | Trust + config + readiness | Aggregate volume |
| Score | daily-driver + last quality | averages events/blobs |
| When | Install, ambient leave-on | Disk planning |

Both soft-warn on large stores. Neither deletes data — use `gc` / `purge` / retention.

---

## 6. Related recipes

- [recipes §15 minimal repro](recipes.md#15-something-is-broken-minimal-repro)  
- [recipes §12 cap disk](recipes.md#12-cap-disk-growth)  
- [cheatsheet](cheatsheet.md)  

Annotated JSON samples: [examples](examples.md).
