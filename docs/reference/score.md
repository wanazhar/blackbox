# Eval score reference (`blackbox.score/v1`)

Shape of `score.json` written under `--artifact-dir` for CI and harness benchmarks.

Related: [CLI `run --eval`](cli.md) · [recipes CI/eval](../guide/recipes.md) · GitHub Action `.github/actions/blackbox-eval/`.

---

## When it is written

Any `blackbox run` with **`--artifact-dir <dir>`** writes:

| File | Role |
|---|---|
| `run.json` | Run record |
| `postmortem.json` | Full summary view |
| `anomalies.json` | Anomaly array |
| `summary.txt` | Headline / next / exit (logs) |
| **`score.json`** | **`blackbox.score/v1` machine score** |
| `portable.json` | Optional portable export |

`--eval` forces observe-only + CI exit codes + tags `eval`/`ci` and is the recommended path for benchmarks.

---

## Schema

```json
{
  "schema": "blackbox.score/v1",
  "run_id": "…",
  "short_id": "a1b2c3d4",
  "status": "failed",
  "exit_code": 1,
  "failed": true,
  "duration_ms": 1234,
  "adapter": "claude",
  "tags": ["eval", "ci"],
  "name": null,
  "command": ["…"],
  "headline": "…",
  "next_action": "…",
  "anomaly_count": 2,
  "anomalies_by_severity": { "high": 1, "warn": 1 },
  "anomalies_by_kind": { "tool_loop": 1, "long_silence": 1 },
  "capture_quality": 72,
  "events_scanned": 400,
  "tools_total": 12,
  "error_count": 3,
  "estimated_cost_usd": null,
  "scored_at": "2026-07-16T12:00:00+00:00"
}
```

| Field | Notes |
|---|---|
| `schema` | Always `blackbox.score/v1` (additive fields only later) |
| `failed` | Failed/Cancelled status **or** non-zero exit |
| `anomaly_count` / `anomalies_by_*` | From postmortem anomaly markers |
| `capture_quality` | 0–100 when `capture.coverage` present |
| `estimated_cost_usd` | Only when pricing enabled on the run |

Rust: `blackbox::score::EvalScore`.

---

## jq examples

```bash
# Fail CI if score says failed
jq -e '.failed == false' score.json

# High-severity anomalies
jq '.anomalies_by_severity.high // 0' score.json

# Compact row for a table
jq -r '[.short_id, .exit_code, .anomaly_count, .capture_quality // "—"] | @tsv' score.json
```

---

## GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: dtolnay/rust-toolchain@stable
- uses: ./.github/actions/blackbox-eval
  with:
    command: 'python scripts/bench.py'
    artifact-dir: eval-out
    artifact-name: my-eval
```

Installs blackbox (from this repo when present, else crates.io), runs:

```bash
blackbox run --eval --ci --artifact-dir eval-out -- <command>
```

Uploads the artifact directory (always, even on failure).

---

## Related tests

- `src/score.rs` unit tests  
- `tests/ci_eval.rs` — `score.json` on artifact path + failed eval  
