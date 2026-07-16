# Debug a failure

**Answers:** How to go from “the agent (or command) failed” to a concrete next action using postmortem, anomalies, evidence links, timeline, and handoff.

---

## When to use this

- A supervised run exited non-zero or ended in `Failed`
- Sticky **attention** is `continue` or `blocked` (`blackbox status`)
- You need a shareable failure story for a human or the next agent

If capture itself is broken (no events, doctor errors), start with [troubleshooting.md](troubleshooting.md).

---

## Fast path (5 commands)

```bash
blackbox status
blackbox runs
blackbox postmortem latest
blackbox timeline latest --semantic
blackbox handoff --json          # for the next agent or your own notes
```

Optional interactive:

```bash
blackbox show latest --tui
# e = failure story, a = anomalies, Enter/g = jump to timeline seq
```

---

## 1. Confirm project attention

```bash
blackbox status
# or
blackbox status --json
```

Useful fields (names stable in JSON views): attention level, unresolved failure id, active claim, last run pointer, optional project memory summary.

| Attention | Meaning |
|---|---|
| `none` | No sticky failure pressure |
| `continue` | Prior failure or WIP expects follow-up |
| `blocked` | Stronger stop — do not ignore before proceeding |

Unrelated successful runs do **not** silently clear an unresolved failure (M6 discipline in the continuity design). Clear deliberately:

```bash
blackbox resolve
blackbox resolve --clear-wip
```

---

## 2. Read the postmortem

```bash
blackbox postmortem latest
blackbox postmortem latest --json
blackbox postmortem <run-id> --fail-on-failure   # CI-friendly exit status
```

Deterministic analysis (not an LLM). Typical payload:

| Field | Use |
|---|---|
| `headline` | One-line story |
| `next_action` | Recommended follow-up |
| `evidence` | Anchors: role, detail, optional `event_id` / `sequence` |
| `anomalies` | Structured markers (see below) |
| `turning_points` | Story beats in the run |
| `failure_fix_chains` | Error → subsequent file edits when correlatable |
| `narrative` | Longer prose summary |
| `errors_top` / tool failures | Classic failure rollups |

CI artifacts (when the run used `--artifact-dir`): `postmortem.json`, `anomalies.json`, `summary.txt`, `run.json`.

---

## 3. Interpret anomalies

Anomalies are first-class markers from the event stream:

| Kind | Rough meaning |
|---|---|
| `tool_loop` | Same tool/signature repeated beyond threshold |
| `destructive` | Side effect classified destructive |
| `error_storm` | Dense error-status events |
| `token_spike` | Unusual token/usage jump when present in metadata |
| `long_silence` | Large time gap in the stream |
| `process_fanout` | Large distinct PID set in process capture |

Severity: `info` | `warn` | `high`. High-severity anomalies influence `next_action` even on some non-obvious outcomes.

```bash
# API (dashboard)
curl -s http://127.0.0.1:7788/api/runs/<id>/anomalies | jq .
```

TUI: `a` for anomaly list; `e` folds anomalies into the failure story.

---

## 4. Follow evidence to the timeline

Evidence and anomaly rows often include `sequence` and/or `event_id`.

**CLI:**

```bash
blackbox timeline <run> --semantic
blackbox inspect <event-id>
```

**TUI:** select the evidence line → `Enter` or `g` → timeline selection moves to that event (or reports if filtered out—toggle `/` for bookkeeping).

**Dashboard:** open `/runs/{id}`, use anomaly chips and timeline table; live view streams events over SSE.

---

## 5. Compare to a prior run

```bash
blackbox diff <earlier> <later>
blackbox diff latest   # when CLI resolves a comparison pair — see help
```

Trajectory output includes longest common prefix style divergence, explanation text, and file hints after divergence. Use this when “it worked yesterday” is the actual question.

---

## 6. Hand off cleanly

```bash
blackbox handoff --json
blackbox context latest --for-resume --json --max-tokens 4000
```

`handoff` packages status + project memory (+ resume material when attention warrants). Agents should load this **before** new work in a `.blackbox/` project—see [skills/blackbox.md](../skills/blackbox.md).

If another holder owns a **claim**, do not clobber:

```bash
blackbox claim status
blackbox claim acquire --holder "you"
# … work …
blackbox claim release
```

---

## 7. Capture mode for the next attempt

| Goal | Flag / mode |
|---|---|
| Preserve exit codes in CI | `blackbox run --ci --artifact-dir ./out -- …` |
| Benchmark without launch mutation | `blackbox run --eval --artifact-dir ./out -- …` (forces observe-only + tags) |
| Full continuity inject | default project continuity; explicit `run` (not ambient) |
| Record only | `--observe-only` or ambient wrappers |

Eval/CI details: [CLI reference — run](../reference/cli.md).

---

## Limits (read before trusting the story)

- Postmortem quality tracks **what was captured**. Adapter parse failures still leave PTY text.
- Redaction may remove tokens from evidence strings; structural ids (UUIDs, blob hashes) should survive.
- Anomaly thresholds are heuristic; absence of anomalies ≠ healthy run.
- Replay does not re-run the LLM deterministically.

---

## See also

- [everyday-use.md](everyday-use.md) — TUI keys, serve, search
- [security.md](security.md) — if the failure involves leaked secrets
- [../reference/json-api.md](../reference/json-api.md) — exact view shapes
- [../internals/continuity-plane.md](../internals/continuity-plane.md) — attention / claims semantics
