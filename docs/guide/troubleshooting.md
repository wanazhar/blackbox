# Troubleshooting

Symptom-first diagnostics. Each entry: likely cause → one diagnostic command → fix → what may be missing.

Related: [debug-a-failure.md](debug-a-failure.md) (agent logic failed), [install.md](install.md), [security.md](security.md), [doctor-and-capture.md](doctor-and-capture.md).

---

## No run was recorded

| | |
|---|---|
| **Likely cause** | Command not under `blackbox run` / ambient wrap; `BLACKBOX_OFF`; wrong store path |
| **Diagnostic** | `blackbox runs --limit 5` and `blackbox doctor --json` (store path) |
| **Fix** | `blackbox run -- <cmd>` or enable ambient wrappers; unset `BLACKBOX_OFF`; check `--store` / `BLACKBOX_DB` |
| **May be missing** | Entire run (nothing to import/analyze) |

---

## Run is marked partial / Failed after crash

| | |
|---|---|
| **Likely cause** | Supervisor exited while status was `Running` (recovered on next open) |
| **Diagnostic** | `blackbox show latest --json` → notes contain `recovered:` / `interrupted` |
| **Fix** | Re-run the agent; inspect last events; do not treat as success |
| **May be missing** | Final events, end checkpoint, complete coverage |

---

## Native tool calls are missing

| | |
|---|---|
| **Likely cause** | Generic adapter; native logs off/project-only; adapter drought |
| **Diagnostic** | `blackbox postmortem latest --json` → `capture_coverage` / `native_log.health` |
| **Fix** | Use a known harness binary; set native log scope if appropriate; inspect PTY transcript |
| **May be missing** | Structured `tool.call` / `tool.result` (PTY text may still exist) |

---

## Dashboard returns 401

| | |
|---|---|
| **Likely cause** | `--token` / `BLACKBOX_SERVE_TOKEN` set; no Bearer header or session cookie |
| **Diagnostic** | `curl -sI -H "Authorization: Bearer $TOKEN" http://127.0.0.1:7788/api/runs` |
| **Fix** | Browser: open `/login` and submit token (sets HttpOnly cookie). API: `Authorization: Bearer …`. Do not put tokens in query strings |
| **May be missing** | Nothing in the store; auth only |

---

## Replay skipped a command

| | |
|---|---|
| **Likely cause** | Workspace policy blocked shell/lossy argv/destructive side effects |
| **Diagnostic** | Re-run with preflight output; check fidelity / side_effect on the event |
| **Fix** | Prefer exact argv capture; use `--live` only when you accept full side effects; workspace mode is not kernel isolation |
| **May be missing** | That command’s re-execution (original trace still present) |

---

## Store key is missing / blob load failed

| | |
|---|---|
| **Likely cause** | Incomplete export; hash mismatch rejected on import; blob GC; wrong store path |
| **Diagnostic** | `blackbox doctor`; re-import error message for `hash mismatch` |
| **Fix** | Export with blobs; import without tampering keys; avoid scrubbing live keys |
| **May be missing** | Payload bytes for that blob key |

---

## Database is locked

| | |
|---|---|
| **Likely cause** | Concurrent writer (`serve` + `run`, or multiple CLIs) on the same SQLite file |
| **Diagnostic** | `lsof` / process list on `.blackbox/blackbox.db`; `blackbox doctor` |
| **Fix** | Stop the other process; wait for WAL writers; avoid copying DB while open |
| **May be missing** | In-flight events not yet committed |

---

## Disk usage keeps growing

| | |
|---|---|
| **Likely cause** | Blobs + WAL growth; retention not applied; large native logs / transcripts |
| **Diagnostic** | `blackbox stats`; `du -sh .blackbox` |
| **Fix** | Configure retention; `blackbox scrub --gc`; export then delete old runs |
| **May be missing** | Nothing required for correctness—only disk |

---

## Postmortem analysis is partial

| | |
|---|---|
| **Likely cause** | Large run; display window vs totals; incomplete aggregates after crash |
| **Diagnostic** | `blackbox postmortem latest --json` → `analysis_scope` (`events_total`, `events_loaded`, `aggregates_complete`) |
| **Fix** | Trust aggregate totals; use timeline/search for middle events; recompute via store open |
| **May be missing** | Full event evidence for causal detail outside the loaded window |

---

## Always start with diagnostics

```bash
blackbox --version
which -a blackbox
blackbox doctor
blackbox doctor --json
blackbox stats
blackbox status
```

Field-level doctor guide: [doctor-and-capture.md](doctor-and-capture.md).

---

## FAQ

**Can I use blackbox without shell wrappers?**  
Yes. Explicit `blackbox run -- <cmd>` only.

**Windows?**  
Out of scope for 1.5; strongest PTY fidelity is Unix.

**How do I share a run?**  
`blackbox export <id> --format portable -o trace.json` (redacted). Recipient: `blackbox import trace.json`.

**Is postmortem an LLM summary?**  
No. Deterministic analysis over the event stream.

**JSON shape?**  
[../reference/json-api.md](../reference/json-api.md).

---

## Still stuck?

1. `blackbox doctor --json` and `blackbox status --json`
2. Minimal repro: `blackbox run --observe-only -- true` then `show latest`
3. File an issue with doctor JSON (redact hosts/paths), OS, version, ambient vs explicit run

Internals: [../internals/architecture.md](../internals/architecture.md).
