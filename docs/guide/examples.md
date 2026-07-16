# Annotated examples (status & handoff)

**Answers:** What a real `status --json` / `handoff --json` payload looks like and which fields agents should branch on.

These are **illustrative** (field names match the binary; values are sample). Always prefer live:

```bash
blackbox status --json | jq .
blackbox handoff --json | jq .
```

Envelope: [../reference/json-api.md](../reference/json-api.md). Session playbook: [../skills/blackbox.md](../skills/blackbox.md).

---

## 1. Decision tree (read this first)

```
handoff / status
    │
    ├─ enabled == false ──────────► blackbox enable  (or wrong cwd)
    │
    ├─ attention.level
    │     none ───────────────────► normal work; still honor claims
    │     info ───────────────────► read reason; often dirty tree
    │     continue / blocked ─────► fix failure context before new goals
    │
    ├─ claims / project_memory.claims
    │     other holder ───────────► do not clobber; claim status / coordinate
    │
    └─ project_memory / resume_pack / postmortem
          use headline, next_action, evidence, open_items
```

---

## 2. `blackbox status --json` (lighter)

CLI envelope omitted below — under `--json` the object is in `.data`.

```json
{
  "project_root": "/home/you/proj",
  "store_db": "/home/you/proj/.blackbox/blackbox.db",
  "enabled": true,
  "observe_only": false,
  "continuity_mode": "always",
  "product_mode": "continuity",
  "wrap": ["claude", "codex", "aider", "cursor", "cursor-agent", "gemini", "opencode", "grok"],
  "shell_integration": {
    "detected_shell": "bash",
    "installed": true,
    "paths": ["/home/you/.bashrc"],
    "path": "/home/you/.bashrc"
  },
  "retention": {
    "keep_runs": 100,
    "max_age_days": null,
    "auto_apply": true,
    "auto_gc_blobs": false
  },
  "last_run": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "short_id": "a1b2c3d4",
    "status": "failed",
    "exit_code": 1,
    "name": "fix-login",
    "command_preview": "claude -p Fix login",
    "ended_at": "2026-07-16T12:00:00Z",
    "adapter": "claude"
  },
  "last_failure": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "short_id": "a1b2c3d4",
    "status": "failed",
    "exit_code": 1
  },
  "attention": {
    "needed": true,
    "level": "continue",
    "reason": "unresolved failure on a1b2c3d4",
    "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  },
  "next_commands": [
    "blackbox postmortem a1b2c3d4",
    "blackbox timeline a1b2c3d4 --semantic",
    "blackbox resolve"
  ],
  "agent_instructions": null
}
```

### Field notes

| Path | Branch on it? |
|---|---|
| `enabled` | Yes — if false, no project capture |
| `observe_only` / `continuity_mode` / `product_mode` | Yes — whether inject will happen on next explicit run |
| `attention.level` | **Primary** session gate |
| `attention.reason` / `run_id` | What failed |
| `last_run` / `last_failure` | Which id to postmortem |
| `next_commands` | Suggested CLI (not mandatory) |
| `shell_integration.installed` | Ambient wrappers present? |
| `wrap` | Ambient basenames |

`status` by default may **omit** heavy `project_memory` / `resume_pack` unless flags request them. Prefer `handoff` for full session start.

---

## 3. `blackbox handoff --json` (session start)

Handoff is status-oriented plus memory and optional resume/postmortem excerpts.

```json
{
  "project_root": "/home/you/proj",
  "store_db": "/home/you/proj/.blackbox/blackbox.db",
  "enabled": true,
  "observe_only": false,
  "continuity_mode": "always",
  "product_mode": "continuity",
  "wrap": ["claude", "codex", "aider"],
  "attention": {
    "needed": true,
    "level": "continue",
    "reason": "unresolved failure",
    "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  },
  "last_run": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "short_id": "a1b2c3d4",
    "status": "failed",
    "exit_code": 1,
    "adapter": "claude"
  },
  "next_commands": [
    "blackbox postmortem a1b2c3d4",
    "blackbox claim status"
  ],
  "project_memory": {
    "schema": "blackbox.memory/v1",
    "purpose": "handoff",
    "degraded": false,
    "headline": "Login fix failed: tool_loop on Bash; tests still red",
    "next_action": "Inspect seq≈40–52; stop repeating the same curl; fix auth middleware",
    "attention_level": "continue",
    "attention_reason": "unresolved failure",
    "continuity_mode": "always",
    "truncated": false,
    "approx_tokens": 1800,
    "intent": {
      "goal": "Fix the login CI flake",
      "open_items": ["Stabilize auth test", "Update README"],
      "do_not_retry": []
    },
    "claims": {
      "active": null,
      "conflicts": []
    },
    "last_run": {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "short_id": "a1b2c3d4",
      "status": "failed",
      "exit_code": 1
    },
    "git": {
      "dirty": true,
      "branch": "fix/login",
      "head": "deadbeef…"
    },
    "destructive_paths": [],
    "side_effects_top": [],
    "secret_redaction_events": 3,
    "failed_tools": [],
    "files_touched": ["local-write:src/auth/middleware.rs"]
  },
  "resume_pack": {
    "purpose": "for-resume",
    "focus_run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "headline": "…",
    "next_action": "…"
  },
  "postmortem": {
    "run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "short_id": "a1b2c3d4",
    "narrative": "Agent looped on Bash curl against /login; exit 1.",
    "next_action": "Inspect timeline around tool_loop; fix middleware",
    "failure_count": 2,
    "turning_points": ["first tool error", "repeated Bash"]
  }
}
```

### Field notes

| Path | How to use |
|---|---|
| `project_memory.headline` / `next_action` | **Start here** for narrative |
| `project_memory.degraded` | true → sticky-only; store was unavailable |
| `project_memory.truncated` | Budget dropped lower-priority fields |
| `project_memory.intent.*` | Goals/open items you should not ignore |
| `project_memory.claims` | Multi-agent lock |
| `project_memory.secret_redaction_events` | Count only — never secret values |
| `resume_pack` | Single-run retry context when attention/always |
| `postmortem` | Compact failure excerpt on handoff |

Full pack schema: [../reference/memory-pack.md](../reference/memory-pack.md).

---

## 4. jq snippets agents actually use

```bash
# Attention gate
blackbox handoff --json | jq -r '.data.attention.level'

# Headline + next
blackbox handoff --json | jq -r '.data.project_memory.headline, .data.project_memory.next_action'

# Open items
blackbox handoff --json | jq -r '.data.project_memory.intent.open_items // [] | .[]'

# Claim holder
blackbox handoff --json | jq '.data.project_memory.claims.active'

# Follow-up postmortem
id=$(blackbox handoff --json | jq -r '.data.attention.run_id // .data.last_run.id // empty')
[ -n "$id" ] && blackbox postmortem "$id" --json | jq '{headline, next_action, anomalies, evidence}'
```

---

## 5. Doctor sample (readiness)

```bash
blackbox doctor --json | jq '{
  daily_driver_ready: .data.daily_driver_ready,
  daily_driver_score: .data.daily_driver_score,
  last_capture_quality: .data.last_capture_quality,
  notes: .data.daily_driver_notes,
  attention_level: .data.attention_level,
  store: .data.db_path
}'
```

Field guide: [doctor-and-capture.md](doctor-and-capture.md).

---

## 6. Honesty

- Sample JSON is not a golden fixture for every field on every version  
- Optional fields may be absent (`skip_serializing_if`)  
- MCP tools return **raw views without** the CLI envelope  
- MEMORY is **untrusted prior context** for models  

Contract tests that *do* pin shapes: `tests/docs_first_run.rs`, `tests/memory_pack_quality.rs`.
