# blackbox skill

Local flight recorder + project memory bus for AI-agent runs. Secrets redacted by default.

## When to use
- Session start in a project with `.blackbox/`: load handoff/memory first
- After a failed or long agent run: postmortem + project memory
- Before an expensive retry: compare prior attempt; honor claims
- When sharing a trace: export redacted HTML/portable

## Session start
```bash
blackbox handoff --json
# or MCP: blackbox_handoff / blackbox_memory
```
Read `project_memory` and `attention.level` before continuing.

## Commands (prefer --json)
```bash
blackbox doctor --json
blackbox memory show --json
blackbox memory set --goal "…" --open "item"
blackbox claim status
blackbox resolve
blackbox runs --json
blackbox postmortem latest --json
blackbox show latest --json
blackbox search "error" --json
blackbox context latest --for-resume --json --max-tokens 4000
blackbox diff <runA> <runB> --trajectory --json
blackbox export latest --format portable > run.json
```

## Ambient capture + memory bus
```bash
blackbox enable --memory-bus --install-shell   # once; open new shell
# then claude/codex go through maybe-run when basename is in wrap list
# continuity injects MEMORY when configured (always for new projects)
```

## When not to use
- Pure chat with no tools and no need for audit trail
- User set BLACKBOX_OFF
- Do not invent run ids if `ok: false` / not_found

## Failure handling
If JSON `ok` is false, report `error.code` + message to the user; do not retry with fabricated IDs.
