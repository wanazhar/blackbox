# blackbox skill

Local flight recorder for AI-agent runs. Secrets redacted by default.

## When to use
- After a failed or long agent run: postmortem + resume pack
- Before an expensive retry: compare prior attempt trajectory
- When sharing a trace: export redacted HTML/portable

## Commands (prefer --json)
```bash
blackbox doctor --json
blackbox runs --json
blackbox postmortem latest --json
blackbox show latest --json
blackbox search "error" --json
blackbox context latest --for-resume --json --max-tokens 4000
blackbox diff <runA> <runB> --trajectory --json
blackbox export latest --format portable > run.json
```

## Ambient capture
```bash
blackbox enable   # once per project; paste shell snippets
# then claude/codex go through maybe-run when basename is in wrap list
```

## When not to use
- Pure chat with no tools and no need for audit trail
- User set BLACKBOX_OFF
- Do not invent run ids if `ok: false` / not_found

## Failure handling
If JSON `ok` is false, report `error.code` + message to the user; do not retry with fabricated IDs.
