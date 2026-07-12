# blackbox skill (for coding agents)

Local flight recorder for AI-agent runs. Secrets redacted by default.

## When to use

- Starting work in a project that has `.blackbox/` or after a prior agent failed
- Need a redacted postmortem, resume pack, or search across tool traces
- User asks to record / debug / hand off an agent session

## Session start (always if `.blackbox/` exists)

```bash
blackbox handoff --json
```

Or MCP tool `blackbox_handoff`. If `attention.needed`, read `resume_pack` before continuing.

## Common commands

| Goal | Command |
|---|---|
| Status | `blackbox status --json` |
| Handoff + resume | `blackbox handoff --json` |
| Postmortem | `blackbox postmortem latest --json` |
| Resume pack | `blackbox context latest --for-resume --json` |
| Search | `blackbox search "error" --json` |
| Record | `blackbox run -- <cmd>` |
| Enable project | `blackbox enable --install-shell` |
| MCP server | `blackbox mcp` |

## Rules

- Never pass `--insecure-raw` / `--no-redact` unless the user explicitly asks
- Prefer JSON (`--json`) over scraping human text
- Auto-resume may inject prior failure context into the next harness launch; respect `BLACKBOX_OFF=1` when the user wants no recording
