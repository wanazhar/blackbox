# Cheatsheet

One screen of high-signal commands. Full workflows: [recipes](recipes.md). Flags: [CLI reference](../reference/cli.md).

---

## Install & project

```bash
curl -fsSL https://raw.githubusercontent.com/wanazhar/blackbox/master/install.sh | sh
# or: cargo install blackbox-recorder

blackbox --version
blackbox doctor

cd ~/project
blackbox setup                               # enable + sample run + doctor
blackbox setup --memory-bus --install-shell  # + continuity + ambient wrap
blackbox setup --harden                      # encrypt_blobs + external key path
blackbox enable                              # store + config only
blackbox enable --harden                     # same trust profile without sample run
blackbox enable --memory-bus --install-shell
blackbox disable                             # pause (keeps data)
# optional: capture.ambient_notice = true → one stderr line after ambient record
```

---

## Record

```bash
blackbox run -- <cmd> [args…]
blackbox run --name label --tag wip -- <cmd>
blackbox run --ci --artifact-dir ./out -- <cmd>     # exit = child; write artifacts
blackbox run --eval --artifact-dir ./out -- <cmd>   # observe-only + tags eval,ci
# ./out → run.json postmortem.json anomalies.json summary.txt score.json
blackbox run --observe-only -- <cmd>                # no launch mutation
```

Ambient (after `--install-shell`): just run `claude` / `codex` / …  
Off: `BLACKBOX_OFF=1` · nest-safe under active run.  
Optional: `capture.ambient_notice = true` → one stderr line after ambient record.

---

## Inspect

```bash
blackbox runs
blackbox runs --status failed --limit 10
blackbox show latest
blackbox show latest --transcript
blackbox show latest --tools
blackbox show latest --tui          # e fail · a anom · Enter/g jump · ? help
blackbox timeline latest --semantic
blackbox timeline latest --kind tool.call
blackbox inspect <event-id>
blackbox search "timeout"
blackbox serve                      # http://127.0.0.1:7788
blackbox serve --token "$TOKEN"
```

---

## Explain / compare

```bash
blackbox fail                                # best failure / attention focus
blackbox fail --json
blackbox fail <run-id>
blackbox postmortem latest
blackbox postmortem latest --json --fail-on-failure
blackbox analyze latest
blackbox diff <good> <bad> --trajectory
```

---

## Continuity / multi-agent

```bash
blackbox status
blackbox handoff --json
blackbox memory show
blackbox memory set --goal "…" --open "…"
blackbox claim acquire --holder "$USER"
blackbox claim acquire --holder a --path src/auth
blackbox claim status
blackbox claim release
blackbox resolve
blackbox resolve --clear-wip
blackbox ack                        # gate_mode=require_ack
blackbox context latest --for-resume --json --max-tokens 4000
```

---

## Share / vault / hygiene

```bash
blackbox export latest --format html -o r.html
blackbox export latest --format portable -o r.json
blackbox export latest --format portable --passphrase '…' -o r.bbx.json
blackbox import r.json

blackbox backup -o vault.bbx.json --passphrase '…' --include-db
blackbox restore vault.bbx.json --passphrase '…'

blackbox scrub --gc
blackbox stats
blackbox gc --dry-run && blackbox gc
blackbox purge --keep 50 --dry-run
```

---

## JSON & agents

```bash
blackbox <cmd> --json | jq .
blackbox mcp                        # stdio MCP server
```

Session start: `blackbox handoff --json` · skill: [../skills/blackbox.md](../skills/blackbox.md)

---

## Danger flags (avoid)

| Flag | Effect |
|---|---|
| `--no-redact` | Disable redaction (capture/export/sync) |
| `--insecure-raw` | Store raw PTY blobs |

---

## Escape hatches

| Goal | Action |
|---|---|
| No ambient this shell | `export BLACKBOX_OFF=1` |
| Uninstall wrappers | `blackbox enable --uninstall-shell` |
| Force store path | `--store` / `BLACKBOX_DB` |
| External crypto key | `BLACKBOX_STORE_KEY_FILE=~/.config/blackbox/default.key` |

---

## TUI keys (show --tui)

| Key | Action |
|---|---|
| `t` `e` `a` `p` `d` `h` | timeline · failure · anomalies · postmortem · diff · handoff |
| `Enter` / `g` | jump to timeline at evidence/`seq=` |
| `/` | toggle bookkeeping |
| `?` `q` | help · quit |

---

## See also

[getting-started](getting-started.md) · [recipes](recipes.md) · [adapters](adapters.md) · [doctor-and-capture](doctor-and-capture.md) · [examples](examples.md) · [glossary](glossary.md) · [troubleshooting](troubleshooting.md)

## 1.6 integrity & verification

```bash
blackbox fsck --deep --json
blackbox verify latest -- cargo test
blackbox experiment init my-exp
blackbox run --eval --experiment my-exp --task t1 --variant v1 --attempt 1 -- cargo test
blackbox report --experiment my-exp --json
blackbox gate --experiment my-exp --min-attempts 3 --min-verified-rate 0.8
blackbox capsule create latest -o fail.bbx.json
blackbox cassette proxy --record c.bbx.json -- my-mcp-server
blackbox budget --max-wall 30 --max-processes 64 --json
blackbox projects scan .
```
