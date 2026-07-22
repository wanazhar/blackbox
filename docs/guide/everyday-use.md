# Everyday use

How to list and inspect runs, navigate timelines, use the TUI and dashboard, search, and produce machine-readable output.

Assumes you already [installed](install.md) and [recorded at least one run](getting-started.md).

---

## Identify a run

```bash
blackbox runs                  # recent runs
blackbox runs --json           # blackbox.cli/v1 envelope
```

Most commands accept:

- full run UUID
- **unique prefix** (often the 8-char short id printed at end of run)
- `latest`

```bash
blackbox show latest
blackbox show a1b2c3d4
```

---

## Show and timeline

```bash
blackbox show <run>
blackbox show <run> --transcript    # reconstructed terminal
blackbox show <run> --tools         # tool-call oriented transcript
blackbox show <run> --tui           # interactive TUI for that run

blackbox timeline <run>
blackbox timeline <run> --semantic  # hide bookkeeping (default on for many UIs)
blackbox timeline <run> --kind tool.call
```

**Semantic vs bookkeeping:** bookkeeping kinds include observer start/stop and similar noise (`pty.started`, `filesystem.observer.stopped`, …). Semantic views filter those so tool and terminal structure stay readable.

Inspect a single event:

```bash
blackbox inspect <event-id>
```

---

## TUI

```bash
blackbox tui
# or
blackbox show <run> --tui
```

Useful modes (see on-screen `?` help):

| Key | Mode |
|---|---|
| `t` | Timeline |
| `e` | Failure story (headline, evidence, anomalies, errors) |
| `a` | Anomalies only |
| `p` | Postmortem summary |
| `d` | Diff vs previous run (trajectory / LCP) |
| `h` | Handoff hints |
| `Enter` / `g` | Jump to timeline at selected evidence / event / `seq=N` |
| `/` | Toggle bookkeeping filter |
| `q` | Quit |

Jump behavior: lines that carry an `event_id` select that event on the timeline; lines that only mention `seq=42` resolve by sequence.

---

## Local dashboard

```bash
blackbox serve
# default http://127.0.0.1:7788
```

| Surface | Role |
|---|---|
| `/` | Run list + live SSE updates; anomaly badges for finished runs |
| `/runs/{id}` | Static detail: tools, terminal, timeline, anomaly chips |
| `/runs/{id}/live` | Live event stream + anomaly refresh |
| `/api/runs/{id}/anomalies` | JSON anomaly markers |
| `/api/status`, `/api/handoff` | Project status / handoff |

**Auth:** by default `serve` auto-generates a one-shot token and prints it (fail-closed). Pin with `--token` / `BLACKBOX_SERVE_TOKEN`. `--allow-anonymous` is a danger flag for loopback/unix only. Query `?token=` is not used for API auth; prefer `Authorization: Bearer …` (dashboard can migrate a one-shot `?token=` into `sessionStorage`).

---

## Search

```bash
blackbox search "error"
blackbox search "tool_name:Bash" --json
```

Backed by FTS5 over indexed event text (reindex via serve `--reindex` or store maintenance paths when needed).

---

## Analysis and comparison

```bash
blackbox analyze <run>           # error / side-effect / correlation passes
blackbox postmortem <run>        # structured summary + anomalies
blackbox postmortem latest --json
blackbox diff <run-a> <run-b>    # trajectory / divergence explanation
blackbox summary <run>           # alias-style summary surfaces (see CLI ref)
```

Postmortem fields of interest: `headline`, `next_action`, `evidence` (event-linked), `anomalies` (tool loops, destructive side effects, error storms, token spikes, long silence, process fan-out). Job guide: [debug-a-failure.md](debug-a-failure.md).

---

## Project status and memory

```bash
blackbox status
blackbox status --json
blackbox handoff --json          # status + memory + resume context when attention warrants
blackbox memory show
blackbox memory show --json
blackbox memory set --goal "…" --open "…"
blackbox resolve                 # clear unresolved failure attention
blackbox resolve --clear-wip     # also clear open items / goal
```

Claims (multi-agent coordination):

```bash
blackbox claim acquire --holder "my-agent"
blackbox claim status
blackbox claim release
```

---

## JSON everywhere

Global `--json` wraps stdout in the `blackbox.cli/v1` envelope (`ok`, `command`, `data`, …). Schemas: [JSON API reference](../reference/json-api.md).

```bash
blackbox runs --json | jq '.data'
```

---

## Maintenance you will actually run

```bash
blackbox doctor
blackbox stats
blackbox scrub          # re-redact historical events
blackbox scrub --gc     # + blob GC
blackbox gc             # GC entry points per CLI
blackbox purge … / blackbox rm …   # deletion policy — see CLI ref
```

Retention and size warnings: [overhead.md](overhead.md), [configuration.md](configuration.md).

---

## See also

- Full flag list: [CLI reference](../reference/cli.md)
- Ambient capture: [leave-it-on.md](leave-it-on.md)
- Export/share: [export-and-sync.md](export-and-sync.md)
