# Leave it on (ambient capture)

How shell wrappers and `maybe-run` work, when a harness is recorded vs passed through, and how to opt out without uninstalling.

Normative decision table: [ambient-contract.md](../ambient-contract.md). This page is the operator-facing explanation.

---

## Goal

Ambient capture makes blackbox useful without remembering to type `blackbox run` for every agent CLI. Wrappers call `blackbox maybe-run`, which **records** only when policy says so, otherwise **passthrough** (exec the bare command). Passthrough never opens the store.

---

## Enable wrappers

```bash
cd /path/to/project
blackbox enable --install-shell
# with project memory defaults:
blackbox enable --memory-bus --install-shell
```

What you get:

1. Project `.blackbox/` + `config.toml` (`enabled = true`)
2. Managed block in shell rc / PowerShell profile between `# >>> blackbox >>>` and `# <<< blackbox <<<`
3. Functions/aliases for names on the **wrap list** (`capture.wrap` in config)—common harness basenames (claude, codex, aider, …)

Install is idempotent (single managed block). Uninstall removes only that block:

```bash
blackbox enable --uninstall-shell
# or
blackbox disable   # project-level disable; wrappers may still call maybe-run but policy passthroughs
```

---

## Decision order (`maybe-run`)

First match wins:

| # | Condition | Action |
|---|---|---|
| 1 | `BLACKBOX_OFF` set | Passthrough |
| 2 | Nested under an active supervisor | Passthrough (PID marker or legacy `BLACKBOX_ACTIVE_RUN`) |
| 3 | No enabled project via discovery | Passthrough |
| 4 | Basename of argv[0] ∉ wrap list | Passthrough |
| 5 | else | **Record** into discovered project store; register supervisor PID marker |

Wrappers themselves: if `blackbox` is missing from `PATH`, invoke the bare harness—**never hard-fail** the developer’s tool.

**Recorder neutrality (1.4):** ambient recording is hard observe-only. The supervised child does **not** see injected `BLACKBOX_*` variables; nest prevention uses a runtime supervisor PID marker (not a child-visible env var). See [ambient-contract.md](../ambient-contract.md).

---

## Ambient vs explicit `run`

| | Ambient (`maybe-run`) | Explicit `blackbox run` |
|---|---|---|
| Continuity / prompt inject | **No** (observe-only) | Yes, when continuity config allows |
| Gate / require_ack | Does not hard-block ambient | Can warn / require ack |
| Typical tags | includes `auto` | your tags |
| Use | Daily harness launches | CI, eval, deliberate memory inject, debugging capture policy |

This split is intentional: ambient is safe to leave on; explicit run is the control plane for continuity and fleet gates.

---

## Opt out (escape hatches)

```bash
# This shell only
export BLACKBOX_OFF=1

# Single command
BLACKBOX_OFF=1 claude -p "…"

# Stop project capture until re-enabled
blackbox disable

# Remove shell integration
blackbox enable --uninstall-shell
```

Nesting: if you are already inside `blackbox run` / ambient record, nested wrap invocations detect the active supervisor via the process-tree PID marker (or legacy `BLACKBOX_ACTIVE_RUN` if set) and will not open a second recording session.

---

## Configuring the wrap list

`.blackbox/config.toml`:

```toml
[capture]
wrap = ["claude", "codex", "aider", "gemini", "cursor-agent", "opencode", "grok"]
observe_only = true   # ambient paths are observe-only regardless; explicit run has its own flags
```

Only **basenames** matter (`/usr/local/bin/claude` → `claude`). Custom agent binaries need an entry here (and ideally an adapter—see contributor docs).

---

## Trust notes

- Ambient recording still redacts by default; same security model as explicit run.
- Store remains project-local under the discovered project root—not “whatever cwd the shell felt like” without discovery rules. If discovery fails → passthrough.
- Multi-user machines: `.blackbox/` is mode-hardened; other UIDs should not read it by default. Same-UID and disk theft are separate threats ([security.md](security.md)).
- Prefer `blackbox setup --harden` / `enable --harden` when the machine is multi-user or you want encrypt_blobs + external key without hand-editing TOML ([security.md — harden](security.md#hardened-project-profile-harden)).
- Ambient is **quiet by default**. Opt in to a one-line stderr notice after a recorded ambient run with `capture.ambient_notice = true` (never printed on passthrough / `BLACKBOX_OFF`).

---

## Verify ambient is working

```bash
blackbox doctor
# enable project, ensure wrap list, run a wrapped harness, then:
blackbox runs
blackbox show latest
# If a long claude/codex run shows 0 tool.call, doctor may note adapter drought
# → check stream-json / native logs (doctor-and-capture.md)
```

Automated gate: `tests/ambient_contract.rs` (A1).

---

## See also

- [getting-started.md](getting-started.md)
- [adapters.md](adapters.md) — which harnesses wrap / parse
- [configuration.md](configuration.md)
- [ambient-contract.md](../ambient-contract.md)
- [../plan/adoption-1.1.md](../plan/adoption-1.1.md) (historical design for the adoption bar)
