# Recipes

Copy-paste workflows for common jobs. Each recipe states **when**, **commands**, **what success looks like**, and **where to go deeper**.

Assumes [install](install.md) works (`blackbox --version`). Terms: [glossary](glossary.md). Dense command list: [cheatsheet](cheatsheet.md).

---

## 1. New project, record once, inspect

**When:** First time in a repo; you want proof capture works before ambient wrappers.

```bash
cd ~/my-project
blackbox setup
# or step-by-step:
blackbox enable
blackbox run -- echo "hello blackbox"
blackbox runs
blackbox show latest
blackbox timeline latest --semantic
```

**Success:** `runs` shows one succeeded row; `show`/`timeline` list events; short id is usable as a prefix.

**Deeper:** [getting-started](getting-started.md) · `cargo test --test setup_fail --test docs_first_run`

---

## 2. Leave agent CLIs instrumented (ambient)

**When:** You run `claude` / `codex` / … often and want automatic recording without typing `blackbox run`.

```bash
cd ~/my-project
blackbox enable --memory-bus --install-shell
# restart shell or: source ~/.bashrc   # or zshrc
claude -p "list open TODOs"    # example harness
blackbox runs
blackbox show latest --tools
```

**Success:** New run appears tagged ambient/`auto`; harness still works if `blackbox` missing from PATH (passthrough).

**Opt out one shell:** `export BLACKBOX_OFF=1`  
**Deeper:** [leave-it-on](leave-it-on.md) · [adapters](adapters.md) · [ambient-contract](../ambient-contract.md)

---

## 3. Debug a failed agent run

**When:** Exit non-zero, sticky attention, or “it did something weird.”

```bash
blackbox fail
blackbox fail --json | jq '{focus: .data.focus, headline: .data.summary.headline, next: .data.summary.next_action, anomalies: .data.summary.anomalies}'
blackbox timeline <short-id> --semantic
blackbox show <short-id> --tui    # e = failure story; Enter/g jumps to seq
```

**Success:** You can name a next action and at least one evidence `seq` or event id.

**Deeper:** [debug-a-failure](debug-a-failure.md)

---

## 4. CI job with artifacts

**When:** Pipeline must fail on child failure and drop machine-readable traces.

```bash
blackbox run --ci --artifact-dir ./bb-out --tag ci -- npm test
# exit code == child exit code
ls ./bb-out
# run.json postmortem.json anomalies.json summary.txt score.json [portable…]
jq -e '.failed == false' ./bb-out/score.json
```

**Success:** Non-zero test → non-zero process exit; `score.json` is `blackbox.score/v1`.

**Deeper:** [score schema](../reference/score.md) · [CLI run](../reference/cli.md#2-run)

---

## 5. Eval / benchmark without launch mutation

**When:** Scoring harnesses or models; continuity inject would bias the run.

```bash
blackbox run --eval --artifact-dir ./eval-out -- \
  your-agent --prompt "solve the task"
# or GitHub Actions: uses: ./.github/actions/blackbox-eval
```

**Success:** Tags include `eval` and `ci`; observe-only (no MEMORY inject); `score.json` + anomalies.

**Deeper:** [score.md](../reference/score.md) · CLI `--eval`

---

## 6. Agent session start (human or LLM)

**When:** Opening a project that already has `.blackbox/`.

```bash
blackbox handoff --json | jq .
# or MCP: blackbox_handoff
blackbox claim status
# if free and multi-agent:
blackbox claim acquire --holder "$USER"
```

**Read:** `attention.level`, `project_memory.headline` / `next_action`, active claim.

**After fixing a sticky failure:**

```bash
blackbox resolve
# or clear goal/open items too:
blackbox resolve --clear-wip
blackbox claim release
```

**Deeper:** [skills/blackbox](../skills/blackbox.md) · [MCP](../reference/mcp.md)

---

## 7. Compare “worked yesterday” vs today

```bash
blackbox runs --limit 10
blackbox diff <good-id> <bad-id> --trajectory
```

**Success:** Shared prefix length, first divergence seq, exclusive steps, file hints.

**Deeper:** [everyday-use](everyday-use.md) · CLI `diff`

---

## 8. Local dashboard while a long run is live

```bash
# terminal A
blackbox serve --token "$(openssl rand -hex 16)"
# note the token; open http://127.0.0.1:7788

# terminal B
blackbox run --name long -- your-long-job
```

**Success:** Run list SSE updates; live page streams events; anomaly badges after completion.

**Deeper:** [everyday-use](everyday-use.md) · [security serve](security.md#7-serve-dashboard)

---

## 9. Share a redacted failure with a colleague

```bash
blackbox export latest --format html -o failure.html
# or re-importable:
blackbox export latest --format portable -o failure.json
# sealed:
blackbox export latest --format portable --passphrase '…' -o failure.bbx.json
```

Recipient:

```bash
blackbox import failure.json
# sealed:
blackbox import failure.bbx.json --passphrase '…'
blackbox postmortem latest
```

**Deeper:** [export-and-sync](export-and-sync.md)

---

## 10. Offline vault (laptop / cold storage)

```bash
# optional at-rest blobs first
# config: capture.encrypt_blobs = true
# key outside project: export BLACKBOX_STORE_KEY_FILE=~/.config/blackbox/default.key

blackbox backup -o ~/vaults/proj.bbx.json --passphrase '…' --include-db
# restore later:
blackbox restore ~/vaults/proj.bbx.json --passphrase '…'
```

**Success:** Archive opens only with passphrase; `store.key` is **not** inside the archive.

**Deeper:** [security](security.md#5-at-rest-encryption-and-offline-vault)

---

## 11. Re-redact history after scanner improvements

```bash
blackbox scrub --gc
blackbox doctor
```

**Success:** Old secret-shaped strings no longer readable in events/blobs; orphan blob keys pruned.

---

## 12. Cap disk growth

```toml
# .blackbox/config.toml
[retention]
auto_apply = true
keep_runs = 50
```

```bash
blackbox stats
blackbox gc --dry-run
blackbox gc
# or:
blackbox purge --keep 50 --dry-run
blackbox purge --keep 50
```

**Deeper:** [overhead](overhead.md) · [configuration](configuration.md)

---

## 13. Path-scoped multi-agent work

```bash
# agent A
blackbox claim acquire --holder agent-a --path src/auth
# agent B (non-overlapping)
blackbox claim acquire --holder agent-b --path src/ui
blackbox claim status
# done
blackbox claim release --holder agent-a
```

**Success:** Overlapping paths or project-vs-path conflicts fail closed.

**Deeper:** [CLI claim](../reference/cli.md#7-claim) · continuity plane

---

## 14. Gate explicit runs until human acks

```toml
# .blackbox/config.toml
[capture]
gate_mode = "require_ack"
```

```bash
blackbox ack
# or:
BLACKBOX_ACK=1 blackbox run -- claude -p "…"
```

Ambient wrappers are **not** hard-blocked by gate (by design).

---

## 15. Something is broken — minimal repro

```bash
blackbox doctor --json
BLACKBOX_OFF=1 true          # sanity shell
blackbox run --observe-only -- true
blackbox show latest
blackbox timeline latest
```

If this fails, capture is broken (see [troubleshooting](troubleshooting.md) and [doctor-and-capture](doctor-and-capture.md)). If it works but your harness does not, check wrap list / [adapters](adapters.md) / ambient decision order.

## 16. Read handoff like an agent

```bash
blackbox handoff --json | jq -r '.data.attention.level'
blackbox handoff --json | jq -r '.data.project_memory.headline, .data.project_memory.next_action'
```

**Deeper:** [examples](examples.md) (annotated JSON) · [skills/blackbox](../skills/blackbox.md)

---

## Recipe → guide map

| Recipe family | Primary guide |
|---|---|
| Install / first run | [getting-started](getting-started.md) |
| Daily inspect | [everyday-use](everyday-use.md) |
| Failures | [debug-a-failure](debug-a-failure.md) |
| Ambient | [leave-it-on](leave-it-on.md) |
| Config / knobs | [configuration](configuration.md) |
| Secrets / vault | [security](security.md) |
| Share | [export-and-sync](export-and-sync.md) |
| Agents | [skills/blackbox](../skills/blackbox.md) |
