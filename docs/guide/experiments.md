# Experiments, reports, and regression gates

Typed experiment metadata links runs into eval cohorts. Prefer this over
tag-only conventions when you need rates and gates.

## Init and link

```bash
blackbox experiment init login-fix
# or create on first linked run:
blackbox run --eval \
  --experiment login-fix \
  --task invalid-session \
  --variant glm-5.2 \
  --attempt 3 \
  --role candidate \
  --model glm-5.2 \
  -- claude -p "Fix the invalid session bug"

blackbox experiment show login-fix
blackbox experiment validate login-fix
blackbox experiment list
```

Link an existing run:

```bash
blackbox experiment link login-fix <run-id> \
  --task invalid-session --variant baseline --role baseline
```

### Attempt numbering and config fingerprint

- If `--attempt` is omitted, blackbox assigns the next attempt for the same
  experiment + task + variant cohort (1-based).
- Each link stamps a **config fingerprint** over variant/task/role/model/
  provider/harness/seed/dataset (stable across attempts of the same setup).

Metadata survives **portable export/import** (`experiment_meta`, `experiment`,
`verification_receipts` on v2 archives).

## Reports

```bash
blackbox report --experiment login-fix
blackbox report --experiment login-fix --group-by variant --json
```

Reports always disclose:

- sample size per group
- verified vs unverified counts
- **domain_confirmed** counts (Passed + Confirmed confidence)
- excluded / incomplete capture when known
- median / p95 duration when present
- `insufficient_evidence` when samples are too small

**Never** treat execution success as verified success.

## Gates (CI)

```bash
blackbox gate --experiment login-fix \
  --baseline baseline \
  --candidate feature \
  --min-attempts 3 \
  --min-verified-rate 0.80 \
  --max-p95-duration-regression 20% \
  --require-capture-complete
```

Exit code is non-zero when any declared rule fails. When a verified rate is
required, the gate prefers **domain-confirmed** rate (fail closed on missing
evidence).

## Related

- [verification.md](verification.md)
- [cheatsheet.md](cheatsheet.md)
