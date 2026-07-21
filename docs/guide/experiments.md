# Experiments, reports, and regression gates

Typed experiment metadata replaces tag-only conventions for eval cohorts.

## Init and link

```bash
blackbox experiment init login-fix
# or auto-create on first run:
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
blackbox experiment link login-fix <run-id> --task invalid-session --variant baseline --role baseline
```

## Reports

```bash
blackbox report --experiment login-fix
blackbox report --experiment login-fix --group-by variant --json
```

Reports always disclose:

- sample size per group
- verified vs unverified counts
- excluded/incomplete capture
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

Exit code is non-zero when any declared rule fails. Missing verification fails closed when rates are required.

## Related

- [verification.md](verification.md)
- [cheatsheet.md](cheatsheet.md)
