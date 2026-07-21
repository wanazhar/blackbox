# Verification outcomes and receipts

Process **exit code is not task verification**. Blackbox stores three independent
outcomes on a run:

```json
{
  "execution": { "status": "succeeded", "exit_code": 0 },
  "verification": { "status": "failed", "receipt_ids": ["verify-…"] },
  "capture": { "status": "complete", "quality_score": 94 }
}
```

`Run.status` is **execution only**. Verification never rewrites it.

## Commands

```bash
# Command-exit verifier (workspace cwd; does not claim OS containment)
blackbox verify latest -- cargo test invalid_session

# JUnit XML / TAP
blackbox verify latest --junit target/test-results.xml
blackbox verify latest --tap results.tap

# File / git assertions
blackbox verify latest --assert-file src/auth.rs
blackbox verify latest --assert-git-clean

# Scope label (used for domain matching)
blackbox verify latest --scope invalid_session -- cargo test invalid_session

# Lineage on re-verify
blackbox verify latest --parent verify-… -- cargo test

# JSON envelope: receipt + outcome
blackbox verify latest --json -- cargo test
```

## Immutability

Each `verify` inserts a **new** receipt. Prior receipts stay on disk. Use
`--parent <receipt-id>` when re-running a related check.

A run may succeed while verification fails; a failed run may later get a
passing receipt.

## Confidence and domain match

Receipts carry a confidence class:

| Class | Meaning |
|---|---|
| `confirmed` | Domain match ties the receipt to the failure/scope |
| `strongly_correlated` | Partial match |
| `weakly_correlated` | Loose match |
| `unknown` | No useful domain signal |

`verify` scores the new receipt against recent error events (scope text,
failure fingerprint). Regression **gates** that require verified success count
**domain-confirmed** passes by default — not bare execution success, and not a
passing receipt for an unrelated suite.

## Related

- [experiments.md](experiments.md) — multi-run verified / confirmed rates
- [claims.md](../claims.md)
- [CLI `verify`](../reference/cli.md#37-verify)
