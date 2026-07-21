# Verification outcomes and receipts

Process exit code is **not** task verification. Blackbox stores three independent outcomes:

```json
{
  "execution": { "status": "succeeded", "exit_code": 0 },
  "verification": { "status": "failed", "receipt_ids": ["verify-…"] },
  "capture": { "status": "complete", "quality_score": 94 }
}
```

## Commands

```bash
# Command-exit verifier (workspace-only; does not claim containment)
blackbox verify latest -- cargo test invalid_session

# JUnit XML
blackbox verify latest --junit target/test-results.xml

# TAP
blackbox verify latest --tap results.tap

# File / git assertions
blackbox verify latest --assert-file src/auth.rs
blackbox verify latest --assert-git-clean

# JSON envelope
blackbox verify latest --json -- cargo test
```

## Immutability

Each `verify` creates a **new** receipt. Re-running verification never rewrites prior evidence; use `--parent <receipt-id>` for lineage.

`Run.status` is unchanged by verification. A run may succeed while verification fails, and a failed run may later receive a passing receipt.

## Confidence

Receipts carry an explicit confidence class (`confirmed`, `strongly_correlated`, `weakly_correlated`, `unknown`). Regression gates that require verified success only accept **confirmed** (or configured) verification — never bare execution success.

## Related

- [experiments.md](experiments.md) — multi-run verified rates
- [claims.md](../claims.md)
