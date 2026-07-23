# Protocol test vectors (1.9)

Machine-readable cases for canonical form, validation, and tamper detection.

| Directory | Purpose |
|---|---|
| `valid/` | Objects that MUST validate |
| `invalid/` | Objects that MUST fail validation |
| `canonical/` | Logical object + expected canonical bytes/hash |
| `migration/` | Cross-version fixtures (placeholder for later vectors) |
| `tampering/` | Mutation cases for commitment verification |
| `signature/` | Signed run-root fixtures |
| `citation/` | Citation completeness fixtures |
| `redaction/` | Redaction transformation fixtures |

## Vector file format

JSON object:

```json
{
  "id": "unique-vector-id",
  "description": "what this proves",
  "expect": "pass" | "fail" | "canonical",
  "input": { },
  "expected_canonical": "{...}",
  "expected_hash": "64-hex",
  "expected_error_path": "/field"
}
```

Reference runner: `blackbox::protocol` unit tests and `tests/protocol_vectors.rs`.
