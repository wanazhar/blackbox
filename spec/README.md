# Blackbox Evidence Protocol (1.9)

Implementation-neutral specification for Blackbox-compatible evidence.

| Resource | Path |
|---|---|
| Canonical rules | [canonical.md](canonical.md) |
| Compatibility policy | [compatibility.md](compatibility.md) |
| Schema documents | [schemas/](schemas/) |
| Test vectors | [../test-vectors/](../test-vectors/) |
| Product plan | [../docs/plan/evidence-protocol-1.9.md](../docs/plan/evidence-protocol-1.9.md) |
| Epic | [issue #7](https://github.com/wanazhar/blackbox/issues/7) |

## Protocol version

**1.9.0** (`blackbox` protocol family). Schema ids use `blackbox.<domain>/vN`.

## Design rules

1. Schemas are independent of any single language's struct serialization.
2. Canonical form is defined here and exercised by `/test-vectors`.
3. Unknown provisional fields survive permitted round-trips; they never silently
   upgrade integrity.
4. Hash inputs never include mutable transport metadata.
5. Commitments prove record consistency after commitment — not completeness or
   truth of observation.

## Packaging

The reference implementation ships as the single published package
`blackbox-recorder`. This `/spec` tree is the normative wire contract for
native integrations.
