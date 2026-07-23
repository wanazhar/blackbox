# Canonical JSON rules

Normative rules for hashing, commitments, and dual-encoder identity.

## Algorithm

- **Hash:** SHA-256 over the canonical UTF-8 byte sequence.
- **Hex encoding:** lowercase hex, 64 characters.

## Serialization rules

1. **UTF-8** only.
2. **Object keys** sorted lexicographically by Unicode code point order
   (byte-wise comparison of UTF-8 is correct for this).
3. **No insignificant whitespace** — compact JSON, no space after `:` or `,`.
4. **Numbers** must be finite. Integers that fit in signed/unsigned 64-bit are
   emitted without a fractional part.
5. **Strings** use standard JSON escapes for `"`, `\`, and control characters
   (`\b \f \n \r \t` and `\u00XX` for other controls). Non-ASCII Unicode is
   emitted as UTF-8, not `\u` escaped.
6. **Arrays** preserve element order.
7. **`null` / `true` / `false`** use JSON literals.
8. **Unknown fields** present on the object are included (they affect hashes).
9. **Transport metadata** (peer address, connection id, spool path, HTTP
   headers) must not appear on hashed protocol objects.
10. **Timestamps** for reference encoders: RFC 3339 UTC with `Z`. Fractional
    seconds only when non-zero.

## Dual-encoder identity

Two independent encoders given the same logical object (same fields, same
array order, same string/number values) MUST produce identical canonical bytes
and therefore identical SHA-256 digests.

## Explicitly out of scope for the hash

- Map insertion order differences (normalized by key sort)
- Whitespace differences
- Key order in JSON object literals

## Failures

The following MUST be rejected before hashing:

- Invalid UTF-8
- Non-finite numbers (`NaN`, `Infinity`)
- Duplicate keys at the same object level (JSON parsers that silently keep one
  value are unsafe for commitments; the reference strict parser rejects them
  at every nesting depth)

## Test vectors

See [`../test-vectors/canonical/`](../test-vectors/canonical/).
