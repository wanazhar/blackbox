# Compatibility and stability policy (1.9)

## Surface classes

| Class | Meaning |
|---|---|
| **stable** | Semantic breaks require a new `/vN` schema id or major package version |
| **provisional** | May change in a minor release with documented migration |
| **experimental** | No compatibility promise; may be removed |
| **internal** | Not a public protocol surface |

Inventory is embedded in the reference implementation as
`blackbox::protocol::stability::SURFACE_INVENTORY` and mirrored in
[schemas/catalog.json](schemas/catalog.json).

## Schema support lifetime

- Stable `/v1` schemas introduced at or before 1.8 remain readable for at least
  one major version after a `/v2` successor appears.
- Provisional 1.9 schemas (`security.decision`, `commitment.run`,
  `reconcile.outcome`, `native.ingest`, `conformance.report`) may revise fields
  in 1.9.x; field removals require a minor version note in CHANGELOG.
- Experimental (`otlp.loss`) may change freely.

## Unknown fields

- Consumers MUST ignore unknown fields they do not understand (forward
  compatible) unless a schema is marked fail-closed for a specific path.
- Producers SHOULD NOT use unknown fields to assert integrity upgrades.
- Canonical hashes include unknown fields that are present.
- Unknown schema ids or unsupported `/vN` versions fail predictably. Unknown
  fields are forward-compatible; unknown semantics are not interpreted as v1.

## Portable archives

- `blackbox.portable/v2` remains the preferred export format.
- Import MUST reject archives that fail hash/blob validation (see 1.5 A1).
- Nested redaction defaults remain on unless `--no-redact`.

## CLI compatibility

- Existing subcommands retain their flags unless CHANGELOG marks a break.
- New 1.9 commands (`conform`, native ingest helpers) are additive.
- `--json` envelopes continue to use `blackbox.cli/v1`.

## Deprecation

1. Announce in CHANGELOG under **Deprecated**.
2. Keep behavior for at least one minor release when the surface was stable.
3. Remove only with a major version or explicit migration tool.

## Integrity honesty

Run commitments prove **record consistency after commitment**. They do not
prove that observation was complete, that external systems told the truth, or
that denied actions could not occur outside the recorder's view.
