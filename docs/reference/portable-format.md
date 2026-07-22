# Portable format reference

Schema for import/export archives (`blackbox.portable/v1|v2`), blob embedding rules, redaction defaults, and how sealed envelopes wrap portable JSON.

Operator workflow: [../guide/export-and-sync.md](../guide/export-and-sync.md). Threat model: [../guide/security.md](../guide/security.md).

---

## Quick answers

| Question | Answer |
|---|---|
| Default redaction? | **On** — pass `--no-redact` only for private forensics |
| Re-importable format? | `--format portable` |
| Current schema? | Prefer **v2** (`blackbox.portable/v2`) |
| Sealed share? | Portable JSON inside `blackbox.export.sealed/v1` envelope |
| Whole store vault? | `backup` / `restore` (different format family) |

---

## 1. Export

```bash
blackbox export <run-id> --format portable -o trace.json
blackbox export <run-id> --format portable -o trace.json --inline-blobs
blackbox export <run-id> --format portable -o trace.json --no-redact   # dangerous
blackbox export <run-id> --format portable --passphrase '…' -o sealed.bbx.json
```

### Logical archive shape (v2 JSON)

The on-wire document uses a numeric `version` field (not a string schema id):

```json
{
  "version": 2,
  "exported_at": "2026-07-12T12:00:00Z",
  "run": { "id": "…", "command": ["…"], "…": "…" },
  "events": [ { "id": "…", "sequence": 1, "kind": "…", "…": "…" } ],
  "blobs": {
    "<sha256_hex>": {
      "encoding": "base64",
      "size": 1234,
      "data": "<base64>"
    }
  },
  "experiment_meta": { "experiment_id": "…", "variant": "…", "attempt": 2 },
  "experiment": { "schema": "blackbox.experiment/v1", "id": "…", "name": "…" },
  "verification_receipts": [ { "schema": "blackbox.verification.receipt/v1", "…": "…" } ],
  "boundary": { "schema": "blackbox.boundary/v1", "policy_hash": "…", "contract": { "…": "…" } },
  "containment_receipts": [ { "schema": "blackbox.containment.receipt/v1", "…": "…" } ],
  "external_evidence": [ { "schema": "blackbox.evidence.event/v1", "…": "…" } ],
  "evidence_edges": [ { "schema": "blackbox.evidence.edge/v1", "…": "…" } ],
  "boundary_findings": [ { "schema": "blackbox.boundary.finding/v1", "…": "…" } ],
  "provenance_records": [ { "schema": "blackbox.provenance/v1", "…": "…" } ],
  "trace_identity": { "schema": "blackbox.trace.identity/v1", "trace_id": "…", "…": "…" }
}
```

`experiment_meta`, `experiment`, and `verification_receipts` are optional and
may be null/empty when the run was not linked or verified. Import restores them
when present (new receipt ids if run ids are remapped).

**1.7 fields** (`boundary`, containment/evidence/findings/provenance/trace_identity)
are optional. Import remaps `run_id` (and regenerates ids when `--new-ids` /
equivalent is used). Absolute/traversal path attributes remain rejected on
evidence re-validation only if re-imported via the evidence importer; portable
JSON restores stored payloads as previously accepted.

### v1 vs v2

| Feature | v1 | v2 |
|---|---|---|
| `version` field | `1` | `2` |
| Blobs | May omit referenced keys | Every referenced blob key must resolve (empty map does **not** waive) |
| Event layout | Looser | Rejects duplicate event ids / sequences |
| Experiment / receipts | Absent | Optional embedded objects |
| Redaction | Default on | Default on |

Import accepts both generations where possible.

### Directory layout (streaming-friendly)

For large runs, prefer a directory archive:

```bash
blackbox export <run-id> --format portable-dir -o ./trace-dir
blackbox import ./trace-dir
```

Library: `export_portable_dir` / `import_portable_dir`.

```text
manifest.json     # format blackbox.portable.dir/v1
run.json
events.jsonl      # one event per line
blobs/<sha256>    # raw bytes; filename must equal content SHA-256
```

Import validates each blob hash before permanent writes (same integrity rules as JSON v2).

---

## 2. Import

```bash
blackbox import trace.json
blackbox import sealed.bbx.json --passphrase '…'
blackbox import trace.json --keep-ids
```

Import reconstructs:

1. Run + events (batch insert; rollback journal on failure)  
2. Blobs under content keys only (declared key must equal SHA-256 of payload)  
3. Optional experiment manifest/meta and verification receipts  
4. Sequence numbers preserved for timeline fidelity  

v2 never renames blob bytes to an unverified caller-supplied key.

---

## 3. Blob handling

| Mode | Behavior |
|---|---|
| Without `--inline-blobs` | Events keep keys; blob bytes may be omitted (lighter file) |
| With `--inline-blobs` | Bytes embedded (base64) under `blobs` |
| On import | Re-store blobs; `move_blob` for key mismatches |

Large traces: prefer sync backends or vault backup over huge single JSON files.

---

## 4. Redaction

- Terminal, env, argv scanned before archive write  
- Structural ids (run UUID, blob SHA, event ids) survive  
- Portable export re-scans blobs (share path must not casually revive raw secrets)  
- `--no-redact` disables protection for that export only  

---

## 5. Sealed envelope

When `--passphrase` or `--encrypt` is used, the portable **plaintext** JSON is encrypted and wrapped:

| Field (conceptual) | Role |
|---|---|
| `format` | `blackbox.export.sealed/v1` |
| `ciphertext_b64` | ChaCha20-Poly1305 payload |
| salt / kdf params | Present for passphrase (PBKDF2) packs |

Open with matching passphrase or store key. Wrong key fails closed.

---

## 6. Related

- [cli.md](cli.md) — export/import/backup flags  
- [stream-protocol.md](stream-protocol.md) — harness NDJSON (not this archive)  
- Recipe: [../guide/recipes.md](../guide/recipes.md#9-share-a-redacted-failure-with-a-colleague)  
