# Docs golden fixtures

Machine-checked contracts for operator documentation.

| Asset | Locked by |
|---|---|
| CLI envelope keys (`blackbox.cli/v1`) | `tests/docs_cli_envelope.rs` |
| Postmortem JSON fields | `tests/docs_first_run.rs` + `docs_cli_envelope.rs` |
| `summary.txt` artifact lines | both |
| Capture quality weights | `docs_first_run.rs` |
| Adapter detection table | `docs_first_run.rs` |

JSON files here are **shape samples** (stable keys), not live store dumps.

```bash
cargo test --test docs_first_run --test docs_cli_envelope
python3 scripts/check_doc_links.py
```
