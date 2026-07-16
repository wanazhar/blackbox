#!/usr/bin/env bash
# Copy repo-root docs that live outside docs/ so MkDocs can resolve links.
# Used for optional local `mkdocs serve` only (no GitHub Pages deploy).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cp -f "$ROOT/AGENTS.md" "$ROOT/docs/AGENTS.md"
cp -f "$ROOT/CHANGELOG.md" "$ROOT/docs/CHANGELOG.md"
# Root files use paths like docs/guide/... — rewrite for in-docs_dir rendering.
if [[ "$(uname -s)" == "Darwin" ]]; then
  sed -i '' -e 's|](docs/|](|g' "$ROOT/docs/AGENTS.md" "$ROOT/docs/CHANGELOG.md"
else
  sed -i -e 's|](docs/|](|g' "$ROOT/docs/AGENTS.md" "$ROOT/docs/CHANGELOG.md"
fi
echo "prepared docs/AGENTS.md and docs/CHANGELOG.md for MkDocs"
