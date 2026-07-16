#!/usr/bin/env python3
"""Check relative markdown links under docs/ (and top-level README/AGENTS).

Exit 0 if all local targets exist. External http(s) links are skipped.
Fragments (#anchors) are not validated against headings (GitHub slug rules vary).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Markdown inline links + optional angle-bracket autolinks we ignore for http
LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")

SKIP_PREFIXES = (
    "http://",
    "https://",
    "mailto:",
    "irc:",
    "ftp://",
    "#",  # same-doc fragment only
)


def iter_md_files() -> list[Path]:
    files: list[Path] = []
    for name in ("README.md", "AGENTS.md", "CHANGELOG.md"):
        p = ROOT / name
        if p.is_file():
            files.append(p)
    docs = ROOT / "docs"
    if docs.is_dir():
        files.extend(sorted(docs.rglob("*.md")))
    return files


def normalize_href(href: str) -> str | None:
    href = href.strip()
    if not href:
        return None
    # title after space: (path "title")
    if href.startswith("<") and href.endswith(">"):
        href = href[1:-1]
    href = href.split()[0]
    if href.startswith(SKIP_PREFIXES):
        return None
    # pure fragment on another file handled below
    return href


def main() -> int:
    missing: list[str] = []
    checked = 0
    for md in iter_md_files():
        text = md.read_text(encoding="utf-8", errors="replace")
        for m in LINK_RE.finditer(text):
            raw = normalize_href(m.group(1))
            if raw is None:
                continue
            path_part = raw.split("#", 1)[0]
            if not path_part:
                # same-file #anchor only
                continue
            # Windows-ish or absolute fs paths: treat as relative to repo if under docs
            target = (md.parent / path_part).resolve()
            checked += 1
            try:
                target.relative_to(ROOT.resolve())
            except ValueError:
                # link escapes repo — still require existence
                pass
            if not target.exists():
                rel_md = md.relative_to(ROOT)
                missing.append(f"{rel_md}: {raw}  (resolved {target})")

    print(f"checked {checked} relative links in {len(iter_md_files())} markdown files")
    if missing:
        print(f"MISSING ({len(missing)}):")
        for line in missing:
            print(f"  {line}")
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
