#!/usr/bin/env python3
"""Check relative markdown links and GitHub-style heading anchors.

Validates:
  - Relative link targets exist under the repo (docs/, README, AGENTS, CHANGELOG)
  - `#fragment` targets match a heading slug in the destination file

External http(s)/mailto links are skipped. Exit non-zero on any failure.
"""

from __future__ import annotations

import re
import sys
import unicodedata
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.MULTILINE)
# Strip markdown code/HTML; keep snake_case underscores (never strip single `_`).
BACKTICK_RE = re.compile(r"`+")
# Only paired **bold** / __bold__ — single * / _ would corrupt tool names.
BOLD_RE = re.compile(r"(\*\*|__)(.*?)\1")
HTML_TAG_RE = re.compile(r"<[^>]+>")

SKIP_SCHEMES = (
    "http://",
    "https://",
    "mailto:",
    "irc:",
    "ftp://",
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


def github_slug(text: str) -> str:
    """Approximate GitHub Flavored Markdown heading anchors.

    Matches common github-slugger behavior well enough for our docs:
    lowercase, strip most punctuation, spaces → hyphens, collapse hyphens.
    """
    text = HTML_TAG_RE.sub("", text)
    for _ in range(3):
        text = BOLD_RE.sub(r"\2", text)
    text = BACKTICK_RE.sub("", text)
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = text.lower().strip()
    out: list[str] = []
    for ch in text:
        if ch.isalnum():
            out.append(ch)
        elif ch in (" ", "-", "_"):
            out.append("-" if ch == " " else ch)
        # drop other punctuation
    slug = "".join(out)
    slug = re.sub(r"-{2,}", "-", slug)
    slug = slug.strip("-")
    return slug


def heading_slugs(md_text: str) -> set[str]:
    """All unique heading slugs, with GitHub-style duplicate suffixes (-1, -2, …)."""
    counts: dict[str, int] = defaultdict(int)
    slugs: set[str] = set()
    for m in HEADING_RE.finditer(md_text):
        base = github_slug(m.group(2))
        if not base:
            continue
        n = counts[base]
        counts[base] = n + 1
        slug = base if n == 0 else f"{base}-{n}"
        slugs.add(slug)
    return slugs


def normalize_href(href: str) -> str | None:
    href = href.strip()
    if not href:
        return None
    if href.startswith("<") and href.endswith(">"):
        href = href[1:-1]
    href = href.split()[0]
    if href.startswith(SKIP_SCHEMES):
        return None
    return href


def main() -> int:
    md_files = iter_md_files()
    # Precompute slugs per resolved path
    slug_cache: dict[Path, set[str]] = {}
    text_cache: dict[Path, str] = {}
    for md in md_files:
        text = md.read_text(encoding="utf-8", errors="replace")
        resolved = md.resolve()
        text_cache[resolved] = text
        slug_cache[resolved] = heading_slugs(text)

    missing_files: list[str] = []
    missing_anchors: list[str] = []
    checked_files = 0
    checked_anchors = 0

    for md in md_files:
        text = text_cache[md.resolve()]
        for m in LINK_RE.finditer(text):
            raw = normalize_href(m.group(1))
            if raw is None:
                continue

            if "#" in raw:
                path_part, frag = raw.split("#", 1)
            else:
                path_part, frag = raw, ""

            if path_part:
                target = (md.parent / path_part).resolve()
                checked_files += 1
                if not target.exists():
                    missing_files.append(
                        f"{md.relative_to(ROOT)}: {raw}  (missing file {target})"
                    )
                    continue
            else:
                # same-document fragment
                target = md.resolve()

            if frag:
                checked_anchors += 1
                # Allow empty fragment? skip
                if not frag:
                    continue
                # Load slugs for target (may be outside pre-scanned set)
                if target not in slug_cache:
                    if target.is_file() and target.suffix.lower() == ".md":
                        t = target.read_text(encoding="utf-8", errors="replace")
                        slug_cache[target] = heading_slugs(t)
                    else:
                        # Non-md target with fragment — ignore anchor check
                        continue
                if frag not in slug_cache[target]:
                    # Suggest close matches
                    near = sorted(
                        s for s in slug_cache[target] if s.startswith(frag[:8])
                    )[:5]
                    hint = f" (nearby: {', '.join(near)})" if near else ""
                    # Also try without numeric prefix quirks
                    missing_anchors.append(
                        f"{md.relative_to(ROOT)}: #{frag} in {target.relative_to(ROOT) if str(target).startswith(str(ROOT)) else target}{hint}"
                    )

    n_files = len(md_files)
    print(
        f"checked {checked_files} file links + {checked_anchors} anchors "
        f"in {n_files} markdown files"
    )
    bad = False
    if missing_files:
        bad = True
        print(f"MISSING FILES ({len(missing_files)}):")
        for line in missing_files:
            print(f"  {line}")
    if missing_anchors:
        bad = True
        print(f"MISSING ANCHORS ({len(missing_anchors)}):")
        for line in missing_anchors:
            print(f"  {line}")
    if bad:
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
