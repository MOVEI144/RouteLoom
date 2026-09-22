"""MkDocs hooks for the RouteLoom documentation site (issue #15).

Two jobs:

* ``on_page_markdown`` rewrites relative links that escape ``docs/`` —
  e.g. ``../protocol/README.md``, ``../../components/...``, ``../../SECURITY.md`` —
  into GitHub ``blob`` URLs. On GitHub those links already resolve; the site
  cannot serve files outside ``docs/``, so pointing at the repo keeps them
  usable instead of turning them into dead relative URLs (and ``mkdocs build
  --strict`` would otherwise report them as unresolved links).
* ``on_page_read_source`` serves ``about.md`` from the repository-root
  ``README.md`` so the site mirrors the project README without copying it:
  ``docs/...`` links are rebased into the site and repo-file links
  (``LICENSE``, ``NOTICE``, ``SECURITY.md``) are rewritten to GitHub URLs.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path

_REPO_URL = "https://github.com/MOVEI144/RouteLoom"
_BLOB_URL = f"{_REPO_URL}/blob/main/"

# Target part of an inline Markdown link or image: ``](target)``.
_MD_LINK_TARGET = re.compile(r"(\]\(\s*)(<[^>]+>|[^\s)]+)")
# Fenced code blocks, so links shown inside code samples stay untouched.
_FENCED_BLOCK = re.compile(r"(^```[^\n]*\n.*?^```\s*$|^~~~[^\n]*\n.*?^~~~\s*$)", re.DOTALL | re.MULTILINE)


def _is_external(url: str) -> bool:
    return url.startswith(("#", "/", "mailto:")) or "://" in url


def _unwrap(raw: str) -> str:
    return raw[1:-1] if raw.startswith("<") else raw


def _rewrap(raw: str, url: str) -> str:
    return f"<{url}>" if raw.startswith("<") else url


def _rewrite_escaping_links(markdown: str, page_dir: str) -> str:
    """Rewrite ``../`` links that resolve outside ``docs/`` to blob URLs."""

    def replace(match: re.Match) -> str:
        prefix, raw = match.group(1), match.group(2)
        url = _unwrap(raw)
        if _is_external(url):
            return match.group(0)
        path, sep, fragment = url.partition("#")
        resolved = posixpath.normpath(posixpath.join(page_dir, path))
        if not (resolved == ".." or resolved.startswith("../")):
            return match.group(0)
        while resolved.startswith("../"):
            resolved = resolved[3:]
        if resolved == "..":  # link to the repository root itself
            new_url = _REPO_URL
        else:
            new_url = _BLOB_URL + resolved
        if sep:
            new_url += sep + fragment
        return prefix + _rewrap(raw, new_url)

    parts = _FENCED_BLOCK.split(markdown)
    for i in range(0, len(parts), 2):
        parts[i] = _MD_LINK_TARGET.sub(replace, parts[i])
    return "".join(parts)


def on_page_markdown(markdown, page, config, files):
    return _rewrite_escaping_links(markdown, posixpath.dirname(page.file.src_uri))


def on_page_read_source(page, config):
    """Serve about.md from the repository-root README.md, links rebased."""
    if page.file.src_uri != "about.md":
        return None
    readme = Path(config["docs_dir"]).parent / "README.md"
    markdown = readme.read_text(encoding="utf-8")

    def replace(match: re.Match) -> str:
        prefix, raw = match.group(1), match.group(2)
        url = _unwrap(raw)
        if _is_external(url):
            return match.group(0)
        path, sep, fragment = url.partition("#")
        if path.startswith("docs/"):  # repo-relative docs link -> site link
            url = path[len("docs/"):] + (sep + fragment if sep else "")
        else:  # repo-root file (LICENSE, NOTICE, SECURITY.md, ...)
            url = _BLOB_URL + path + (sep + fragment if sep else "")
        return prefix + _rewrap(raw, url)

    return _MD_LINK_TARGET.sub(replace, markdown)
