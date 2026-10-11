"""The GitHub Release body is the CHANGELOG section with its wrapped lines joined.

A Release body renders every newline as a line break, so the 100-column CHANGELOG showed up
ragged on the Releases page (53 breaks inside sentences for 0.62.0).
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release_notes.py"
_spec = importlib.util.spec_from_file_location("release_notes", _SCRIPT)
release_notes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release_notes)

_CHANGELOG = """\
# Changelog

## [1.1.0]
Intro paragraph that was wrapped
onto a second line.

### Security
- **First item** that was wrapped
  onto two lines.
  - A nested item, also
    wrapped.
- Second item.

```
  code stays
  as it is
```

| a | b |
|---|---|

## [1.0.0]
- Older entry.
"""


def test_paragraphs_and_list_items_are_joined_onto_one_line():
    assert release_notes.notes(_CHANGELOG, "1.1.0").splitlines() == [
        "Intro paragraph that was wrapped onto a second line.",
        "",
        "### Security",
        "- **First item** that was wrapped onto two lines.",
        "  - A nested item, also wrapped.",
        "- Second item.",
        "",
        "```",
        "  code stays",
        "  as it is",
        "```",
        "",
        "| a | b |",
        "|---|---|",
    ]


def test_a_section_stops_at_the_next_version_and_a_missing_one_is_empty():
    assert release_notes.notes(_CHANGELOG, "1.0.0") == "- Older entry.\n"
    assert release_notes.notes(_CHANGELOG, "9.9.9").strip() == ""


def test_every_real_section_changes_only_whitespace():
    text = (_SCRIPT.parents[1] / "CHANGELOG.md").read_text(encoding="utf-8")
    versions = re.findall(r"^## \[([^\]]+)\]$", text, flags=re.M)
    assert versions
    for version in versions:
        wrapped = "\n".join(release_notes.section(text, version))
        body = release_notes.notes(text, version)
        assert body.split() == wrapped.split(), version
        # Joining is the point: no list item or paragraph keeps a line break mid-sentence.
        assert len(body.splitlines()) <= len(wrapped.strip().splitlines()), version
