"""Print the CHANGELOG section for one version as the body of its GitHub Release.

    python scripts/release_notes.py 0.63.0 > notes.md

CHANGELOG.md is wrapped at 100 columns, and a GitHub Release body renders every newline as a line
break, so the wrapped text showed up ragged (53 breaks inside sentences on the 0.62.0 page). Each
paragraph and list item is joined onto one line; headings, blank lines, list items, table rows and
fenced code keep their own lines. Only whitespace changes.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"

# A line that starts a new block instead of continuing the paragraph or list item above it.
_BLOCK_START = re.compile(r"\s*(?:[-*+]\s|\d+[.)]\s|#{1,6}\s|\||>)")


def section(text: str, version: str) -> list[str]:
    """The lines under `## [version]`, up to the next version heading; [] if there is none."""
    lines = text.splitlines()
    heading = f"## [{version}]"
    if heading not in lines:
        return []
    start = lines.index(heading) + 1
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("## [")), len(lines))
    return lines[start:end]


def unwrap(lines: list[str]) -> list[str]:
    out: list[str] = []
    continues = False  # the last line out is a paragraph or list item the next line may continue
    fenced = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            fenced = not fenced
            out.append(line.rstrip())
            continues = False
        elif fenced:
            out.append(line.rstrip())
        elif not stripped:
            out.append("")
            continues = False
        elif continues and not _BLOCK_START.match(line):
            out[-1] += " " + stripped
        else:
            out.append(line.rstrip())
            continues = not stripped.startswith(("#", "|"))
    return out


def notes(text: str, version: str) -> str:
    return "\n".join(unwrap(section(text, version))).strip() + "\n"


def footer(version: str) -> str:
    """How to get exactly this version, and where its rule changes are described."""
    fence = "`" * 3
    return (
        "\n### Install\n\n"
        f"{fence}\n"
        f"pipx install skilltotal=={version}\n"
        f"npx -y --package=skilltotal@{version} -- skilltotal scan <source>\n"
        f"{fence}\n\n"
        f"GitHub Action: `uses: pezhik/skilltotal@v{version}`. Rule changes are described in "
        f"[RULES_CHANGELOG.md](https://github.com/pezhik/skilltotal/blob/v{version}/RULES_CHANGELOG.md).\n"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: release_notes.py <version>", file=sys.stderr)
        return 2
    body = notes(CHANGELOG.read_text(encoding="utf-8"), argv[1])
    if not body.strip():
        print(f"CHANGELOG.md has no section [{argv[1]}]", file=sys.stderr)
        return 1
    body += footer(argv[1])
    sys.stdout.buffer.write(body.encode("utf-8"))  # the notes file is UTF-8 on any platform
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
