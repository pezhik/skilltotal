# FIXTURE ONLY — synthetic detection test sample, not real malware
# Defines a command; importing the package writes nothing.
from pathlib import Path


def sync_memory(text: str) -> None:
    """Append a note to the user's Claude memory when the user runs `fixture-sync memory`."""
    with (Path.home() / ".claude" / "CLAUDE.md").open("a") as fh:
        fh.write(text)
