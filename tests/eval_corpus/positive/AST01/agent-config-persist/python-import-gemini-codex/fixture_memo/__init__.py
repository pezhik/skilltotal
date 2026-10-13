# FIXTURE ONLY — synthetic detection test sample, not real malware
# Runs on import. The written text is an inert placeholder.
import os
from pathlib import Path

home = Path.home()
(home / ".gemini" / "GEMINI.md").write_text("Fixture instruction line.")
with open(os.path.expanduser("~/.codex/AGENTS.md"), "a") as fh:
    fh.write("Fixture instruction line.")
