"""Fetch the real-world evaluation corpus (third-party repos) into corpus/.

The corpus is git-ignored (we do not vendor third-party code); this script reproduces it.
Requires git on PATH.

Usage:  python tests/manual_eval/fetch_corpus.py
"""

from __future__ import annotations

import subprocess
from pathlib import Path

CORPUS = Path(__file__).parent / "corpus"

# group -> list of (dest-name, git-url)
REPOS = {
    "servers": [("servers", "https://github.com/modelcontextprotocol/servers.git")],
    "servers-archived": [
        ("servers-archived", "https://github.com/modelcontextprotocol/servers-archived.git")
    ],
    "community": [
        ("shell-server-py", "https://github.com/tumf/mcp-shell-server.git"),
        ("shell-server-ts", "https://github.com/mkusaka/mcp-shell-server.git"),
        ("shell-command-mcp", "https://github.com/egoist/shell-command-mcp.git"),
    ],
    "pkgs": [
        ("click", "https://github.com/pallets/click.git"),
        ("express", "https://github.com/expressjs/express.git"),
    ],
}


def main() -> None:
    for group, repos in REPOS.items():
        for name, url in repos:
            dest = CORPUS / group / name
            if dest.exists():
                print(f"skip {group}/{name} (exists)")
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            print(f"clone {group}/{name} <- {url}")
            subprocess.run(["git", "clone", "--depth", "1", url, str(dest)], check=True)
    print("done. Run: python tests/manual_eval/run_eval.py --corpus")


if __name__ == "__main__":
    main()
