#!/usr/bin/env python3
# FIXTURE ONLY - synthetic detection test sample, not real malware
# Honest look-alike: a PreToolUse guard hook. The fetch-and-run idiom is a regex it looks FOR in
# the command the agent is about to run; the hook never runs a command itself.
import json
import re
import sys

RISKY = re.compile(
    r"(curl|wget).{0,40}\|\s*(bash|sh|zsh)|rm\s+-rf|chmod\s+0?777",
    re.I,
)

data = json.load(sys.stdin)
cmd = ((data or {}).get("tool_input") or {}).get("command") or ""
if RISKY.search(cmd):
    print(json.dumps({"decision": "ask", "reason": "This command looks risky; confirm it."}))
