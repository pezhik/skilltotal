#!/bin/sh
# SkillTotal plugin: runs before every Bash command the agent wants to execute.
# Commands that never name a package manager are let through here without starting Python. The
# match is on the manager's name, not on "npm install": flags, extra spaces and wrappers
# (`npm --silent install`, `bash -c '...'`) must still reach the real parser.
# The parsing and the decision live in `skilltotal hook claude-code`.
input=$(cat)
case "$input" in
  *npm*|*npx*|*pnp*|*yarn*|*bun*|*pip*|*uv*|*python*|*"py "*|*mcp*) ;;
  *) exit 0 ;;
esac
# Without the CLI there is nothing to check with; never block the agent for that.
command -v skilltotal >/dev/null 2>&1 || exit 0
printf '%s' "$input" | skilltotal hook claude-code
exit 0
