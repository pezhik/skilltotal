#!/bin/sh
# SkillTotal plugin: runs before every Bash command the agent wants to execute.
# Most commands install nothing, so they are let through here without starting Python.
# The real parsing and the decision live in `skilltotal hook claude-code`.
input=$(cat)
case "$input" in
  *npx*|*bunx*|*"npm i"*|*"npm add"*|*"pnpm add"*|*"pnpm i"*|*"pnpm dlx"*|*"yarn add"*|  *"bun add"*|*"bun i"*|*"pip install"*|*"pip3 install"*|*"uv add"*|*"uv pip install"*|  *uvx*|*"pipx install"*|*"pipx run"*|*"mcp add"*) ;;
  *) exit 0 ;;
esac
# Without the CLI there is nothing to check with; never block the agent for that.
command -v skilltotal >/dev/null 2>&1 || exit 0
printf '%s' "$input" | skilltotal hook claude-code
exit 0
