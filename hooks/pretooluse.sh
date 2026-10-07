#!/bin/sh
# SkillTotal plugin: runs before every Bash command the agent wants to execute.
# Every command goes to the CLI. A cheaper text match here was tried and dropped: the shell runs
# `NPM install x` and `n''px x` as installs, a match on the raw text does not see them, and the
# parser does. One parser decides; the parsing and the answer live in `skilltotal hook claude-code`.
#
# Without a working CLI nothing can be checked, and the agent is never blocked for that. It must
# not be silent either: a missing or broken install (a stale venv, a CLI too old to know `hook`)
# would otherwise look exactly like protection that found nothing.

# Tell the person, for commands that look like an install. Only a heuristic, and only for this
# warning: with no CLI there is no parser to ask.
warn() {
  lowered=$(printf '%s' "$input" | tr 'A-Z' 'a-z' | tr -d "'\"\\\\")
  case "$lowered" in
    *npm*|*npx*|*pnpm*|*yarn*|*bun*|*pip*|*uv*|*python*|*"py "*|*mcp*) ;;
    *) return ;;
  esac
  printf '%s\n' "{\"systemMessage\": \"SkillTotal did not check this install: $1. Fix: pip install -U skilltotal\", \"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", \"additionalContext\": \"SkillTotal did not check this install: $1.\"}}"
}

input=$(cat)
if ! command -v skilltotal >/dev/null 2>&1; then
  warn "the skilltotal CLI is not on PATH"
  exit 0
fi
if ! answer=$(printf '%s' "$input" | skilltotal hook claude-code 2>/dev/null); then
  warn "the skilltotal CLI failed to run"
  exit 0
fi
if [ -n "$answer" ]; then
  printf '%s\n' "$answer"
fi
exit 0
