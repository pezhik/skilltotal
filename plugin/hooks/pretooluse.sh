#!/bin/sh
# SkillTotal plugin: runs before every Bash or PowerShell command the agent wants to execute.
# Every command goes to the CLI. A cheaper text match here was tried and dropped: the shell runs
# `NPM install x` and `n''px x` as installs, a match on the raw text does not see them, and the
# parser does. One parser decides; the parsing and the answer live in `skilltotal hook claude-code`.
#
# Without a working CLI nothing can be checked. Outside CI the agent is never blocked for that, but
# it must not be silent either: a missing or broken install (a stale venv, a CLI too old to know
# `hook`) would otherwise look exactly like protection that found nothing. In CI (strict mode)
# nobody is there to read a warning, so an install that cannot be checked is denied.

# CI strict mode, read the way the CLI reads it: SKILLTOTAL_STRICT=1/true turns it on and 0/false
# off; otherwise it is on exactly when CI is set to anything but empty, 0 or false.
strict() {
  case "$(printf '%s' "${SKILLTOTAL_STRICT:-}" | tr 'A-Z' 'a-z' | tr -d ' \t\r\n')" in
    1|true) return 0 ;;
    0|false) return 1 ;;
  esac
  case "$(printf '%s' "${CI:-}" | tr 'A-Z' 'a-z' | tr -d ' \t\r\n')" in
    ''|0|false) return 1 ;;
  esac
  return 0
}

# Tell the person, for commands that look like an install, and deny them in strict mode. Only a
# heuristic: with no CLI there is no parser to ask.
unchecked() {
  lowered=$(printf '%s' "$input" | tr 'A-Z' 'a-z' | tr -d "'\"\\\\")
  case "$lowered" in
    *npm*|*npx*|*pnpm*|*yarn*|*bun*|*pip*|*uv*|*python*|*"py "*|*mcp*) ;;
    *) return ;;
  esac
  fix="To fix it, run pipx install skilltotal, or pipx upgrade skilltotal for an existing install."
  if strict; then
    reason="(CI rule) SkillTotal blocked this command: $1, so it could not be checked."
    printf '%s\n' "{\"systemMessage\": \"$reason $fix\", \"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", \"permissionDecision\": \"deny\", \"permissionDecisionReason\": \"$reason\"}}"
    return
  fi
  printf '%s\n' "{\"systemMessage\": \"SkillTotal did not check this command: $1. $fix\", \"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", \"additionalContext\": \"SkillTotal did not check this install: $1.\"}}"
}

input=$(cat)
if ! command -v skilltotal >/dev/null 2>&1; then
  unchecked "the skilltotal CLI is not on PATH"
  exit 0
fi
if ! answer=$(printf '%s' "$input" | skilltotal hook claude-code 2>/dev/null); then
  unchecked "the skilltotal CLI failed to run"
  exit 0
fi
if [ -n "$answer" ]; then
  printf '%s\n' "$answer"
fi
exit 0
