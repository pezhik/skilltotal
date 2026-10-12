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

# CI strict mode, read the way the CLI reads it: SKILLTOTAL_STRICT=1/true/yes/on turns it on and
# 0/false/no/off off; otherwise it is on when CI, or the marker of a CI service that does not always
# set CI, is set to anything but empty or a false value. `strict_by` names the variable that did.
# Only ASCII letters are lowercased, and only spaces, tabs and line ends are removed.
word() {
  printf '%s' "$1" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz' | tr -d ' \t\r\n'
}
strict() {
  if [ -n "${SKILLTOTAL_STRICT:-}" ]; then
    case "$(word "$SKILLTOTAL_STRICT")" in
      1|true|yes|on) strict_by=SKILLTOTAL_STRICT; return 0 ;;
      0|false|no|off) return 1 ;;
    esac
  fi
  for name in CI TF_BUILD JENKINS_URL TEAMCITY_VERSION CODEBUILD_BUILD_ID BUILDKITE GITLAB_CI; do
    eval "value=\${$name:-}"
    [ -n "$value" ] || continue
    case "$(word "$value")" in
      ''|0|false|no|off) ;;
      *) strict_by=$name; return 0 ;;
    esac
  done
  return 1
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
    note="Strict mode is on because $strict_by is set (SKILLTOTAL_STRICT=0 turns it off)."
    printf '%s\n' "{\"systemMessage\": \"$reason $fix $note\", \"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", \"permissionDecision\": \"deny\", \"permissionDecisionReason\": \"$reason\"}}"
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
