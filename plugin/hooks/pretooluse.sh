#!/bin/sh
# SkillTotal plugin: runs before every Bash or PowerShell command the agent wants to execute.
# Every command goes to the CLI. A cheaper text match here was tried and dropped: the shell runs
# `NPM install x` and `n''px x` as installs, a match on the raw text does not see them, and the
# parser does. One parser decides; the parsing and the answer live in `skilltotal hook claude-code`.
#
# Without a working CLI nothing can be checked. Outside CI the agent is never blocked for that, but
# it must not be silent either: a missing, broken or outdated install (a stale venv, a CLI older
# than this plugin) would otherwise look exactly like protection that found nothing. In CI (strict
# mode) nobody is there to read a warning, and a text match cannot rule an install out (an encoded,
# globbed or computed command reads like anything), so every command is denied until the CLI works.

# The hook protocol this wrapper needs (skilltotal.cli.HOOK_PROTOCOL; a test keeps the two equal):
# a CLI that speaks an older one, or knows no --protocol at all, fails on it.
PROTOCOL=2
FIX="To fix it, run pipx install skilltotal, or pipx upgrade skilltotal for an existing install."

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

# Whether the command looks like an install or a download: only a heuristic, for the console line
# outside CI when there is no parser to ask.
looks_like_install() {
  lowered=$(printf '%s' "$input" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz' \
    | tr -d "'\"\\\\\`")
  case "$lowered" in
    *npm*|*npx*|*pnpm*|*yarn*|*bun*|*pip*|*uv*|*python*|*"py "*|*mcp*) return 0 ;;
    *poetry*|*pdm*|*conda*|*mamba*|*curl*|*wget*|*irm*|*iwr*|*iex*|*invoke-*) return 0 ;;
    *downloadstring*|*downloadfile*|*webclient*) return 0 ;;
  esac
  return 1
}

deny() {
  reason="(CI rule) SkillTotal blocked this command: $1, so it could not be checked."
  note="Strict mode is on because $strict_by is set (SKILLTOTAL_STRICT=0 turns it off)."
  printf '%s\n' "{\"systemMessage\": \"$reason $FIX $note\", \"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", \"permissionDecision\": \"deny\", \"permissionDecisionReason\": \"$reason\"}}"
}

# Nothing could be checked: denied in strict mode, said for what looks like an install otherwise.
cannot_check() {
  if strict; then
    deny "$1"
    return
  fi
  looks_like_install || return 0
  printf '%s\n' "{\"systemMessage\": \"SkillTotal did not check this command: $1. $FIX\", \"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", \"additionalContext\": \"SkillTotal did not check this install: $1.\"}}"
}

# Outside CI, a CLI older than this plugin still checks what it knows: its answer stands, and for
# what looks like an install the person is told it was not the whole check.
older() {
  if ! looks_like_install; then
    if [ -n "$1" ]; then
      printf '%s\n' "$1"
    fi
    return
  fi
  note="SkillTotal did not fully check this command: the skilltotal CLI is older than this plugin. $FIX"
  case "$1" in
    *'"systemMessage"'*) printf '%s\n' "$1" ;;
    '{'*) printf '%s\n' "{\"systemMessage\": \"$note\", ${1#?}" ;;
    *) printf '%s\n' "{\"systemMessage\": \"$note\"}" ;;
  esac
}

input=$(cat)
if ! command -v skilltotal >/dev/null 2>&1; then
  cannot_check "the skilltotal CLI is not on PATH"
  exit 0
fi
if answer=$(printf '%s' "$input" | skilltotal hook claude-code --protocol "$PROTOCOL" 2>/dev/null); then
  if [ -n "$answer" ]; then
    printf '%s\n' "$answer"
  fi
  exit 0
fi
if strict; then
  deny "the skilltotal CLI failed to run or is older than this plugin"
  exit 0
fi
# An older CLI fails on --protocol and still answers without it; a broken one fails either way.
if old=$(printf '%s' "$input" | skilltotal hook claude-code 2>/dev/null); then
  older "$old"
else
  cannot_check "the skilltotal CLI failed to run"
fi
exit 0
