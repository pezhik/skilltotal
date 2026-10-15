#!/bin/sh
# SkillTotal plugin: runs before every Bash or PowerShell command the agent wants to execute.
# The CLI's parser decides what a command installs (`skilltotal hook claude-code`). Starting it
# costs about a second, so outside CI a command that cannot install anything skips it: one that
# holds only ASCII letters, digits, spaces, quotes and plain punctuation (no `$`, backquote,
# backslash, glob, brace, parenthesis, `+`, `%`, `^` or `!`, which a shell can build a name from)
# and, with its quotes removed and in any letter case, none of the words in TRIGGERS. A plain text
# match on installer names was dropped before because the shell runs `NPM install x` and `n''px x`
# as installs; this one ignores case, drops quotes, and hands anything it cannot rule out to the
# parser. It uses only shell builtins (a process started from Git Bash on Windows costs about
# 50 ms). In CI every command goes to the CLI, as before.
#
# Without a working CLI nothing can be checked. Outside CI the agent is never blocked for that, but
# it must not be silent either: a missing, broken or outdated install (a stale venv, a CLI older
# than this plugin) would otherwise look exactly like protection that found nothing. In CI (strict
# mode) nobody is there to read a warning, and a text match cannot rule an install out (an encoded,
# globbed or computed command reads like anything), so every command is denied until the CLI works.
# A CLI older than this plugin that says nothing about a command the pre-filter could not rule out
# may have missed what newer releases read (an encoded or computed install): that is said, and in
# CI denied.

# The hook protocol this wrapper needs (skilltotal.cli.HOOK_PROTOCOL; a test keeps the two equal):
# a CLI that speaks an older one, or knows no --protocol at all, fails on it.
PROTOCOL=2
INSTALL="To fix it, install the skilltotal CLI (pipx install skilltotal or pip install skilltotal)."
UPDATE="update the skilltotal CLI (pipx upgrade skilltotal or pip install -U skilltotal)"
FIX="To fix it, $UPDATE."

# Words that send a command to the parser (tests/test_plugin_prefilter.py reads this list). A word
# with `=` in front must stand alone (after every character but a letter or digit is read as a
# space); the others count anywhere in the command: installers and runners, interpreters and
# shells, downloads, evals and decoders, git clone, and agent CLIs that add servers or plugins.
TRIGGERS="np bun yarn pip =uv =uvx poetry pdm pipenv corepack conda mamba rye pixi volta easy_install
deno hatch tox nox python =py =py2 =py3 node perl ruby php osascript
=sh bash zsh dash ksh fish pwsh powershell cmd =exec eval iex invoke source trap alias
curl wget =irm =iwr download webclient http base xxd openssl printf decode atob uudecode
clone claude codex gemini skill smithery mcp"

# CI strict mode, read the way the CLI reads it: SKILLTOTAL_STRICT=0/false/no/off turns it off and
# any other non-empty value on (1/true/yes/on, or a typo: a typo must not loosen a gate); otherwise
# it is on when CI, or the marker of a CI service that does not always set CI, is set to anything
# but empty or a false value. `strict_by` names the variable that did. Only ASCII letters are
# lowercased, and only spaces, tabs and line ends are removed.
word() {
  printf '%s' "$1" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz' | tr -d ' \t\r\n'
}
strict() {
  if [ -n "${SKILLTOTAL_STRICT:-}" ]; then
    case "$(word "$SKILLTOTAL_STRICT")" in
      0|false|no|off) return 1 ;;
      '') ;;
      *) strict_by=SKILLTOTAL_STRICT; return 0 ;;
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
    # A command decoded and run: `... | base64 -d | sh`, FromBase64String, `certutil -decode`,
    # `powershell -EncodedCommand ...` (any prefix of it, down to `-e`).
    *base64*|*certutil*|*powershell*" -e"*|*pwsh*" -e"*|*powershell*" /e"*|*pwsh*" /e"*) return 0 ;;
  esac
  return 1
}

# Whether the command certainly installs nothing, so the CLI need not start (see the top). Any
# doubt, a field it cannot find or an escape it does not undo, answers no.
ALNUM=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
QUOTES="'\""
# What a plain command may hold, spelled out rather than as ranges, which some shells read by locale.
PLAIN="$ALNUM$QUOTES ._/:,@=;|&<>#~-"
plain_command() {
  # The one "command" field of the event (two: the CLI decides which one runs).
  case $input in
    *'"command"'*'"command"'*) return 1 ;;
    *'"command"'*) rest=${input#*'"command"'} ;;
    *) return 1 ;;
  esac
  rest=${rest#"${rest%%[! ]*}"}
  case $rest in :*) rest=${rest#?} ;; *) return 1 ;; esac
  rest=${rest#"${rest%%[! ]*}"}
  case $rest in \"*) rest=${rest#?} ;; *) return 1 ;; esac
  # Its JSON string, up to the closing quote. An escaped quote (`\"`) is a quote; any other escape
  # (`\\`, `\n`, `\u...`) is not undone here, so the CLI reads that command.
  text=
  while :; do
    chunk=${rest%%\"*}
    [ "$chunk" != "$rest" ] || return 1
    rest=${rest#"$chunk"}
    rest=${rest#?}
    escaped=
    case $chunk in *\\) chunk=${chunk%?} escaped=1 ;; esac
    case $chunk in *\\*) return 1 ;; esac
    text=$text$chunk
    [ -n "$escaped" ] || break
  done
  [ -n "$text" ] && [ "${#text}" -le 4096 ] || return 1
  case $text in *[!$PLAIN]*) return 1 ;; esac
  # The command without its quotes: `n''px` is `npx`.
  bare=
  while :; do
    chunk=${text%%[$QUOTES]*}
    bare=$bare$chunk
    [ "$chunk" != "$text" ] || break
    text=${text#"$chunk"}
    text=${text#?}
  done
  for trigger in $TRIGGERS; do
    any_case "${trigger#=}"
    case $trigger in
      =*) case " $bare " in *[!$ALNUM]$pattern[!$ALNUM]*) return 1 ;; esac ;;
      *) case $bare in *$pattern*) return 1 ;; esac ;;
    esac
  done
  return 0
}

# Sets `pattern` to a lowercase word in any letter case: `np` -> `[nN][pP]` (no subshell: each one
# would start a process).
any_case() {
  rest=$1
  pattern=
  while [ -n "$rest" ]; do
    tail=${rest#?}
    letter=${rest%"$tail"}
    rest=$tail
    case $letter in
      a) pattern="$pattern[aA]" ;; b) pattern="$pattern[bB]" ;; c) pattern="$pattern[cC]" ;;
      d) pattern="$pattern[dD]" ;; e) pattern="$pattern[eE]" ;; f) pattern="$pattern[fF]" ;;
      g) pattern="$pattern[gG]" ;; h) pattern="$pattern[hH]" ;; i) pattern="$pattern[iI]" ;;
      j) pattern="$pattern[jJ]" ;; k) pattern="$pattern[kK]" ;; l) pattern="$pattern[lL]" ;;
      m) pattern="$pattern[mM]" ;; n) pattern="$pattern[nN]" ;; o) pattern="$pattern[oO]" ;;
      p) pattern="$pattern[pP]" ;; q) pattern="$pattern[qQ]" ;; r) pattern="$pattern[rR]" ;;
      s) pattern="$pattern[sS]" ;; t) pattern="$pattern[tT]" ;; u) pattern="$pattern[uU]" ;;
      v) pattern="$pattern[vV]" ;; w) pattern="$pattern[wW]" ;; x) pattern="$pattern[xX]" ;;
      y) pattern="$pattern[yY]" ;; z) pattern="$pattern[zZ]" ;;
      *) pattern="$pattern$letter" ;;
    esac
  done
}

deny() {
  reason="(CI rule) SkillTotal blocked this command: $1, so it could not be checked."
  note="Strict mode is on because $strict_by is set (SKILLTOTAL_STRICT=0 turns it off)."
  printf '%s\n' "{\"systemMessage\": \"$reason $2 $note\", \"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", \"permissionDecision\": \"deny\", \"permissionDecisionReason\": \"$reason\"}}"
}

# Nothing could be checked: denied in strict mode, said for what looks like an install otherwise.
cannot_check() {
  if strict; then
    deny "$1" "$2"
    return
  fi
  looks_like_install || return 0
  printf '%s\n' "{\"systemMessage\": \"SkillTotal did not check this command: $1. $2\", \"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", \"additionalContext\": \"SkillTotal did not check this install: $1.\"}}"
}

# Outside CI, a CLI too old to speak this plugin's protocol still checks what it knows: its answer
# stands, and the person is told it was not the whole check. Only a command the pre-filter could
# not rule out gets here, so the line comes even when the old CLI said nothing.
older() {
  with_note "$1" "SkillTotal did not fully check this command: the skilltotal CLI is older than this plugin. $FIX"
}

# The CLI's answer ($1) with a console line ($2) added in front of its own, or the line alone.
# The answer is the CLI's JSON (json.dumps): its key is the only unescaped `"systemMessage": "`.
with_note() {
  case "$1" in
    *'"systemMessage": "'*)
      printf '%s\n' "$1" | sed "s|\"systemMessage\": \"|\"systemMessage\": \"$2 |" ;;
    '{'*) printf '%s\n' "{\"systemMessage\": \"$2\", ${1#?}" ;;
    *) printf '%s\n' "{\"systemMessage\": \"$2\"}" ;;
  esac
}

# Sets `version` to $1 when it is a plain version number (0.72.0, 1.0.0rc1), else to nothing.
plain_version() {
  version=$1
  case $version in
    [0123456789]*) ;;
    *) version= ;;
  esac
  case $version in *[!$ALNUM.+-]*) version= ;; esac
}

# Sets `mine` to the plugin's version, from its manifest next to this script (shell builtins only:
# it is read for every answer).
plugin_version() {
  mine=
  case $0 in */*|*\\*) manifest=${0%[/\\]*} ;; *) manifest=. ;; esac  # `\`: a Windows path
  manifest=$manifest/../.claude-plugin/plugin.json
  [ -r "$manifest" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case $line in *'"version"'*) ;; *) continue ;; esac
    line=${line#*'"version"'}
    line=${line#"${line%%[! ]*}"}
    case $line in :*) line=${line#?} ;; *) continue ;; esac
    line=${line#"${line%%[! ]*}"}
    case $line in \"*) line=${line#?} ;; *) continue ;; esac
    plain_version "${line%%\"*}"
    mine=$version
    return 0
  done < "$manifest"
}

# The CLI's answer starts with its version (`skilltotal 0.73.0`, asked for with
# SKILLTOTAL_HOOK_VERSION_LINE): sets `theirs` to it and takes that line off `answer`. A CLI that
# predates the line leaves `theirs` empty and `answer` as it was.
NL='
'
split_version() {
  theirs=
  first=${answer%%"$NL"*}
  case $first in 'skilltotal '*) ;; *) return 0 ;; esac
  version=${first#skilltotal }
  case $version in *[!$ALNUM.+-]) version=${version%?} ;; esac  # a Windows line end
  plain_version "$version"
  [ -n "$version" ] || return 0
  theirs=$version
  answer=${answer#"$first"}
  answer=${answer#"$NL"}
}

# Whether version $1 is lower than $2, by their first three numbers (0.66.0 < 0.69.0).
lower() {
  a=$1
  b=$2
  for _ in 1 2 3; do
    x=${a%%[!0-9]*}
    y=${b%%[!0-9]*}
    a=${a#"$x"}
    a=${a#.}
    b=${b#"$y"}
    b=${b#.}
    [ "${#x}" -le 9 ] && [ "${#y}" -le 9 ] || return 1
    [ "${x:-0}" -lt "${y:-0}" ] && return 0
    [ "${x:-0}" -gt "${y:-0}" ] && return 1
  done
  return 1
}

# The CLI's answer, with a line in front when the CLI is older than this plugin: it speaks the
# protocol, so it checks, but without what newer releases check. When it said nothing about a
# command the pre-filter could not rule out, that silence is no verdict: said, and in CI denied.
answer_with_version() {
  split_version
  plugin_version
  if [ -z "$theirs" ] && [ -n "$mine" ] && { [ -n "$answer" ] || [ -z "$plain" ]; }; then
    # A CLI that predates the version line: asked for it separately.
    first=$(skilltotal --version 2>/dev/null)
    first=${first%%"$NL"*}
    case $first in
      'skilltotal '*)
        version=${first#skilltotal }
        case $version in *[!$ALNUM.+-]) version=${version%?} ;; esac
        plain_version "$version"
        theirs=$version
        ;;
    esac
  fi
  if [ -z "$mine" ] || [ -z "$theirs" ] || ! lower "$theirs" "$mine"; then
    if [ -n "$answer" ]; then
      printf '%s\n' "$answer"
    fi
  elif [ -n "$answer" ]; then
    with_note "$answer" "SkillTotal CLI $theirs is older than the plugin $mine; $UPDATE."
  elif [ -n "$plain" ]; then
    :  # a command that certainly installs nothing (in CI, where it still goes to the CLI)
  elif strict; then
    deny "the skilltotal CLI $theirs is older than the plugin $mine" "$FIX"
  else
    printf '%s\n' "{\"systemMessage\": \"SkillTotal CLI $theirs is older than the plugin $mine and could not judge this command; $UPDATE.\"}"
  fi
}

input=$(cat)
if ! command -v skilltotal >/dev/null 2>&1; then
  # pipx puts the command in a folder a fresh shell may not have on PATH yet.
  cannot_check "the skilltotal CLI is not on PATH" "$INSTALL If it is installed, run pipx ensurepath and start Claude Code from a new terminal."
  exit 0
fi
plain=
if plain_command; then
  plain=1
  strict || exit 0
fi
if answer=$(printf '%s' "$input" | SKILLTOTAL_HOOK_VERSION_LINE=1 skilltotal hook claude-code --protocol "$PROTOCOL" 2>/dev/null); then
  answer_with_version
  exit 0
fi
if strict; then
  deny "the skilltotal CLI failed to run or is older than this plugin" "$FIX"
  exit 0
fi
# An older CLI fails on --protocol and still answers without it; a broken one fails either way.
if old=$(printf '%s' "$input" | skilltotal hook claude-code 2>/dev/null); then
  older "$old"
else
  cannot_check "the skilltotal CLI failed to run" "$FIX"
fi
exit 0
