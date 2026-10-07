#!/bin/sh
# SkillTotal plugin: runs before every Bash command the agent wants to execute.
# Every command goes to the CLI. A cheaper text match here was tried and dropped: the shell runs
# `NPM install x` and `n''px x` as installs, a match on the raw text does not see them, and the
# parser does. One parser decides; the parsing and the answer live in `skilltotal hook claude-code`.
# Without the CLI there is nothing to check with; never block the agent for that.
command -v skilltotal >/dev/null 2>&1 || exit 0
skilltotal hook claude-code
exit 0
