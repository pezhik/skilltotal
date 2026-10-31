#!/bin/sh
# SkillTotal plugin: runs when a session starts and when skills or user settings change. What the
# sentinel found last goes to the agent at once, and a sweep of what changed starts in the
# background: `skilltotal watch --session` returns without waiting for it. A missing CLI, or one
# older than this plugin, must not get in the way of a session: the install hook says what is wrong.
command -v skilltotal >/dev/null 2>&1 || exit 0
skilltotal watch --session 2>/dev/null
exit 0
