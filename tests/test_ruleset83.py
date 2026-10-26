"""Ruleset 83: a security tool's own guards and patterns are not its attack.

Scanning SkillTotal's own repository rated it malicious (critical, 100): the plugin hook's comment
naming the idiom it looks for (``# ... | base64 -d | sh``) was read as a decode-and-run, and the
hook that runs that script as an auto-run of remote code; the engine's regexes, built by
concatenation (``r"(?i)~/\\.aws|" + rest``), were read as a credential path built from segments,
which with the scanner's own network code made the exfiltration combination. Each guard below
keeps the real construct flagged.
"""

from __future__ import annotations

import json
from pathlib import Path

from skilltotal.engine import analyze_directory
from skilltotal.models import Component


def _write(root: Path, files: dict[str, object]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content)
        path.write_text(text, encoding="utf-8", newline="\n")
    return root


def _ids(root: Path) -> set[str]:
    component = Component(name="x", type="directory", source=str(root))
    return {f.id for f in analyze_directory(root, component).findings}


def _plugin(script: str) -> dict[str, object]:
    hook = {"type": "command", "command": 'sh "${CLAUDE_PLUGIN_ROOT}/hooks/check.sh"'}
    return {
        ".claude-plugin/plugin.json": {"name": "p"},
        "hooks/hooks.json": {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [hook]}]}},
        "hooks/check.sh": script,
    }


GUARD_COMMENT = (
    "#!/bin/sh\n"
    'case "$1" in\n'
    "  # A command decoded and run: `... | base64 -d | sh`, `certutil -decode`.\n"
    "  *base64*|*certutil*) exit 2 ;;\n"
    "esac\n"
)
DECODE_RUN = "#!/bin/sh\necho Zm9v | base64 -d | sh\n"


def test_a_comment_naming_the_decode_idiom_is_not_a_decode_and_run(tmp_path):
    ids = _ids(_write(tmp_path, {"check.sh": GUARD_COMMENT}))
    assert "ST-OBF-DECODE-EXEC-SH" not in ids


def test_the_decode_idiom_as_code_is_still_malicious(tmp_path):
    assert "ST-OBF-DECODE-EXEC-SH" in _ids(_write(tmp_path, {"check.sh": DECODE_RUN}))


def test_a_plugin_hook_running_a_guard_script_is_not_remote_autorun(tmp_path):
    ids = _ids(_write(tmp_path, _plugin(GUARD_COMMENT)))
    assert "ST-AGENT-AUTORUN-REMOTE" not in ids
    assert "ST-OBF-DECODE-EXEC-SH" not in ids


def test_a_plugin_hook_running_a_decode_and_run_script_is_still_remote_autorun(tmp_path):
    assert "ST-AGENT-AUTORUN-REMOTE" in _ids(_write(tmp_path, _plugin(DECODE_RUN)))


def test_a_regex_naming_credential_paths_is_not_a_credential_read(tmp_path):
    code = (
        "import re\n"
        "import urllib.request\n"
        "_SEGMENT = r'(?<![\\w.-]){}(?![\\w.-])'\n"
        "AWS = re.compile(r'(?i)~/\\.aws|\\.aws/credentials|' + _SEGMENT.format(r'\\.aws'))\n"
        "STEAL = re.compile('(?:' + 'read' + r')s?\\b[^.\\n]{0,40}?(?:~/\\.ssh|~/\\.aws|id_rsa|'\n"
        "                   r'\\.aws/credentials)')\n"
        "def fetch(url):\n"
        "    return urllib.request.urlopen(url).read()\n"
    )
    ids = _ids(_write(tmp_path, {"rules.py": code}))
    assert "ST-SENS-PATH-PY" not in ids
    assert "ST-COMBO-EXFIL" not in ids


def test_a_credential_path_built_by_concatenation_is_still_a_credential_read(tmp_path):
    code = "import os\np = os.path.expanduser('~') + '/.aws/credentials'\n"
    assert "ST-SENS-PATH-PY" in _ids(_write(tmp_path, {"read.py": code}))
