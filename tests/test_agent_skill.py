"""Agent Skill support: SKILL.md detection + declared-vs-actual capability mismatch.

ST-SKILL-CAP-MISMATCH is synthesized in the engine (like ST-COMBO-EXFIL), so these tests run the
full engine over a temp skill folder.
"""

from __future__ import annotations

from skilltotal import engine
from skilltotal.agent_skill import parse_skill_frontmatter
from skilltotal.collector import detect_component

MISMATCH = "ST-SKILL-CAP-MISMATCH"


def _skill(tmp_path, frontmatter: str, *, helper: str | None = None):
    (tmp_path / "SKILL.md").write_text(frontmatter, encoding="utf-8")
    if helper is not None:
        (tmp_path / "helper.py").write_text(helper, encoding="utf-8")
    component = detect_component(tmp_path, str(tmp_path))
    report = engine.analyze_directory(tmp_path, component)
    return component, {f.id for f in report.findings}


_FM_READ = "---\nname: demo\ndescription: A demo skill.\nallowed-tools: [Read]\n---\n# Demo\n"


# --- frontmatter parser --------------------------------------------------------------
def test_parse_inline_list():
    fm = parse_skill_frontmatter("---\nname: x\nallowed-tools: [Read, Write]\n---\nbody\n")
    assert fm["allowed_tools"] == ["Read", "Write"]
    assert fm["name"] == "x"


def test_parse_block_list():
    text = "---\nname: x\nallowed-tools:\n  - Read\n  - Bash\n---\n"
    assert parse_skill_frontmatter(text)["allowed_tools"] == ["Read", "Bash"]


def test_parse_comma_string():
    assert parse_skill_frontmatter("---\nallowed-tools: Read, Write\n---\n")["allowed_tools"] == [
        "Read",
        "Write",
    ]


def test_parse_no_frontmatter():
    assert parse_skill_frontmatter("# just markdown\nno frontmatter\n") is None


def test_parse_no_allowed_tools():
    fm = parse_skill_frontmatter("---\nname: x\ndescription: y\n---\n")
    assert fm is not None and fm["allowed_tools"] is None


# --- component detection -------------------------------------------------------------
def test_skill_md_detected_as_agent_skill(tmp_path):
    component, _ = _skill(tmp_path, _FM_READ)
    assert component.type == "agent_skill"


# --- mismatch fires ------------------------------------------------------------------
def test_mismatch_network_undeclared(tmp_path):
    # declares only Read, but bundled code reaches the network
    _, ids = _skill(tmp_path, _FM_READ, helper="import requests\nrequests.get('http://x')\n")
    assert MISMATCH in ids


def test_mismatch_shell_undeclared(tmp_path):
    _, ids = _skill(tmp_path, _FM_READ, helper="import subprocess\nsubprocess.run(['ls'])\n")
    assert MISMATCH in ids


# --- mismatch does NOT fire ----------------------------------------------------------
def test_no_mismatch_when_tool_declared(tmp_path):
    fm = "---\nname: x\nallowed-tools: [Read, Bash]\n---\n"
    _, ids = _skill(tmp_path, fm, helper="import subprocess\nsubprocess.run(['ls'])\n")
    assert MISMATCH not in ids


def test_no_mismatch_without_allowed_tools(tmp_path):
    fm = "---\nname: x\ndescription: y\n---\n"
    _, ids = _skill(tmp_path, fm, helper="import subprocess\nsubprocess.run(['ls'])\n")
    assert MISMATCH not in ids


def test_no_mismatch_wildcard(tmp_path):
    fm = "---\nname: x\nallowed-tools: ['*']\n---\n"
    _, ids = _skill(tmp_path, fm, helper="import subprocess\nsubprocess.run(['ls'])\n")
    assert MISMATCH not in ids


def test_no_mismatch_read_only_code(tmp_path):
    # declares Read, code only reads -> filesystem_read is not a checked capability
    _, ids = _skill(tmp_path, _FM_READ, helper="data = open('data.txt').read()\n")
    assert MISMATCH not in ids
