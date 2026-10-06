"""Threat-research run 2026-10-02.

Two techniques published within the prior ~45 days, each paired with an honest look-alike:

* sckit/MemTensor credential harvester (compromised @memtensor npm + PyPI packages, reported
  September 2026) targets SSH key types beyond id_rsa, a HashiCorp Vault CLI token, and a
  Hugging Face CLI token - none of which the sensitive-path denylist covered.
* Dynamic decode-function resolution (cybersecuritynews.com, September 2026, on agent-skill
  scanner-evasion techniques): resolving b64decode/atob through getattr()/__dict__/vars() with
  a literal-or-concatenated name evades a plain "exec(/eval( directly followed by the decode
  function name" matcher.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal import engine
from skilltotal.collector import detect_component
from skilltotal.file_index import FileIndex
from skilltotal.scanners.obfuscation import ObfuscationScanner
from skilltotal.scanners.sensitive_paths import SensitivePathScanner


def _scan_sensitive(tmp_path: Path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8", newline="\n")
    return SensitivePathScanner().scan(FileIndex.build(tmp_path))


def _scan_obfuscation(tmp_path: Path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8", newline="\n")
    return ObfuscationScanner().scan(FileIndex.build(tmp_path))


def _analyze(relpath: str):
    root = Path(relpath)
    return engine.analyze_directory(root, detect_component(root, source=str(root)))


# --- sckit/MemTensor AI-dev credential paths (ST-SENS-PATH extension) ----------------------


def test_sensitive_paths_cover_new_aidev_credential_files(tmp_path: Path):
    content = (
        "const home = require('os').homedir();\n"
        "const loot = [\n"
        "  require('fs').readFileSync(`${home}/.ssh/id_ecdsa`, 'utf8'),\n"
        "  require('fs').readFileSync(`${home}/.ssh/id_ed25519`, 'utf8'),\n"
        "  require('fs').readFileSync(`${home}/.vault-token`, 'utf8'),\n"
        "  require('fs').readFileSync(`${home}/.cache/huggingface/token`, 'utf8'),\n"
        "];\n"
    )
    result = _scan_sensitive(tmp_path, "harvest.js", content)
    assert any(f.id == "ST-SENS-PATH" for f in result.findings)
    snippets = " ".join(e.snippet for f in result.findings for e in f.evidence)
    for token in ("id_ecdsa", "id_ed25519", "vault-token", "huggingface/token"):
        assert token in snippets


def test_ssh_keygen_look_alike_for_new_key_types_stays_clean(tmp_path: Path):
    # ssh-keygen -f <path> WRITES a fresh identity; it is not a read of an existing secret, the
    # same exemption id_rsa already had.
    content = 'ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""\n'
    result = _scan_sensitive(tmp_path, "rotate.sh", content)
    assert result.findings == []


def test_credential_harvest_fixture_synthesizes_exfil_combo():
    report = _analyze("tests/eval_corpus/positive/AST01/credential-exfil/node-aidev-cred-harvest")
    assert "ST-COMBO-EXFIL" in {f.id for f in report.findings}
    assert report.risk_level.value in ("high", "critical")


def test_deploy_key_rotation_look_alike_fixture_stays_clean():
    report = _analyze("tests/eval_corpus/negative/AST01/credential-exfil/deploy-key-rotation")
    ids = {f.id for f in report.findings}
    assert "ST-SENS-PATH" not in ids
    assert "ST-COMBO-EXFIL" not in ids
    assert not (report.verdict or {}).get("has_malicious_indicators")


# --- Dynamic decode-function resolution (ST-OBF-DYNAMIC-DECODE-EXEC) ------------------------


def test_dynamic_getattr_decode_exec_is_detected(tmp_path: Path):
    content = (
        "import base64\n"
        'exec(getattr(base64, "b64" + "decode")(b"cHJpbnQoMSk="))\n'
    )
    result = _scan_obfuscation(tmp_path, "plugin.py", content)
    assert any(f.id == "ST-OBF-DYNAMIC-DECODE-EXEC" for f in result.findings)
    f = next(f for f in result.findings if f.id == "ST-OBF-DYNAMIC-DECODE-EXEC")
    assert f.evidence  # every Finding must carry evidence


def test_dynamic_decode_without_exec_stays_clean(tmp_path: Path):
    # Same getattr()+concatenated-name shape, but the decoded bytes are only written to disk.
    content = (
        "import base64\n"
        'decoder = getattr(base64, "b64" + "decode")\n'
        "data = decoder(b'eyJhIjogMX0=')\n"
        "open('out.json', 'wb').write(data)\n"
    )
    result = _scan_obfuscation(tmp_path, "config_loader.py", content)
    assert result.findings == []


def test_dynamic_decode_exec_fixture_is_malicious():
    report = _analyze("tests/eval_corpus/positive/AST01/decode-exec/python-evasion-getattr")
    verdict = report.verdict or {}
    assert verdict.get("has_malicious_indicators") is True
    assert "ST-OBF-DYNAMIC-DECODE-EXEC" in {f.id for f in report.findings}


def test_getattr_decode_no_exec_fixture_stays_clean():
    report = _analyze("tests/eval_corpus/negative/AST01/decode-exec/getattr-decode-no-exec")
    assert "ST-OBF-DYNAMIC-DECODE-EXEC" not in {f.id for f in report.findings}
    assert not (report.verdict or {}).get("has_malicious_indicators")


def test_an_app_own_ed25519_identity_key_is_not_a_stolen_ssh_key(tmp_path: Path):
    # An application can keep its own signing key at ~/.<app>/id_ed25519 and read it to
    # authenticate to its registry. The key-type name alone flagged that, and with the client's
    # network calls synthesized an exfil combo on a mainstream project. Only an SSH directory
    # makes the name a credential path.
    findings = _scan_sensitive(tmp_path, "auth.go", (
        'const defaultPrivateKey = "id_ed25519"\n'
        'keyPath := filepath.Join(home, ".someapp", "id_ed25519")\n'
    ))
    assert findings.findings == []


def test_ssh_key_path_built_by_joining_segments_is_flagged(tmp_path: Path):
    findings = _scan_sensitive(tmp_path, "steal.py", (
        'key = open(os.path.join(home, ".ssh", "id_ed25519")).read()\n'
    ))
    assert any(f.id == "ST-SENS-PATH" for f in findings.findings)
