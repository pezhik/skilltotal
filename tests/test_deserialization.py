"""Unsafe deserialization detection (pickle/marshal/jsonpickle/yaml.load)."""

from __future__ import annotations

from skilltotal.file_index import FileIndex
from skilltotal.models import ThreatClass
from skilltotal.scanners.python_ast import PythonAstScanner


def _scan(tmp_path, code):
    (tmp_path / "m.py").write_text(code, encoding="utf-8")
    return PythonAstScanner().scan(FileIndex.build(tmp_path))


def _ids(res):
    return {f.id for f in res.findings}


def test_pickle_loads_flagged(tmp_path):
    res = _scan(tmp_path, "import pickle\nobj = pickle.loads(data)\n")
    assert "ST-DESERIALIZE-PY" in _ids(res)
    f = next(f for f in res.findings if f.id == "ST-DESERIALIZE-PY")
    assert f.threat_class == ThreatClass.RISKY_CONSTRUCT


def test_marshal_and_jsonpickle_flagged(tmp_path):
    assert "ST-DESERIALIZE-PY" in _ids(_scan(tmp_path, "import marshal\nmarshal.loads(b)\n"))
    assert "ST-DESERIALIZE-PY" in _ids(
        _scan(tmp_path, "import jsonpickle\njsonpickle.decode(s)\n")
    )


def test_yaml_load_without_loader_flagged(tmp_path):
    res = _scan(tmp_path, "import yaml\ncfg = yaml.load(stream)\n")
    assert "ST-DESERIALIZE-PY" in _ids(res)


def test_yaml_load_with_unsafe_loader_flagged(tmp_path):
    res = _scan(tmp_path, "import yaml\ncfg = yaml.load(stream, Loader=yaml.Loader)\n")
    assert "ST-DESERIALIZE-PY" in _ids(res)


def test_yaml_safe_load_not_flagged(tmp_path):
    assert "ST-DESERIALIZE-PY" not in _ids(
        _scan(tmp_path, "import yaml\ncfg = yaml.safe_load(stream)\n")
    )


def test_yaml_load_with_safeloader_not_flagged(tmp_path):
    res = _scan(tmp_path, "import yaml\ncfg = yaml.load(stream, Loader=yaml.SafeLoader)\n")
    assert "ST-DESERIALIZE-PY" not in _ids(res)


def test_json_loads_not_flagged(tmp_path):
    assert "ST-DESERIALIZE-PY" not in _ids(_scan(tmp_path, "import json\njson.loads(s)\n"))
