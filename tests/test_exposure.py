"""Network-exposure posture: 0.0.0.0 binds and debug servers."""

from __future__ import annotations

from skilltotal.file_index import FileIndex
from skilltotal.models import ThreatClass
from skilltotal.scanners.exposure import ExposureScanner


def _scan(tmp_path, name, code):
    (tmp_path / name).write_text(code, encoding="utf-8")
    return ExposureScanner().scan(FileIndex.build(tmp_path))


def _ids(res):
    return {f.id for f in res.findings}


def test_flask_host_bind_flagged(tmp_path):
    res = _scan(tmp_path, "app.py", "app.run(host='0.0.0.0', port=8000)\n")
    assert "ST-EXPOSE-BIND" in _ids(res)
    assert all(f.threat_class == ThreatClass.RISKY_CONSTRUCT for f in res.findings)


def test_uvicorn_cli_host_flagged(tmp_path):
    # a .py launcher that builds the uvicorn command line
    res = _scan(tmp_path, "launch.py", 'cmd = "uvicorn app:app --host 0.0.0.0 --port 80"\n')
    assert "ST-EXPOSE-BIND" in _ids(res)


def test_socket_bind_tuple_flagged(tmp_path):
    res = _scan(tmp_path, "srv.py", "sock.bind(('0.0.0.0', 5000))\n")
    assert "ST-EXPOSE-BIND" in _ids(res)


def test_node_listen_all_interfaces_flagged(tmp_path):
    res = _scan(tmp_path, "server.js", "server.listen(3000, '0.0.0.0');\n")
    assert "ST-EXPOSE-BIND" in _ids(res)


def test_flask_debug_true_flagged(tmp_path):
    res = _scan(tmp_path, "app.py", "app.run(debug=True)\n")
    assert "ST-EXPOSE-DEBUG" in _ids(res)


def test_localhost_bind_not_flagged(tmp_path):
    res = _scan(tmp_path, "app.py", "app.run(host='127.0.0.1', port=8000)\n")
    assert _ids(res) == set()


def test_plain_code_not_flagged(tmp_path):
    res = _scan(tmp_path, "m.py", "x = '0.0.0.0 is the wildcard address'  # docs\n")
    # a bare mention in prose without a bind context should not match the bind patterns
    assert "ST-EXPOSE-BIND" not in _ids(res)
