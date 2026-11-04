"""Methods named like the dynamic-execution builtins are not dynamic execution (0.93.0 sweep).

The 0.93.0 benign sweep stopped the release on two shapes in reputable packages: a torch module's
``Model(cfg).eval()`` read as the builtin ``eval`` (its base is a call, so only the method name
resolved), and bundled zod's ``new Function("")`` code-generation probe, which has an empty body.
Each look-alike must stay clean while the direct forms keep firing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal import engine
from skilltotal.collector import detect_component


def _ids(tmp_path: Path, name: str, code: str) -> set[str]:
    (tmp_path / name).write_text(code, encoding="utf-8")
    report = engine.analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))
    return {f.id for f in report.findings}


@pytest.mark.parametrize("code", [
    "attention = Attention(cfg, layer_idx=0).eval().to(dtype)\n",
    "result = QDialog(parent).exec()\n",
    "Model(inputs, outputs).compile(optimizer='adam', loss='mse')\n",
    "step = Model().eval\nstep()\n",
])
def test_a_method_named_like_a_builtin_is_not_dynamic_execution(tmp_path, code):
    assert "ST-DYN-PY" not in _ids(tmp_path, "model.py", code)


@pytest.mark.parametrize("code", [
    "eval(user_input)\n",
    "exec(payload)\n",
    "compile(source=text, filename='<x>', mode='exec')\n",
    "_run = exec\n_run(payload)\n",
    "load().exec(payload)\n",
])
def test_the_builtins_with_something_to_run_still_fire(tmp_path, code):
    assert "ST-DYN-PY" in _ids(tmp_path, "run.py", code)


@pytest.mark.parametrize("code", [
    'try { new Function(""); ok = true } catch (e) { ok = false }\n',
    "const jit = (() => { try { return new Function(''), true } catch { return false } })();\n",
])
def test_an_empty_function_body_probe_is_not_dynamic_execution(tmp_path, code):
    assert "ST-DYN-NODE" not in _ids(tmp_path, "probe.js", code)


@pytest.mark.parametrize("code", [
    "const run = new Function(body);\n",
    'const run = new Function("a", "return a + 1");\n',
    "new Function(atob(blob))();\n",
])
def test_a_function_with_a_body_still_fires(tmp_path, code):
    assert "ST-DYN-NODE" in _ids(tmp_path, "run.js", code)
