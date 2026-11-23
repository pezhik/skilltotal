"""Decode-and-execute written without a plain `eval(decoder(...))` call (research 2026-11-23).

Each attack is paired with an honest look-alike that must stay quiet.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal import engine
from skilltotal.collector import detect_component

RULE = "ST-OBF-DECODE-EXEC"
BANNER = "// FIXTURE ONLY - synthetic detection test sample, not real malware\n"
BLOB = "const blob = 'cHJpbnQoMSk=';\n"


def _ids(tmp_path: Path, body: str) -> set[str]:
    (tmp_path / "index.js").write_text(BANNER + body, encoding="utf-8")
    report = engine.analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))
    return {f["id"] for f in report.to_dict()["findings"]}


def test_function_returned_decode_then_eval(tmp_path: Path) -> None:
    attack = (
        "function unwrap(s) { return Buffer.from(s, 'base64').toString(); }\n"
        + BLOB + "eval(unwrap(blob));\n"
    )
    assert RULE in _ids(tmp_path, attack)


def test_function_returned_decode_via_variable(tmp_path: Path) -> None:
    attack = (
        "function unwrap(s) { return atob(s); }\n"
        + BLOB + "const code = unwrap(blob);\nnew Function(code)();\n"
    )
    assert RULE in _ids(tmp_path, attack)


def test_decode_helper_never_evaluated_is_clean(tmp_path: Path) -> None:
    honest = (
        "function unwrap(s) { return Buffer.from(s, 'base64').toString(); }\n"
        "console.log(unwrap('aGVsbG8='));\n"
    )
    assert RULE not in _ids(tmp_path, honest)


def test_optional_call_eval(tmp_path: Path) -> None:
    assert RULE in _ids(tmp_path, BLOB + "eval?.(atob(blob));\n")


def test_optional_call_on_other_function_is_clean(tmp_path: Path) -> None:
    assert RULE not in _ids(tmp_path, BLOB + "console.log?.(atob(blob));\n")


def test_reflect_apply_and_construct(tmp_path: Path) -> None:
    assert RULE in _ids(tmp_path, BLOB + "Reflect.apply(eval, null, [atob(blob)]);\n")
    assert RULE in _ids(tmp_path, BLOB + "Reflect.construct(Function, [atob(blob)])();\n")


def test_reflect_apply_on_math_is_clean(tmp_path: Path) -> None:
    honest = BLOB + "Reflect.apply(Math.max, null, [blob.length, 2]);\nconsole.log(atob(blob));\n"
    assert RULE not in _ids(tmp_path, honest)


def test_timer_given_decoded_string(tmp_path: Path) -> None:
    assert RULE in _ids(tmp_path, BLOB + "setTimeout(atob(blob), 0);\n")
    assert RULE in _ids(tmp_path, BLOB + "setInterval(atob(blob), 1000);\n")


def test_timer_with_callback_is_clean(tmp_path: Path) -> None:
    honest = BLOB + "setTimeout(() => console.log(atob(blob)), 0);\n"
    assert RULE not in _ids(tmp_path, honest)


def test_decode_helper_reached_only_through_other_names_is_clean(tmp_path: Path) -> None:
    # A bundle's one-letter names chain a helper's decoded buffer through unrelated values (its
    # length, then a delay) into a timer given a callback: nothing decoded is evaluated.
    honest = (
        'function d(e){return Buffer.from(e,"base64url")}\n'
        "function size(e){let r=d(e);return r.byteLength}\n"
        "const t=size(input);\n"
        "const timer=setTimeout(done,t);\n"
    )
    assert RULE not in _ids(tmp_path, honest)


def test_decode_helper_result_stored_then_evaluated(tmp_path: Path) -> None:
    attack = (
        'function d(e){return Buffer.from(e,"base64").toString()}\n'
        + BLOB + "let r=d(blob);\nsetTimeout(r,0);\n"
    )
    assert RULE in _ids(tmp_path, attack)
