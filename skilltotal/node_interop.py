"""Node.js module calls as a compiler writes them, spelled the way the source wrote them.

A published npm package ships what tsc, esbuild, Babel or swc made of its source, and the detection
patterns read the source's spelling. ``fs.writeFileSync(p, x)`` becomes::

    const fs_1 = __importDefault(require("fs"));        // tsc
    fs_1.default.writeFileSync(p, x);
    (0, fs_1.writeFileSync)(p, x);                      // a named import

    var import_fs = __toESM(require("fs"));             // esbuild
    import_fs.default.writeFileSync(p, x);

:func:`call_sites` finds such calls and :func:`fold` rewrites them in place: the receiver becomes
the module's usual name and everything else in the span becomes spaces, so the text keeps its length
and a match found in the folded text is a span of the original. Nothing is resolved by name alone:
a site counts only through a binding of the module in the same file, in code, so an unrelated object
called ``fs_1`` is left as it is. A one-letter name (``f.writeFileSync(``) has no room for ``fs.``
and stays unfolded.

Deterministic and dependency-free; nothing is run.
"""

from __future__ import annotations

import re
from collections.abc import Callable

# Module -> the name the detection patterns spell it with. child_process has none: an import of it
# makes a bare `exec(` count (see scanners.shell_exec), and a bare call fits in any span.
_SPELLING = {
    "fs": "fs",
    "fs/promises": "fs",
    "child_process": "",
    "http": "http",
    "https": "https",
    "vm": "vm",
    "axios": "axios",
    "node-fetch": "fetch",
    "cross-fetch": "fetch",
}
# Modules whose default export is itself the call (`(0, axios_1.default)(config)`).
_CALLABLE = frozenset({"axios", "node-fetch", "cross-fetch"})
_DEFAULT_ONLY = frozenset({"node-fetch", "cross-fetch"})

_NAME = r"[A-Za-z_$][\w$]{0,100}"
_MODULES = "|".join(re.escape(m) for m in sorted(_SPELLING, key=len, reverse=True))
# The interop helpers each compiler wraps a require in (a helper this list does not name might
# return anything).
_HELPERS = (
    r"(?:(?:tslib_\d+\.)?__import(?:Default|Star)|__toESM|_interopRequire(?:Default|Wildcard)"
    r"|_interop_require_(?:default|wildcard))"
)
_REQUIRE_BINDING = re.compile(
    rf"(?<![\w$.])(?:const|let|var|import)[ \t]+({_NAME})[ \t]*=[ \t]*"
    r"(?:/\*[^*\n]{0,40}\*/[ \t]*)?"
    rf"(?:{_HELPERS}\([ \t]*)?"
    rf"""(?:__)?require\([ \t]*(["'])(?:node:)?({_MODULES})\2[ \t]*\)"""
    r"(?:[ \t]*,[ \t]*\d[ \t]*\))?[ \t]*\)?(?:\.promises\b)?(?![ \t]*[.(\[])"
)
_IMPORT_BINDING = re.compile(
    rf"(?<![\w$.])import[ \t]+(?:\*[ \t]*as[ \t]+)?({_NAME})"
    r"(?:[ \t]*,[ \t]*\{[^{}]{0,2000}\})?[ \t]+from[ \t]*"
    rf"""(["'])(?:node:)?({_MODULES})\2"""
)


def _bindings(text: str) -> list[tuple[str, str, int]]:
    """``(local name, module, offset)`` for each binding of one of ``_SPELLING``."""
    return [
        (m.group(1), m.group(3), m.start())
        for pattern in (_REQUIRE_BINDING, _IMPORT_BINDING)
        for m in pattern.finditer(text)
    ]


def _site_pattern(names: list[str]) -> re.Pattern[str]:
    receiver = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
    return re.compile(
        r"(?P<wrap>(?<![\w$)\]])\([ \t]*0[ \t]*,[ \t]*)?"
        rf"(?<![\w$.])(?P<name>{receiver})(?![\w$])"
        r"(?P<chain>(?:[ \t]*\.[ \t]*default(?![\w$]))?(?:[ \t]*\.[ \t]*promises(?![\w$]))?)"
        rf"[ \t]*\.[ \t]*(?P<member>{_NAME})(?P<close>[ \t]*\))?(?=[ \t]*\()"
    )


def _rewrite(m: re.Match[str], module: str) -> tuple[int, str] | None:
    """Where one site's rewrite starts and its same-length text, or None to leave it as it is."""
    member = m.group("member")
    closed = m.group("close") is not None
    if closed and m.group("wrap") is None:
        return None  # `wrap(fs_1.readFile)(p)`: the member is passed, not called here
    start = m.start() if closed else m.start("name")  # `(0, f(x))` keeps its own brackets
    spelling = _SPELLING[module]
    if member == "default":
        if module not in _CALLABLE:
            return None
        text = spelling
    elif module in _DEFAULT_ONLY:
        return None
    else:
        text = f"{spelling}.{member}" if spelling else member
    span = m.end() - start
    if len(text) > span or text == m.string[start:m.end()]:
        return None
    return start, " " * (span - len(text)) + text


def call_sites(text: str, code_view: Callable[[], str]) -> list[tuple[int, int, str]]:
    """``(start, end, replacement)`` for each compiled module call in ``text``, in file order.

    ``code_view`` gives the text with comments and strings blanked, same length; it is asked for
    only when a file has a site to rewrite, since nearly every file that binds ``fs`` calls it
    ``fs``.
    """
    if "require" not in text and "import" not in text:
        return []
    bindings = _bindings(text)
    modules: dict[str, set[str]] = {}
    for name, module, _offset in bindings:
        modules.setdefault(name, set()).add(module)
    names = [name for name, found in modules.items() if len(found) == 1]
    if not names:
        return []
    candidates = [
        (m, rewrite)
        for m in _site_pattern(names).finditer(text)
        if (rewrite := _rewrite(m, next(iter(modules[m.group("name")])))) is not None
    ]
    if not candidates:
        return []
    code = code_view()
    live = {name for name, _module, at in bindings if code[at] == text[at]}
    return [
        (start, m.end(), new)
        for m, (start, new) in candidates
        if m.group("name") in live and code[m.start("name")] == text[m.start("name")]
    ]


def fold(text: str, sites: list[tuple[int, int, str]]) -> str:
    """``text`` with each site replaced; offsets and length do not change."""
    pieces: list[str] = []
    pos = 0
    for start, end, new in sites:
        pieces.append(text[pos:start])
        pieces.append(new)
        pos = end
    pieces.append(text[pos:])
    return "".join(pieces)
