"""Node.js: the text of a network response reaches a call that runs it.

``eval(await (await fetch(url)).text())`` written out is one expression. The same thing is usually
spread over a promise chain or a response callback, with the sink spelled indirectly::

    fetch(url).then((r) => r.text()).then((t) => (0, eval)(t));
    https.get(url, (res) => { let d = ""; res.on("data", (c) => (d += c));
                              res.on("end", () => vm.runInThisContext(d)); });
    const g = globalThis, k = ["e", "v", "a", "l"].join("");  ...  g[k](body)

:func:`fetched_text_sinks` links a request to a sink in the same file when the response gets
there: inside the sink's own argument, through names assigned from it (the flow the
decode-and-spawn rule already follows, see ``obfuscation._DecodeFlow``), through a parameter of the
function around the sink, or through the parameters of the callbacks of the request's own
statement. A request and a sink that merely share a file are not linked.

The caller says which sinks it means: dynamic-code sinks here (:func:`code_sink_heads`), the
``child_process`` calls in ``shell_exec``. Pattern matching only; nothing is run.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from itertools import islice

from skilltotal.concat_normalize import assigned_once, bound_strings
from skilltotal.file_index import IndexedFile
from skilltotal.scanners.obfuscation import (
    _FLOW_REACH,
    _JS_ASSIGNMENT,
    _JS_SINK_HANDLE,
    _MAX_CODE_TRIES,
    _balanced_end,
    _DecodeFlow,
    _expression_names,
    _names,
    _sink_aliases,
    _span,
    _starts_a_word,
    _view,
)

NODE_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

_IDENT = r"[A-Za-z_$][\w$]{0,60}"
# A request whose response the file reads. `fetch` counts bare or on the global object (a
# `cache.fetch(` or `git.fetch(` is something else); the module calls are spelled as the source
# wrote them (the compiled forms are read through IndexedFile.interop_view).
_SOURCE = re.compile(
    r"fetch\s*\("
    r"|axios\s*(?:\.\s*(?:get|post|request)\s*)?\("
    r"|got\s*(?:\.\s*(?:get|post)\s*)?\("
    r"|https?\s*\.\s*(?:get|request)\s*\("
    r"|require\(\s*[\"'](?:node:)?https?[\"']\s*\)\s*\.\s*(?:get|request)\s*\("
    r"|undici\s*\.\s*(?:request|fetch)\s*\("
)
_SOURCE_TOKENS = ("fetch", "axios", "got", "http", "undici")
_FETCH_OWNERS = ("globalThis.", "window.", "self.", "undici.", "global.")
_GOT_IMPORT = re.compile(r"[\"']got[\"']")
_MAX_SOURCES = 16

# Dynamic-code sinks: eval and the Function constructor written out or reached indirectly
# (`(0, eval)`, `globalThis["eval"]`, a constructor chain), and the vm module's runners.
_CODE_SINK = rf"{_JS_SINK_HANDLE}|vm\s*\.\s*Script|runIn(?:This|New)Context"
_GLOBAL_OBJECTS = ("globalThis", "global", "window", "self")
_GLOBAL_BINDING = re.compile(
    rf"(?:const|let|var)\s+({_IDENT})\s*=\s*(?:{'|'.join(_GLOBAL_OBJECTS)})\s*(?=[;,\n\r])"
)
_CODE_NAMES = frozenset({"eval", "Function"})
# A name bound to eval itself (written out, indirect, or looked up on the global object).
_EVAL_BINDING = re.compile(
    rf"(?:const|let|var)\s+({_IDENT})\s*=\s*(?:\(\s*0\s*,\s*eval\s*\)|eval"
    rf"|(?:{'|'.join(_GLOBAL_OBJECTS)})\s*(?:\.\s*eval|\[\s*['\"`]eval['\"`]\s*\]))\s*(?=[;\n\r])"
)
# `owner[key](`: starts with a literal bracket, so the regex engine skips to the few places one
# can begin; the owner is read off the text in front of it.
_INDEXED_CALL = re.compile(rf"\[\s*({_IDENT})\s*\]\s*\(")
_OWNER = re.compile(rf"(?<![\w$.])({_IDENT})\s*$")
# The words a sink is spelled with; a file's joined view is read only where it has more of them.
_SINK_WORDS = ("eval", "Function", "exec", "child_process", "runIn", "Script", "constructor")
# Matches of the sink patterns looked at per view; `_MAX_CODE_TRIES` of them are kept.
_MAX_SINK_TRIES = 4000
_OPEN = re.compile(r"\s*\(")
_TAKES_BODY_LAST = re.compile(r"Function|constructor")

# The parameters of the callbacks in a statement: `(a, b) =>`, `a =>`, `function (a, b)`.
_CALLBACK_PARAMS = re.compile(
    rf"\(([^()]{{0,200}})\)\s*=>|(?<![\w$.])({_IDENT})\s*=>|function\s*[\w$]*\s*\(([^()]{{0,200}})\)"
)
_PUSH = re.compile(rf"(?<![\w$.])({_IDENT})\s*\.\s*push\s*\(")
# `const { data } = await axios.get(url)`: the names a destructuring binds, the value starting at
# the end of the match.
_DESTRUCTURED = re.compile(r"(?:const|let|var)\s*\{([^{}]{1,200})\}\s*=\s*(?:await\s+)?\(?")
_PLAIN_NAME = re.compile(_IDENT)


def code_sink_heads(f: IndexedFile, text: str) -> str | None:
    """The dynamic-code sinks of ``f`` as one alternation over ``text`` (the file, or its view
    with spliced string literals joined): the fixed forms, a name bound once to one of them
    (`const run = eval`), and the global object indexed by a name that spells one
    (`g[k]` with `g = globalThis`, `k = ["e", "v", "a", "l"].join("")`)."""
    return "|".join(f"(?:{h})" for h in (_CODE_SINK, *_named_sink_heads(f, text)))


def _named_sink_heads(f: IndexedFile, text: str, *, eval_only: bool = False) -> list[str]:
    """The sinks of ``f`` that go by a name the file chose: see :func:`code_sink_heads`. With
    ``eval_only`` a name bound to the Function constructor is left out."""
    aliases = _sink_aliases(f, text)
    if aliases and eval_only:
        to_eval = {m.group(1) for m in _EVAL_BINDING.finditer(text)}
        aliases = [a for a in aliases if a in to_eval]
    heads = [re.escape(a) for a in aliases]
    if not any(g in text for g in _GLOBAL_OBJECTS):
        return heads
    # A call through an object indexed by a bare name (`g[k](`) is uncommon; only a file that has
    # one on the global object pays for reading what its names are bound to.
    indexed: dict[str, set[str]] = {}
    for m in islice(_INDEXED_CALL.finditer(text), _MAX_SINK_TRIES):
        owner = _OWNER.search(text, max(0, m.start() - 64), m.start())
        if owner is not None:
            indexed.setdefault(owner.group(1), set()).add(m.group(1))
    if not indexed:
        return heads
    objects = set(_GLOBAL_OBJECTS)
    if not objects.issuperset(indexed):
        objects.update(m.group(1) for m in _GLOBAL_BINDING.finditer(text))
    keys = {key for owner, found in indexed.items() if owner in objects for key in found}
    if not keys:
        return heads
    # Reading what a name is bound to tokenizes the file: only now, for the few files that
    # index the global object (or a name bound to it) by a bare name and call the result.
    bound = bound_strings(f.text, f.suffix)
    keys = {k for k in keys if k in bound and bound[k][0] in _CODE_NAMES}
    if keys:
        once = assigned_once(f.text, f.suffix)
        owners = sorted(o for o in objects if o in _GLOBAL_OBJECTS or o in once)
        heads.append(rf"(?:{_names(owners)})\s*\[\s*(?:{_names(sorted(keys))})\s*\]")
    return heads


def _indirect_heads(f: IndexedFile, text: str) -> str:
    """eval reached without an `eval(` token, and the vm runners ST-DYN-NODE's own pattern leaves
    out. A form is looked for only in a text that holds its fixed word. A name bound to the
    Function constructor is not one of them: `const F = Function` is how a schema compiler or a
    polyfill reaches it (bundled zod, get-intrinsic), often only to probe with an empty body that
    ST-DYN-NODE leaves out on purpose; such a name is still a sink for a fetched response."""
    heads = _named_sink_heads(f, text, eval_only=True)
    if "eval" in text:
        heads.append(r"\(\s*0\s*,\s*eval\s*\)")
        heads.append(rf"(?:{'|'.join(_GLOBAL_OBJECTS)})\s*\[\s*['\"`]eval['\"`]\s*\]")
    if "vm" in text:
        heads.append(r"vm\s*\.\s*(?:Script|runInContext|compileFunction)")
    return "|".join(f"(?:{h})" for h in heads)


def indirect_code_sink_spans(f: IndexedFile) -> list[tuple[int, int]]:
    """The dynamic-code calls of ``f`` that the plain ``eval(`` / ``new Function(`` /
    ``vm.runIn...Context(`` patterns do not read: the indirect call ``(0, eval)(x)``, eval looked
    up on the global object by a quoted, spliced or bound name, a name bound to a sink, and the
    other vm runners."""
    return [(start, end)
            for start, end, _args in _sink_sites(f, f.interop_view(), _indirect_heads)]


def _is_source(text: str, m: re.Match[str]) -> bool:
    start = m.start()
    if text.startswith("fetch", start):
        if start and text[start - 1] == ".":
            return text.endswith(_FETCH_OWNERS, max(0, start - 12), start)
        return _starts_a_word(text, start, "_$")
    if text.startswith("got", start):
        return _starts_a_word(text, start, "_$.") and _GOT_IMPORT.search(text) is not None
    return _starts_a_word(text, start, "_$.")


def _in_code(f: IndexedFile, at: int) -> bool:
    return not (f.in_c_comment(at) or f.in_c_string(at))


def _sources(f: IndexedFile, text: str) -> list[tuple[int, int]]:
    found = []
    for m in islice(_SOURCE.finditer(text), _MAX_CODE_TRIES):
        if _is_source(text, m) and _in_code(f, m.start()):
            found.append((m.start(), m.end()))
            if len(found) >= _MAX_SOURCES:
                break
    return found


def _sink_sites(
    f: IndexedFile, text: str, heads: Callable[[IndexedFile, str], str | None]
) -> list[tuple[int, int, int]]:
    """``(start, end, arguments start)`` of each sink call in ``f``, as spans of ``text`` (the
    file's compiled-call view, which has the file's own offsets). Sinks are also read on the view
    with spliced string literals joined, and mapped back."""
    sites: dict[int, tuple[int, int, int]] = {}
    views: list[tuple[str, Sequence[int] | None]] = [(text, None)]
    folded_text, idx = _view(f)
    # The joined view shows another sink only where joining literals spelled one of their words.
    if idx is not None and any(folded_text.count(w) != text.count(w) for w in _SINK_WORDS):
        views.append((folded_text, idx))
    for view, origin in views:
        alternation = heads(f, view)
        if not alternation:
            continue
        for m in islice(re.compile(alternation).finditer(view), _MAX_SINK_TRIES):
            if not _starts_a_word(view, m.start(), "_$."):
                continue
            start, end = _span(origin, m.start(), m.end())
            opened = _OPEN.match(text, end)
            if opened is None or start in sites or not _in_code(f, start):
                continue
            sites[start] = (start, end, opened.end())
            if len(sites) >= _MAX_CODE_TRIES:
                break
    return sorted(sites.values())


def _first_argument_end(text: str, start: int, close: int) -> int:
    """Where the first argument of a call ends (its arguments are ``text[start:close]``)."""
    depth, quote, i = 0, "", start
    while i < close:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return i
        i += 1
    return close


def _callback_names(text: str, start: int, end: int) -> set[str]:
    """The names that hold what the callbacks of the statement ``text[start:end]`` are given: the
    callbacks' parameters, and the names in that statement assigned or appended from them
    (`d += chunk`, `chunks.push(chunk)`, `const body = Buffer.concat(chunks).toString()`)."""
    names: set[str] = set()
    for m in _CALLBACK_PARAMS.finditer(text, start, end):
        names.update(_PLAIN_NAME.findall(m.group(1) or m.group(2) or m.group(3) or ""))
    if not names:
        return names
    assignments = [(m.group(1), m.end()) for m in _JS_ASSIGNMENT.finditer(text, start, end)]
    assignments += [(m.group(1), m.end()) for m in _PUSH.finditer(text, start, end)]
    for _ in range(3):
        grown = False
        for name, value in assignments:
            if name in names:
                continue
            stop = min(_balanced_end(text, value, statement=True), end)
            if _expression_names(text[value:stop]) & names:
                names.add(name)
                grown = True
        if not grown:
            break
    return names


def fetched_text_sinks(
    f: IndexedFile,
    heads: Callable[[IndexedFile, str], str | None],
    *,
    whole_argument: bool = False,
) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    """``(request span, sink span)`` for each sink of ``f`` that is given the response of a
    request the same file makes. ``heads`` names the sinks: it returns one regex alternation of
    call heads for a view of the file. With ``whole_argument`` the response must be the argument
    itself, not a value quoted into a longer string (a command line built around a version number
    read from a registry is not the response run as a command)."""
    if f.suffix not in NODE_SUFFIXES:
        return []
    text = f.interop_view()
    if not any(t in text for t in _SOURCE_TOKENS):
        return []
    sources = _sources(f, text)
    if not sources:
        return []
    sinks = _sink_sites(f, text, heads)
    if not sinks:
        return []
    flow = _DecodeFlow(text, sources, reach=_FLOW_REACH)
    flow.follow()
    for m in _DESTRUCTURED.finditer(text):
        origin = next((s for s in sources if s[0] == m.end()), None)
        if origin is not None:
            for name in _PLAIN_NAME.findall(re.sub(rf"{_IDENT}\s*:", "", m.group(1))):
                flow.hold(name, m.end(), origin)
    statements = [(start, _balanced_end(text, start, statement=True), (start, end))
                  for start, end in sources]
    callback_names: dict[int, set[str]] = {}
    found = []
    for start, end, args in sinks:
        close = _balanced_end(text, args)
        # The text a sink runs is its first argument; the Function constructor takes it last.
        if whole_argument or not _TAKES_BODY_LAST.search(text, start, end):
            close = _first_argument_end(text, args, close)
        argument = text[args:close]
        # A code sink runs the response however it is wrapped (`eval("(" + body + ")")` runs any
        # expression); a command line built around a value is a different thing from the value.
        if whole_argument and any(q in argument for q in "'\"`"):
            continue
        origin = flow.reaches_launch(start, args, close)
        if origin is None:
            read = _expression_names(argument)
            for lo, hi, source in statements:
                if not lo < start < hi:
                    continue
                if lo not in callback_names:
                    callback_names[lo] = _callback_names(text, lo, hi)
                if read & callback_names[lo]:
                    origin = source
                    break
        if origin is not None:
            found.append((origin, (start, end)))
    return found
