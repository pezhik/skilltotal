"""Deterministic string-concatenation folding for literal matching.

A regex detector matches a *contiguous* literal: ``"~/.ssh/id_rsa"``, ``"WALLET_PRIVATE_KEY"``,
``".cursor/mcp.json"``. An attacker hides that literal from the regex by splitting it across
adjacent string literals that the language concatenates at parse time and that run identically::

    process.env["WALLET_" + "PRIVATE_KEY"]      // JS / TS
    const p = "~/." + "ssh/id_rsa"
    path = "~/." "aws/credentials"               # Python implicit adjacency
    $key = $hive + "\\" + "Run"                  # PowerShell, $hive bound once to a literal

None of this changes what the program does; it only defeats byte-for-byte matching, exactly like
the homoglyph / zero-width tricks :mod:`skilltotal.text_normalize` already folds away.

:func:`fold_string_concats` folds each *run of adjacent string literals joined only by ``+`` or
(in Python) whitespace* into one literal holding the concatenated contents, and returns an index
map so a match on the folded text anchors back to the exact span in the ORIGINAL source — the
engine invariant that every finding carries real file/line/snippet evidence.

Conservative by construction (correctness first, then low false positives):

* A run is folded only when EVERY operand is a plain string literal, or a name the file binds
  exactly once, to a string spelled out in literals (:func:`bound_strings`). Any other operand
  (``a + "x"`` with ``a`` assigned twice or from a call, ``f(x) + "y"``) leaves the whole run
  untouched — folding across a variable whose value is not fixed would invent a literal that never
  exists at runtime.
* String *contents* are joined verbatim (quotes and the ``+`` dropped); escapes are not decoded,
  so nothing new is synthesised beyond what the quotes already contained.
* Pure-ASCII with no ``+``-adjacent quote and no adjacent quotes returns identity (empty map),
  the overwhelmingly common case, so normal files pay almost nothing.

Deterministic and dependency-free. It does not evaluate code; the only cross-statement step is the
single-assignment binding above (``a = "W"; a += "P"`` assigns ``a`` twice and is not followed).
"""

from __future__ import annotations

import bisect
import re
from array import array
from collections.abc import Sequence

# Files whose string concatenation uses ``+`` (and, in Python, bare adjacency). Other languages
# have their own splicing, handled where relevant; folding is scoped to where the attack appears.
_JS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})
_PY_SUFFIXES = frozenset({".py", ".pyw"})
_PS_SUFFIXES = frozenset({".ps1", ".psm1"})
_FOLDABLE_SUFFIXES = _JS_SUFFIXES | _PY_SUFFIXES | _PS_SUFFIXES

# A quick pre-check: only files that actually adjoin two string literals, or a string literal and
# a `+`, can change. Cheap to over-accept; the real work runs only when this matches. Whitespace
# runs are BOUNDED so a crafted file (a quote followed by a megabyte of spaces) cannot make this
# gate backtrack — a static scanner must not be DoS-able by the thing it scans. A concat with >80
# whitespace chars between operands simply is not folded.
_HAS_ADJACENCY = re.compile(r"""["'`]\s{0,80}\+?\s{0,80}["'`]|\+\s{0,80}["'`]""")

# A string token: ``(open_quote, content_start, content_end, close_quote_end)``. A dynamic
# template literal has ``content_start == open_quote``.
_Token = tuple[int, int, int, int]


def _lang(suffix: str) -> str:
    if suffix in _JS_SUFFIXES:
        return "js"
    if suffix in _PS_SUFFIXES:
        return "ps"
    return "py"


def _string_tokens(
    text: str, lang: str, comments: list[tuple[int, int]] | None = None
) -> list[_Token]:
    """Return string-literal spans as ``(open_quote, content_start, content_end, close_quote_end)``.

    Best-effort, stdlib-only, mirroring the lexer in file_index._c_code_spans but recording the
    content bounds (inside the quotes). A ``'``/``"`` literal ends at an unescaped matching quote
    or a newline; backtick/triple-quoted may span lines. A template literal containing ``${`` (or a
    PowerShell double-quoted string that expands a ``$variable``) is dynamic and is returned as a
    token with ``content_start == open_quote`` so callers do not fold it. Comment spans are
    appended to ``comments`` when given.
    """
    js, ps = lang == "js", lang == "ps"
    toks: list[_Token] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        # Skip line and block comments so a quote inside them is not treated as a string.
        if (c == "#" and not js) or (js and c == "/" and text[i + 1 : i + 2] == "/"):
            j = text.find("\n", i)
            end = n if j < 0 else j
            if comments is not None:
                comments.append((i, end))
            i = end
            continue
        if (js and c == "/" and text[i + 1 : i + 2] == "*") or (ps and text[i : i + 2] == "<#"):
            close = "*/" if js else "#>"
            j = text.find(close, i + 2)
            end = n if j < 0 else j + 2
            if comments is not None:
                comments.append((i, end))
            i = end
            continue
        if ps and c == "@" and text[i + 1 : i + 2] in ("'", '"'):
            # A here-string runs to a line that starts with the closing `"@` / `'@`: never folded.
            close = "\n" + text[i + 1] + "@"
            j = text.find(close, i + 2)
            end = n if j < 0 else j + len(close)
            toks.append((i, i, end, end))
            i = end
            continue
        if not ps and c in ("'", '"') and text[i : i + 3] == c * 3:  # triple-quoted (Python)
            open_q = i
            end = text.find(c * 3, i + 3)
            content_end = n if end < 0 else end
            close_end = n if end < 0 else end + 3
            toks.append((open_q, i + 3, content_end, close_end))
            i = close_end
            continue
        if c in ("'", '"') or (js and c == "`"):
            open_q = i
            i += 1
            dynamic = False
            while i < n:
                ch = text[i]
                if ps:
                    # PowerShell: a backtick escapes inside "..."; a doubled quote is one quote;
                    # a backslash is an ordinary character (`"\"` is one backslash).
                    if ch == "`" and c == '"':
                        i += 2
                        continue
                    if ch == c and text[i + 1 : i + 2] == c:
                        i += 2
                        continue
                    if c == '"' and ch == "$" and re.match(r"[\w{(:]", text[i + 1 : i + 2]):
                        dynamic = True
                elif ch == "\\":
                    i += 2
                    continue
                if ch == c:
                    break
                if ch == "\n" and c != "`":
                    break
                if js and c == "`" and ch == "$" and text[i + 1 : i + 2] == "{":
                    dynamic = True
                i += 1
            content_end = min(i, n)
            close_end = min(i + 1, n) if i < n and text[i] == c else content_end
            # A template literal with interpolation is not a plain literal: mark start == end so
            # it never joins a fold (its content is dynamic).
            toks.append((open_q, open_q if dynamic else open_q + 1, content_end, close_end))
            i = close_end
            continue
        i += 1
    return toks


def _only_join_between(text: str, a_end: int, b_start: int, js: bool, plus: bool = False) -> bool:
    """True if the gap between two string literals is only a concatenation join.

    JS: optional whitespace, exactly one ``+``, optional whitespace. Python: the same, OR pure
    whitespace (implicit adjacency ``"a" "b"``) with no newline-continuation ambiguity handled by
    the caller. Any other character (``,`` ``)`` ``[`` another operand) means they are not a
    single concatenation and must not be folded. ``plus`` requires the ``+`` (a bound name is
    joined to a literal only by ``+``, never by adjacency).
    """
    gap = text[a_end:b_start]
    if gap.count("+") > 1:
        return False
    stripped = gap.replace("+", "", 1).strip() if "+" in gap else gap.strip()
    if stripped != "":
        return False
    if "+" in gap:
        return True
    # No '+': only Python concatenates by bare adjacency; JS does not.
    return not js and not plus and gap.strip() == ""


# --- names bound once to a string ------------------------------------------------------------

# Every assignment to a name, compound ones included: a name assigned more than once (or added
# to) has no single value. Keyword arguments and default parameters (`f(name="x")`) are counted
# too, which only ever makes a name ambiguous: conservative.
_ASSIGNMENT = {
    "js": re.compile(
        r"(?<![\w$.])([A-Za-z_$][\w$]{0,60})\s*(?:[-+*/%&|^]|\*\*|<<|>>>?|\?\?|&&|\|\|)?=(?![=>])"
    ),
    "py": re.compile(r"(?<![\w.])([A-Za-z_]\w{0,60})\s*(?:[-+*/%&|^@]|//|\*\*|<<|>>)?=(?!=)"),
    "ps": re.compile(r"\$([A-Za-z_]\w{0,60})\s*[-+*/%]?=(?!=)"),
}
# The head of a binding statement, the value starting at the end of the match.
_BINDING = {
    "js": re.compile(
        r"(?:(?<![\w$.])(?:const|let|var)\s+|(?:^|(?<=[;{}]))[ \t]*)([A-Za-z_$][\w$]{0,60})"
        r"\s*=(?![=>])\s*",
        re.MULTILINE,
    ),
    "py": re.compile(r"^[ \t]*([A-Za-z_]\w{0,60})[ \t]*=(?!=)[ \t]*", re.MULTILINE),
    "ps": re.compile(r"(?:^|(?<=;))[ \t]*\$([A-Za-z_]\w{0,60})[ \t]*=(?!=)[ \t]*", re.MULTILINE),
}
# What may follow a binding's value: the end of the statement.
_STATEMENT_END = re.compile(r"[ \t]*(?:$|;|\r|\n|#|//)")
# A name used as an operand of `+` next to a string literal (not a member, a call or an index):
# the only uses a binding is substituted into. Found by one pass over the file, whatever the
# number of names it binds.
_IDENT = {"js": r"[A-Za-z_$][\w$]{0,60}", "py": r"[A-Za-z_]\w{0,60}", "ps": r"\$[A-Za-z_]\w{0,60}"}
_OPERAND_USE = {
    lang: re.compile(
        rf"(?<![\w$.])({ident})\s{{0,80}}\+\s{{0,80}}(?=[\"'`])"
        rf"|(?<=[\"'`])\s{{0,80}}\+\s{{0,80}}({ident})(?![\w$])(?!\s*[(\[.`])"
    )
    for lang, ident in _IDENT.items()
}
_JOIN_CALL = re.compile(r"\s*\.\s*join\s*\(\s*")
_PLUS_GAP = re.compile(r"[ \t]*\+?[ \t]*")


class _Tokens:
    """The string tokens and comments of one file, for lookups by offset."""

    def __init__(self, text: str, lang: str) -> None:
        self.text = text
        self.lang = lang
        self.comments: list[tuple[int, int]] = []
        self.toks = _string_tokens(text, lang, self.comments)
        self.by_open = {t[0]: t for t in self.toks}
        spans = sorted([(t[0], t[3]) for t in self.toks] + self.comments)
        self.starts = [s for s, _ in spans]
        self.spans = spans

    def inside(self, offset: int) -> bool:
        """True if ``offset`` is inside a string literal or a comment."""
        k = bisect.bisect_right(self.starts, offset) - 1
        return k >= 0 and self.spans[k][0] <= offset < self.spans[k][1]

    def plain_at(self, offset: int) -> _Token | None:
        tok = self.by_open.get(offset)
        return tok if tok is not None and tok[1] != tok[0] else None

    def value_at(self, pos: int) -> tuple[str, int] | None:
        """The string a value starting at ``pos`` spells out in literals, and where it ends: a
        literal, literals joined by ``+`` (or Python adjacency), or a list of literals joined with
        a literal separator (``["a", "b"].join("")``, ``"".join(["a", "b"])``)."""
        text, no_adjacency = self.text, self.lang != "py"
        tok = self.plain_at(pos)
        if tok is None and text[pos : pos + 1] in "[(" and self.lang != "ps":
            return self._array_join(pos)
        if tok is None:
            return None
        parts = [text[tok[1] : tok[2]]]
        end = tok[3]
        while True:
            nxt = self.plain_at(_PLUS_GAP.match(text, end).end())  # type: ignore[union-attr]
            if nxt is None or not _only_join_between(text, end, nxt[0], no_adjacency):
                break
            parts.append(text[nxt[1] : nxt[2]])
            end = nxt[3]
        # `"sep".join([...])` (Python)
        join = _JOIN_CALL.match(text, end)
        if join is not None and len(parts) == 1 and self.lang == "py":
            joined = self._literal_list(join.end())
            if joined is None:
                return None
            items, close = joined
            if text[close : close + 1] != ")":
                return None
            return parts[0].join(items), close + 1
        return "".join(parts), end

    def _literal_list(self, pos: int) -> tuple[list[str], int] | None:
        """``["a", "b"]`` / ``("a", "b")`` at ``pos``: the literals, and the offset after it."""
        text = self.text
        if text[pos : pos + 1] not in "[(":
            return None
        closer = "]" if text[pos] == "[" else ")"
        items: list[str] = []
        i = pos + 1
        while True:
            i = _skip_ws(text, i)
            if text[i : i + 1] == closer:
                return items, i + 1
            tok = self.plain_at(i)
            if tok is None:
                return None
            items.append(text[tok[1] : tok[2]])
            i = _skip_ws(text, tok[3])
            if text[i : i + 1] == ",":
                i += 1
            elif text[i : i + 1] != closer:
                return None

    def _array_join(self, pos: int) -> tuple[str, int] | None:
        """``["a", "b"].join("")`` (JS): the joined string and the offset after the call."""
        listed = self._literal_list(pos)
        if listed is None or self.lang != "js":
            return None
        items, end = listed
        join = _JOIN_CALL.match(self.text, end)
        if join is None:
            return None
        i = join.end()
        sep = ","
        tok = self.plain_at(i)
        if tok is not None:
            sep = self.text[tok[1] : tok[2]]
            i = _skip_ws(self.text, tok[3])
        if self.text[i : i + 1] != ")":
            return None
        return sep.join(items), i + 1


def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    return i


def _assignment_counts(tokens: _Tokens) -> dict[str, int]:
    counts: dict[str, int] = {}
    for m in _ASSIGNMENT[tokens.lang].finditer(tokens.text):
        if not tokens.inside(m.start()):
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return counts


def assigned_once(text: str, suffix: str) -> frozenset[str]:
    """Names this file assigns exactly once (counting compound assignments, outside strings and
    comments): the names whose one value a reader can take from that single assignment."""
    if suffix not in _FOLDABLE_SUFFIXES:
        return frozenset()
    counts = _assignment_counts(_Tokens(text, _lang(suffix)))
    return frozenset(name for name, count in counts.items() if count == 1)


def _bindings(tokens: _Tokens) -> dict[str, tuple[str, int]]:
    text, lang = tokens.text, tokens.lang
    counts = _assignment_counts(tokens)
    bound: dict[str, tuple[str, int]] = {}
    for m in _BINDING[lang].finditer(text):
        name = m.group(1)
        if counts.get(name) != 1 or tokens.inside(m.start(1)):
            continue
        value = tokens.value_at(m.end())
        if value is None or not _STATEMENT_END.match(text, value[1]):
            continue
        bound[name] = (value[0], m.end())
    return bound


def bound_strings(text: str, suffix: str) -> dict[str, tuple[str, int]]:
    """Names this file assigns exactly once, to a string spelled out in literals: ``name ->
    (value, offset where the value starts)``. A literal, literals joined by ``+``, or a list of
    literals joined with a literal separator. PowerShell names are given without the ``$``.

    Shared by the scanners that need a value an attacker moved one assignment away from where it
    is used (an encoding name, a CLI flag's value): the name has exactly one value at runtime.
    """
    if suffix not in _FOLDABLE_SUFFIXES or not any(q in text for q in "'\"`"):
        return {}
    return _bindings(_Tokens(text, _lang(suffix)))


def fold_string_concats(text: str, suffix: str) -> tuple[str, Sequence[int]]:
    """Return ``(folded_text, index_map)`` with adjacent string-literal concatenations collapsed.

    ``index_map[i]`` is the offset in ``text`` of the character that produced ``folded[i]``.
    Returns ``(text, [])`` unchanged when there is nothing to fold (identity), which callers treat
    as "no folded view" exactly like :func:`skilltotal.text_normalize.normalize_with_map`.
    """
    empty: array[int] = array("I")
    if suffix not in _FOLDABLE_SUFFIXES or not _HAS_ADJACENCY.search(text):
        return text, empty
    lang = _lang(suffix)
    no_adjacency = lang != "py"  # only Python joins literals written side by side
    tokens = _Tokens(text, lang)
    toks = list(tokens.toks)
    if not toks:
        return text, empty

    # A name bound once to a literal is an operand of its value (`$hive + "\" + "Run"`).
    values: dict[int, str] = {}  # open offset of a name token -> its value
    uses = []
    for m in _OPERAND_USE[lang].finditer(text):
        group = m.lastindex or 1
        if not tokens.inside(m.start(group)):
            uses.append((m.start(group), m.end(group), m.group(group)))
    bound = _bindings(tokens) if uses else {}
    for start, end, name in uses:
        value = bound.get(name[1:] if lang == "ps" else name)
        if value is not None and start not in values:
            values[start] = value[0]
            toks.append((start, start, end, end))
    if values:
        toks.sort()

    # Group tokens into maximal concatenation runs (each run folds to one literal).
    runs: list[list[_Token]] = []
    cur: list[_Token] = []
    for tok in toks:
        if not cur:
            cur = [tok]
            continue
        prev = cur[-1]
        # A dynamic template (content_start == open_quote) breaks a run: it is not a plain literal.
        plain_prev = prev[1] != prev[0] or prev[0] in values
        plain_cur = tok[1] != tok[0] or tok[0] in values
        plus = prev[0] in values or tok[0] in values
        if plain_prev and plain_cur and _only_join_between(
            text, prev[3], tok[0], no_adjacency, plus
        ):
            cur.append(tok)
        else:
            runs.append(cur)
            cur = [tok]
    if cur:
        runs.append(cur)

    if not any(len(r) > 1 for r in runs):
        return text, empty  # no actual concatenation to fold

    out: list[str] = []
    idx: array[int] = array("I")
    pos = 0
    for run in runs:
        if len(run) < 2:
            continue
        run_start = run[0][0]
        run_end = run[-1][3]
        # Copy verbatim source before this run.
        if run_start > pos:
            out.append(text[pos:run_start])
            idx.extend(range(pos, run_start))
        # Emit one synthetic quote (maps to the run's opening quote) so string-context checks on
        # the folded text still see a quoted literal, then the joined contents, then a close quote.
        quote = next((text[t[0]] for t in run if t[0] not in values), '"')
        out.append(quote)
        idx.append(run[0][0])
        for open_q, c_start, c_end, _close in run:
            if open_q in values:
                # A bound name contributes its value, every character anchored on the name.
                value = values[open_q]
                out.append(value)
                idx.extend(min(open_q + k, c_end - 1) for k in range(len(value)))
            else:
                out.append(text[c_start:c_end])
                idx.extend(range(c_start, c_end))
        out.append(quote)
        last = run[-1]
        idx.append(last[3] - 1 if last[3] > last[2] or last[0] in values else last[2])
        pos = run_end
    if pos < len(text):
        out.append(text[pos:])
        idx.extend(range(pos, len(text)))
    folded = "".join(out)
    if folded == text:
        return text, empty
    return folded, idx
