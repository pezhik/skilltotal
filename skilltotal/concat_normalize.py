"""Deterministic string-concatenation folding for literal matching.

A regex detector matches a *contiguous* literal: ``"~/.ssh/id_rsa"``, ``"WALLET_PRIVATE_KEY"``,
``".cursor/mcp.json"``. An attacker hides that literal from the regex by splitting it across
adjacent string literals that the language concatenates at parse time and that run identically::

    process.env["WALLET_" + "PRIVATE_KEY"]      // JS / TS
    const p = "~/." + "ssh/id_rsa"
    path = "~/." "aws/credentials"               # Python implicit adjacency

None of this changes what the program does; it only defeats byte-for-byte matching, exactly like
the homoglyph / zero-width tricks :mod:`skilltotal.text_normalize` already folds away.

:func:`fold_string_concats` folds each *run of adjacent string literals joined only by ``+`` or
(in Python) whitespace* into one literal holding the concatenated contents, and returns an index
map so a match on the folded text anchors back to the exact span in the ORIGINAL source — the
engine invariant that every finding carries real file/line/snippet evidence.

Conservative by construction (correctness first, then low false positives):

* A run is folded only when EVERY operand is a plain string literal. One non-literal operand
  (``a + "x"``, ``f(x) + "y"``) leaves the whole run untouched — folding across a variable would
  invent a literal that never exists at runtime.
* String *contents* are joined verbatim (quotes and the ``+`` dropped); escapes are not decoded,
  so nothing new is synthesised beyond what the quotes already contained.
* Pure-ASCII with no ``+``-adjacent quote and no adjacent quotes returns identity (empty map),
  the overwhelmingly common case, so normal files pay almost nothing.

Deterministic and dependency-free. It does not evaluate code or resolve variables; cross-statement
reconstruction (``a = "W"; a += "P"``) is out of scope and belongs to the paid dynamic layer.
"""

from __future__ import annotations

import re
from array import array
from collections.abc import Sequence

# Files whose string concatenation uses ``+`` (and, in Python, bare adjacency). Other languages
# have their own splicing, handled where relevant; folding is scoped to where the attack appears.
_JS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})
_PY_SUFFIXES = frozenset({".py", ".pyw"})
_FOLDABLE_SUFFIXES = _JS_SUFFIXES | _PY_SUFFIXES

# A quick pre-check: only files that actually adjoin two string literals can change. Either a
# quote with only whitespace/`+` before the next quote. Cheap to over-accept; the real work runs
# only when this matches.
_HAS_ADJACENCY = re.compile(r"""["'`]\s*\+?\s*["'`]""")


def _string_tokens(text: str, js: bool) -> list[tuple[int, int, int, int]]:
    """Return string-literal spans as ``(open_quote, content_start, content_end, close_quote_end)``.

    Best-effort, stdlib-only, mirroring the lexer in file_index._c_code_spans but recording the
    content bounds (inside the quotes). A ``'``/``"`` literal ends at an unescaped matching quote
    or a newline; backtick/triple-quoted may span lines. A template literal containing ``${`` is
    dynamic and is skipped (returned as a token with a sentinel so callers do not fold it).
    """
    toks: list[tuple[int, int, int, int]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        # Skip line and block comments so a quote inside them is not treated as a string.
        if c == "#" and not js:
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if js and c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if js and c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c in ("'", '"') and text[i : i + 3] == c * 3:  # triple-quoted (Python; harmless in JS)
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
                if ch == "\\":
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


def _only_join_between(text: str, a_end: int, b_start: int, js: bool) -> bool:
    """True if the gap between two string literals is only a concatenation join.

    JS: optional whitespace, exactly one ``+``, optional whitespace. Python: the same, OR pure
    whitespace (implicit adjacency ``"a" "b"``) with no newline-continuation ambiguity handled by
    the caller. Any other character (``,`` ``)`` ``[`` another operand) means they are not a
    single concatenation and must not be folded.
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
    return not js and gap.strip() == ""


def fold_string_concats(text: str, suffix: str) -> tuple[str, Sequence[int]]:
    """Return ``(folded_text, index_map)`` with adjacent string-literal concatenations collapsed.

    ``index_map[i]`` is the offset in ``text`` of the character that produced ``folded[i]``.
    Returns ``(text, [])`` unchanged when there is nothing to fold (identity), which callers treat
    as "no folded view" exactly like :func:`skilltotal.text_normalize.normalize_with_map`.
    """
    empty: array[int] = array("I")
    if suffix not in _FOLDABLE_SUFFIXES or not _HAS_ADJACENCY.search(text):
        return text, empty
    js = suffix in _JS_SUFFIXES
    toks = _string_tokens(text, js)
    if not toks:
        return text, empty

    # Group tokens into maximal concatenation runs (each run folds to one literal).
    runs: list[list[tuple[int, int, int, int]]] = []
    cur: list[tuple[int, int, int, int]] = []
    for tok in toks:
        if not cur:
            cur = [tok]
            continue
        prev = cur[-1]
        # A dynamic template (content_start == open_quote) breaks a run: it is not a plain literal.
        plain_prev = prev[1] != prev[0]
        plain_cur = tok[1] != tok[0]
        if plain_prev and plain_cur and _only_join_between(text, prev[3], tok[0], js):
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
        quote = text[run[0][0]]
        out.append(quote)
        idx.append(run[0][0])
        for _open_q, c_start, c_end, _close in run:
            out.append(text[c_start:c_end])
            idx.extend(range(c_start, c_end))
        out.append(quote)
        idx.append(run[-1][3] - 1 if run[-1][3] > run[-1][2] else run[-1][2])
        pos = run_end
    if pos < len(text):
        out.append(text[pos:])
        idx.extend(range(pos, len(text)))
    folded = "".join(out)
    if folded == text:
        return text, empty
    return folded, idx
