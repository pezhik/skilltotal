"""Unit tests for the string-concatenation normalizer (skilltotal/concat_normalize.py).

Folding must (1) collapse adjacent string-literal concatenations so a split literal matches, and
(2) anchor every folded character back to the original source so evidence stays real, and (3)
never invent a literal that is not there (a non-literal operand, or a dynamic template, blocks the
fold).
"""

from __future__ import annotations

import re

from skilltotal.concat_normalize import fold_string_concats
from skilltotal.text_normalize import original_span


def _folded(text: str, suffix: str = ".js") -> str:
    return fold_string_concats(text, suffix)[0]


def test_js_plus_concatenation_is_folded():
    assert _folded('const k = process.env["WALLET_" + "PRIVATE_KEY"];') == (
        'const k = process.env["WALLET_PRIVATE_KEY"];'
    )


def test_three_part_concatenation_is_folded():
    assert _folded("x = '~/' + '.aws/' + 'credentials'") == "x = '~/.aws/credentials'"


def test_python_implicit_adjacency_is_folded():
    assert _folded('p = "~/." "aws/credentials"', ".py") == 'p = "~/.aws/credentials"'


def test_non_literal_operand_blocks_the_fold():
    # prefix + "x" could be anything at runtime; folding would invent a literal.
    assert _folded('x = prefix + "ssh/id_rsa"') == 'x = prefix + "ssh/id_rsa"'


def test_dynamic_template_literal_blocks_the_fold():
    assert _folded('const p = `~/.${a}` + "ssh"') == 'const p = `~/.${a}` + "ssh"'


def test_no_adjacency_is_identity():
    text = 'const p = "hello world"'
    folded, idx = fold_string_concats(text, ".js")
    assert folded == text and len(idx) == 0


def test_quote_inside_a_comment_does_not_desync():
    text = '// "~/." + "x"\nconst k = process.env["WALLET_" + "PRIVATE_KEY"];'
    folded = _folded(text)
    assert '"WALLET_PRIVATE_KEY"' in folded
    # the comment's own split string is untouched
    assert '"~/." + "x"' in folded


def test_index_map_anchors_folded_match_to_original_span():
    text = 'open("~/." + "ssh/id_rsa")'
    folded, idx = fold_string_concats(text, ".js")
    m = re.search(r"~/\.ssh/id_rsa", folded)
    assert m is not None
    start, end = original_span(idx, m.start(), m.end())
    # The original span covers the whole concatenation the match came from.
    assert text[start:end] == '~/." + "ssh/id_rsa'


def test_python_plus_concatenation_is_folded():
    assert _folded("p = '~/.' + 'ssh/id_rsa'", ".py") == "p = '~/.ssh/id_rsa'"


def test_unrelated_language_is_untouched():
    text = 'let s = "a" + "b"'
    assert fold_string_concats(text, ".go") == (text, fold_string_concats(text, ".go")[1])
    assert fold_string_concats(text, ".go")[0] == text
