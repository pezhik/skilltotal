"""What a terminal does not show of a line of text.

A file printed in a terminal (``cat SKILL.md``, a diff, a pager without ``-R`` filtering) is drawn
by the terminal, and a handful of control sequences make it draw less than the file holds, while a
model or a shell still reads every byte:

* an **OSC** sequence (``ESC ]`` ... ``BEL`` or ``ESC \\``): a window title, or the address of an
  OSC 8 hyperlink. The payload is never drawn. So are the other string sequences (DCS, APC, PM,
  SOS);
* **SGR** attributes that conceal (8) or set the same foreground and background colour, until the
  next reset;
* the **alternate screen** (``CSI ?1049h`` ... ``CSI ?1049l``): what is written there is gone when
  the terminal switches back;
* **erase line** (``CSI 2K`` / ``CSI 1K``): the text before it on the line is wiped;
* a **carriage return** in the middle of a line: the text after it is drawn over the text before;
* a run of three or more **backspaces** followed by text, which is drawn over what came before.

``hidden_spans`` returns those spans for one line. It says nothing about intent: a progress bar is
a carriage return, a coloured prompt is SGR. The caller reports a span only when the text in it is
something already treated as risky (see ``invisible_unicode``). CSI may be introduced by ``ESC [``
or by the 8-bit U+009B. With ``spelled=True`` the control characters are also read in their escaped
spelling (``\\u001b``, ``\\x1b``, ``\\033``, ``\\r``, ``\\b``), for a JSON or source string.

DEL (U+007F) is not read as an overwrite: terminals ignore it on output.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class Hidden(NamedTuple):
    start: int  # offsets in the line
    end: int
    how: str
    at: int  # where the control sequence that hides the span starts


def _char(cp: int, spelled: bool, *short: str) -> str:
    """A pattern for one control character: raw, and with ``spelled`` its escapes too."""
    raw = re.escape(chr(cp))
    if not spelled:
        return raw
    forms = [rf"(?i:u00{cp:02x}|x{cp:02x})", *short]
    if cp < 0o100:
        forms.append(rf"0{cp:02o}")
    # An escaped backslash (`\\r`) spells a backslash and a letter, not the control character.
    return rf"(?:{raw}|(?<!\\)\\(?:{'|'.join(forms)}))"


def _token_pattern(spelled: bool) -> re.Pattern[str]:
    esc = _char(0x1B, spelled)
    c1 = {cp: _char(cp, spelled) for cp in (0x90, 0x98, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F)}
    newline = r"(?!\n|\\n)" if spelled else r"(?!\n)"
    return re.compile(
        rf"(?P<st>{_char(0x07, spelled, 'a')}|{esc}\\{{1,2}}|{c1[0x9C]})"
        rf"|(?P<osc>{esc}\]|{c1[0x9D]})"
        rf"|(?P<dcs>{esc}[P_^X]|{c1[0x90]}|{c1[0x98]}|{c1[0x9E]}|{c1[0x9F]})"
        rf"|(?P<csi>(?:{esc}\[|{c1[0x9B]})(?P<params>[0-9;?]{{0,64}})(?P<final>[@-~]))"
        rf"|(?P<cr>{_char(0x0D, spelled, 'r')}){newline}"
        rf"|(?P<bs>(?:{_char(0x08, spelled, 'b')}){{3,}})"
    )


_TOKENS = {False: _token_pattern(False), True: _token_pattern(True)}
_ONE_BACKSPACE = re.compile(_char(0x08, True, "b"))
# A cheap test for "this text may hold one of the sequences above".
TRIGGER = {
    False: re.compile("[\x08\x1b\x90\x98\x9b\x9d\x9e\x9f]|\r(?!\n)"),
    True: re.compile(
        "[\x08\x1b\x90\x98\x9b\x9d\x9e\x9f]|\r(?!\n)"
        r"|(?<!\\)\\(?:(?i:u001b|x1b|u009[bd0]|x9[bd0])|033|r(?!\\n)"
        r"|(?:b|(?i:u0008|x08)|010)\\(?:b|(?i:u0008|x08)|010)\\)"
    ),
}
_ALT_SCREEN = frozenset({"?1049", "?1047", "?47"})
_MAX_TOKENS = 256


def _colour(params: list[str], i: int) -> tuple[tuple[int, ...] | None, int]:
    """The colour an extended SGR colour (``38;5;n`` / ``38;2;r;g;b``) names, and how many
    parameters it took after the 38 / 48."""
    try:
        if params[i + 1] == "5":
            return (int(params[i + 2] or 0),), 2
        if params[i + 1] == "2":
            r, g, b = (int(p or 0) for p in params[i + 2:i + 5])
            return (r, g, b), 4
    except (IndexError, ValueError):
        pass
    return None, 0


class _Sgr:
    """The attributes that decide whether text is drawn: conceal, foreground, background."""

    def __init__(self) -> None:
        self.conceal = False
        self.fg: tuple[int, ...] | None = None
        self.bg: tuple[int, ...] | None = None

    def hides(self) -> bool:
        return self.conceal or (self.fg is not None and self.fg == self.bg)

    def apply(self, raw: str) -> None:
        params = raw.split(";")
        i = 0
        while i < len(params):
            try:
                n = int(params[i] or 0)
            except ValueError:
                return
            if n == 0:
                self.conceal, self.fg, self.bg = False, None, None
            elif n == 8:
                self.conceal = True
            elif n == 28:
                self.conceal = False
            elif 30 <= n <= 37 or 90 <= n <= 97:
                self.fg = (n - 30 if n < 90 else n - 90 + 8,)
            elif 40 <= n <= 47 or 100 <= n <= 107:
                self.bg = (n - 40 if n < 100 else n - 100 + 8,)
            elif n == 39:
                self.fg = None
            elif n == 49:
                self.bg = None
            elif n in (38, 48):
                colour, taken = _colour(params, i)
                if n == 38:
                    self.fg = colour
                else:
                    self.bg = colour
                i += taken
            i += 1


def hidden_spans(line: str, *, spelled: bool = False) -> list[Hidden]:
    """The parts of ``line`` (one line, no newline) a terminal does not draw, in order."""
    found: list[Hidden] = []
    segment = 0  # where the text since the last carriage return starts
    # Each open region: (where its text starts, how it is hidden, where its sequence starts).
    string: tuple[int, str, int] | None = None
    drawn_off: tuple[int, str, int] | None = None
    alternate: tuple[int, str, int] | None = None
    sgr = _Sgr()
    for count, m in enumerate(_TOKENS[spelled].finditer(line)):
        if count >= _MAX_TOKENS:
            break
        kind = m.lastgroup
        at = m.start()
        if string is not None:
            if kind == "st":
                found.append(Hidden(string[0], at, string[1], string[2]))
                string = None
            continue
        if kind == "osc":
            string = (m.end(), "the payload of an OSC sequence (a title or a link address)", at)
        elif kind == "dcs":
            string = (m.end(), "the payload of a terminal string sequence", at)
        elif kind == "csi":
            params, final = m.group("params"), m.group("final")
            if final == "m":
                sgr.apply(params)
                if sgr.hides() and drawn_off is None:
                    drawn_off = (m.end(), "concealed or drawn in its own background colour", at)
                elif drawn_off is not None and not sgr.hides():
                    found.append(Hidden(drawn_off[0], at, drawn_off[1], drawn_off[2]))
                    drawn_off = None
            elif final in "hl" and params in _ALT_SCREEN:
                if final == "h" and alternate is None:
                    alternate = (m.end(), "written to the alternate screen", at)
                elif final == "l" and alternate is not None:
                    found.append(Hidden(alternate[0], at, alternate[1], alternate[2]))
                    alternate = None
            elif final == "K" and params in ("1", "2") and line[segment:at].strip():
                found.append(Hidden(segment, at, "erased by an erase-line sequence", at))
        elif kind == "cr":
            if line[m.end():].strip():
                found.append(Hidden(segment, at, "overwritten after a carriage return", at))
            segment = m.end()
        elif kind == "bs" and line[m.end():].strip():
            steps = len(_ONE_BACKSPACE.findall(m.group()))
            found.append(Hidden(max(segment, at - steps), at, "overwritten after backspaces", at))
    for region in (string, drawn_off, alternate):
        if region is not None:
            found.append(Hidden(region[0], len(line), region[1], region[2]))
    return [h for h in found if h.end > h.start]
